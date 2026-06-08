// ── AI Analysis Orchestrator ────────────────────────────────────────────────
// Coordinates AI-assisted analysis of malware artifacts.
// The AI NEVER receives actual malware samples - only sanitized analysis results.

import type { AIProvider, AIOptions } from './provider.js';
import {
  SYSTEM_INSTRUCTIONS,
  BEHAVIOR_SUMMARY_PROMPT,
  EXECUTIVE_SUMMARY_PROMPT,
  TECHNICAL_ANALYSIS_PROMPT,
  THREAT_ASSESSMENT_PROMPT,
  IOC_CONTEXT_PROMPT,
  ATTACK_CHAIN_PROMPT,
} from './prompts.js';
import { sanitizeForAI } from './sanitizer.js';
import { createHash } from 'node:crypto';
import type Redis from 'ioredis';

// ── Types ───────────────────────────────────────────────────────────────────

export interface ThreatAssessmentResult {
  summary: string;
  riskLevel: string;
  recommendations: string[];
}

interface RateLimitState {
  count: number;
  windowStart: number;
}

// ── Constants ───────────────────────────────────────────────────────────────

/** Maximum AI API calls per submission to prevent runaway costs. */
const MAX_CALLS_PER_SUBMISSION = 10;

/** Rate limit window in milliseconds (1 minute). */
const RATE_LIMIT_WINDOW_MS = 60_000;

/** Cache TTL in seconds (1 hour). */
const CACHE_TTL_SECONDS = 3600;

/** Cache key prefix for AI analysis results. */
const CACHE_PREFIX = 'fraudvault:ai:';

// ── AIAnalyzer Class ────────────────────────────────────────────────────────

export class AIAnalyzer {
  private readonly provider: AIProvider;
  private readonly redis: Redis | null;
  private readonly rateLimits: Map<string, RateLimitState> = new Map();

  constructor(provider: AIProvider, redis?: Redis) {
    this.provider = provider;
    this.redis = redis ?? null;
  }

  /**
   * Summarize dynamic analysis behaviors for a SOC analyst.
   * Returns 2-3 paragraphs describing observed malicious behaviors.
   */
  async summarizeBehavior(dynamicResults: object): Promise<string> {
    const sanitized = sanitizeForAI(dynamicResults);
    const submissionId = extractSubmissionId(sanitized);

    const cacheKey = `${CACHE_PREFIX}behavior:${submissionId}`;
    const cached = await this.getCached(cacheKey);
    if (cached) return cached;

    this.checkRateLimit(submissionId);

    const prompt = BEHAVIOR_SUMMARY_PROMPT.replace('{{DATA}}', JSON.stringify(sanitized, null, 2));
    const options: AIOptions = {
      maxTokens: 1500,
      temperature: 0.3,
      systemPrompt: SYSTEM_INSTRUCTIONS,
    };

    const result = await this.callProvider(prompt, options);
    await this.setCached(cacheKey, result);
    return result;
  }

  /**
   * Generate a non-technical executive summary.
   * Returns a single paragraph suitable for executives and non-technical stakeholders.
   */
  async generateExecutiveSummary(fullReport: object): Promise<string> {
    const sanitized = sanitizeForAI(fullReport);
    const submissionId = extractSubmissionId(sanitized);

    const cacheKey = `${CACHE_PREFIX}executive:${submissionId}`;
    const cached = await this.getCached(cacheKey);
    if (cached) return cached;

    this.checkRateLimit(submissionId);

    const prompt = EXECUTIVE_SUMMARY_PROMPT.replace('{{DATA}}', JSON.stringify(sanitized, null, 2));
    const options: AIOptions = {
      maxTokens: 1000,
      temperature: 0.3,
      systemPrompt: SYSTEM_INSTRUCTIONS,
    };

    const result = await this.callProvider(prompt, options);
    await this.setCached(cacheKey, result);
    return result;
  }

  /**
   * Generate a detailed technical analysis for malware researchers.
   * Returns a structured multi-section technical writeup.
   */
  async generateTechnicalAnalysis(fullReport: object): Promise<string> {
    const sanitized = sanitizeForAI(fullReport);
    const submissionId = extractSubmissionId(sanitized);

    const cacheKey = `${CACHE_PREFIX}technical:${submissionId}`;
    const cached = await this.getCached(cacheKey);
    if (cached) return cached;

    this.checkRateLimit(submissionId);

    const prompt = TECHNICAL_ANALYSIS_PROMPT.replace('{{DATA}}', JSON.stringify(sanitized, null, 2));
    const options: AIOptions = {
      maxTokens: 4096,
      temperature: 0.2,
      systemPrompt: SYSTEM_INSTRUCTIONS,
    };

    const result = await this.callProvider(prompt, options);
    await this.setCached(cacheKey, result);
    return result;
  }

  /**
   * Assess threat level with structured recommendations.
   * Returns a parsed threat assessment with summary, risk level, and actionable recommendations.
   */
  async assessThreat(fullReport: object): Promise<ThreatAssessmentResult> {
    const sanitized = sanitizeForAI(fullReport);
    const submissionId = extractSubmissionId(sanitized);

    const cacheKey = `${CACHE_PREFIX}threat:${submissionId}`;
    const cached = await this.getCached(cacheKey);
    if (cached) {
      return JSON.parse(cached) as ThreatAssessmentResult;
    }

    this.checkRateLimit(submissionId);

    const prompt = THREAT_ASSESSMENT_PROMPT.replace('{{DATA}}', JSON.stringify(sanitized, null, 2));
    const options: AIOptions = {
      maxTokens: 1500,
      temperature: 0.2,
      systemPrompt: SYSTEM_INSTRUCTIONS,
    };

    const rawResult = await this.callProvider(prompt, options);
    const parsed = parseThreatAssessment(rawResult);

    await this.setCached(cacheKey, JSON.stringify(parsed));
    return parsed;
  }

  /**
   * Explain the significance of extracted IOCs.
   * Returns contextual analysis of indicators of compromise.
   */
  async explainIOCs(iocs: object[]): Promise<string> {
    const sanitized = sanitizeForAI(iocs);
    const iocHash = simpleHash(JSON.stringify(sanitized));

    const cacheKey = `${CACHE_PREFIX}iocs:${iocHash}`;
    const cached = await this.getCached(cacheKey);
    if (cached) return cached;

    // IOC explanation uses a generic rate limit key since IOCs may span submissions
    this.checkRateLimit(`ioc-${iocHash}`);

    const prompt = IOC_CONTEXT_PROMPT.replace('{{DATA}}', JSON.stringify(sanitized, null, 2));
    const options: AIOptions = {
      maxTokens: 2048,
      temperature: 0.3,
      systemPrompt: SYSTEM_INSTRUCTIONS,
    };

    const result = await this.callProvider(prompt, options);
    await this.setCached(cacheKey, result);
    return result;
  }

  /**
   * Describe the kill chain / attack flow based on ATT&CK technique mappings.
   * Returns a narrative description of the attack chain.
   */
  async describeAttackChain(techniques: object[]): Promise<string> {
    const sanitized = sanitizeForAI(techniques);
    const techHash = simpleHash(JSON.stringify(sanitized));

    const cacheKey = `${CACHE_PREFIX}attackchain:${techHash}`;
    const cached = await this.getCached(cacheKey);
    if (cached) return cached;

    this.checkRateLimit(`attack-${techHash}`);

    const prompt = ATTACK_CHAIN_PROMPT.replace('{{DATA}}', JSON.stringify(sanitized, null, 2));
    const options: AIOptions = {
      maxTokens: 2048,
      temperature: 0.3,
      systemPrompt: SYSTEM_INSTRUCTIONS,
    };

    const result = await this.callProvider(prompt, options);
    await this.setCached(cacheKey, result);
    return result;
  }

  // ── Private Helpers ─────────────────────────────────────────────────────

  private async callProvider(prompt: string, options: AIOptions): Promise<string> {
    try {
      return await this.provider.generateCompletion(prompt, options);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new AIAnalysisError(`AI provider (${this.provider.name}) failed: ${message}`, error);
    }
  }

  /**
   * Enforce per-submission rate limiting.
   * Throws if the submission has exceeded MAX_CALLS_PER_SUBMISSION within the window.
   */
  private checkRateLimit(submissionId: string): void {
    const now = Date.now();
    const state = this.rateLimits.get(submissionId);

    if (!state || now - state.windowStart > RATE_LIMIT_WINDOW_MS) {
      this.rateLimits.set(submissionId, { count: 1, windowStart: now });
      return;
    }

    if (state.count >= MAX_CALLS_PER_SUBMISSION) {
      throw new AIRateLimitError(
        `Rate limit exceeded: ${MAX_CALLS_PER_SUBMISSION} AI calls per submission within ${RATE_LIMIT_WINDOW_MS / 1000}s window`,
      );
    }

    state.count++;
  }

  private async getCached(key: string): Promise<string | null> {
    if (!this.redis) return null;
    try {
      return await this.redis.get(key);
    } catch {
      // Cache miss on error - proceed without cache
      return null;
    }
  }

  private async setCached(key: string, value: string): Promise<void> {
    if (!this.redis) return;
    try {
      await this.redis.set(key, value, 'EX', CACHE_TTL_SECONDS);
    } catch {
      // Silently ignore cache write failures
    }
  }
}

// ── Error Types ─────────────────────────────────────────────────────────────

export class AIAnalysisError extends Error {
  override readonly cause: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'AIAnalysisError';
    this.cause = cause;
  }
}

export class AIRateLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AIRateLimitError';
  }
}

// ── Utility Functions ───────────────────────────────────────────────────────

/**
 * Extract submissionId from a sanitized object, falling back to a hash.
 */
function extractSubmissionId(data: object): string {
  const record = data as Record<string, unknown>;
  if (typeof record['submissionId'] === 'string') return record['submissionId'];
  if (typeof record['id'] === 'string') return record['id'];

  // Check nested submission object
  const submission = record['submission'] as Record<string, unknown> | undefined;
  if (submission && typeof submission['id'] === 'string') return submission['id'];

  // Fallback to a hash of the data
  return simpleHash(JSON.stringify(data));
}

function simpleHash(str: string): string {
  return createHash('sha256').update(str).digest('hex').slice(0, 16);
}

/**
 * Parse the AI's threat assessment JSON response, with fallback handling.
 */
function parseThreatAssessment(raw: string): ThreatAssessmentResult {
  try {
    // Try to extract JSON from the response (the AI might wrap it in markdown)
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return {
        summary: raw.trim(),
        riskLevel: 'medium',
        recommendations: ['Unable to parse structured assessment. Review the raw AI output.'],
      };
    }

    const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;

    const validRiskLevels = new Set(['critical', 'high', 'medium', 'low', 'informational']);
    const riskLevel = typeof parsed['riskLevel'] === 'string' && validRiskLevels.has(parsed['riskLevel'])
      ? parsed['riskLevel']
      : 'medium';

    const recommendations = Array.isArray(parsed['recommendations'])
      ? (parsed['recommendations'] as unknown[]).filter((r): r is string => typeof r === 'string')
      : [];

    return {
      summary: typeof parsed['summary'] === 'string' ? parsed['summary'] : raw.trim(),
      riskLevel,
      recommendations: recommendations.length > 0
        ? recommendations
        : ['Review the full analysis report for detailed findings.'],
    };
  } catch {
    return {
      summary: raw.trim(),
      riskLevel: 'medium',
      recommendations: ['Unable to parse structured assessment. Review the raw AI output.'],
    };
  }
}
