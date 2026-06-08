import axios, { type AxiosInstance } from 'axios';
import type { ThreatIntelResult } from '@scanboy/shared';
import { BaseThreatIntelProvider } from './base.js';
import { config } from '../config.js';

/**
 * Simple sliding-window rate limiter.
 * Ensures we do not exceed `maxRequests` within a rolling `windowMs` window.
 */
class RateLimiter {
  private timestamps: number[] = [];
  private readonly maxRequests: number;
  private readonly windowMs: number;

  constructor(maxRequests: number, windowMs: number) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  async acquire(): Promise<void> {
    const now = Date.now();
    this.timestamps = this.timestamps.filter((t) => now - t < this.windowMs);

    if (this.timestamps.length >= this.maxRequests) {
      const oldest = this.timestamps[0]!;
      const delay = this.windowMs - (now - oldest) + 50;
      await new Promise((resolve) => setTimeout(resolve, delay));
      return this.acquire();
    }

    this.timestamps.push(Date.now());
  }
}

/** Helper to safely read a nested property from unknown data. */
function readProp(obj: unknown, key: string): unknown {
  if (obj !== null && typeof obj === 'object') {
    return (obj as Record<string, unknown>)[key];
  }
  return undefined;
}

/**
 * VirusTotal API v3 provider.
 *
 * Free-tier rate limit: 4 requests/minute (configurable).
 */
export class VirusTotalProvider extends BaseThreatIntelProvider {
  readonly name = 'VirusTotal';

  private readonly client: AxiosInstance;
  private readonly rateLimiter: RateLimiter;

  constructor() {
    super();

    this.client = axios.create({
      baseURL: 'https://www.virustotal.com/api/v3',
      timeout: config.requestTimeoutMs,
      headers: {
        'x-apikey': config.providers.virustotal.apiKey,
        Accept: 'application/json',
      },
    });

    this.rateLimiter = new RateLimiter(
      config.providers.virustotal.rateLimit,
      60_000,
    );
  }

  isConfigured(): boolean {
    return config.providers.virustotal.apiKey.length > 0;
  }

  async lookup(hash: string, submissionId: string): Promise<ThreatIntelResult | null> {
    await this.rateLimiter.acquire();

    try {
      const response = await this.client.get(`/files/${encodeURIComponent(hash)}`);
      return this.parseFileReport(response.data as Record<string, unknown>, submissionId);
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      throw err;
    }
  }

  async lookupUrl(url: string, submissionId: string): Promise<ThreatIntelResult | null> {
    await this.rateLimiter.acquire();

    // VirusTotal v3 URL ID is base64url of the URL
    const urlId = Buffer.from(url).toString('base64url');

    try {
      const response = await this.client.get(`/urls/${encodeURIComponent(urlId)}`);
      return this.parseUrlReport(response.data as Record<string, unknown>, submissionId);
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      throw err;
    }
  }

  override async lookupIp(ip: string, submissionId: string): Promise<ThreatIntelResult | null> {
    await this.rateLimiter.acquire();

    try {
      const response = await this.client.get(`/ip_addresses/${encodeURIComponent(ip)}`);
      const rawData = response.data as Record<string, unknown>;
      const dataObj = readProp(rawData, 'data');
      const attrs = readProp(dataObj, 'attributes');
      if (!attrs) return null;

      const stats = readProp(attrs, 'last_analysis_stats') as Record<string, number> | undefined ?? {};
      const malicious = (stats['malicious'] ?? 0);
      const total = Object.values(stats).reduce(
        (sum: number, v) => sum + (typeof v === 'number' ? v : 0),
        0,
      );

      const reputation = readProp(attrs, 'reputation');
      const rawTags = readProp(attrs, 'tags');

      return {
        submissionId,
        source: this.name,
        knownMalware: malicious > 0,
        malwareFamily: null,
        firstSeenAt: null,
        detectionRatio: total > 0 ? `${malicious}/${total}` : null,
        communityScore: typeof reputation === 'number' ? reputation : null,
        tags: Array.isArray(rawTags) ? (rawTags as string[]) : [],
        rawResponse: rawData,
        queriedAt: new Date().toISOString(),
      };
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      throw err;
    }
  }

  override async lookupDomain(domain: string, submissionId: string): Promise<ThreatIntelResult | null> {
    await this.rateLimiter.acquire();

    try {
      const response = await this.client.get(`/domains/${encodeURIComponent(domain)}`);
      const rawData = response.data as Record<string, unknown>;
      const dataObj = readProp(rawData, 'data');
      const attrs = readProp(dataObj, 'attributes');
      if (!attrs) return null;

      const stats = readProp(attrs, 'last_analysis_stats') as Record<string, number> | undefined ?? {};
      const malicious = (stats['malicious'] ?? 0);
      const total = Object.values(stats).reduce(
        (sum: number, v) => sum + (typeof v === 'number' ? v : 0),
        0,
      );

      const reputation = readProp(attrs, 'reputation');
      const rawTags = readProp(attrs, 'tags');

      return {
        submissionId,
        source: this.name,
        knownMalware: malicious > 0,
        malwareFamily: null,
        firstSeenAt: null,
        detectionRatio: total > 0 ? `${malicious}/${total}` : null,
        communityScore: typeof reputation === 'number' ? reputation : null,
        tags: Array.isArray(rawTags) ? (rawTags as string[]) : [],
        rawResponse: rawData,
        queriedAt: new Date().toISOString(),
      };
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      throw err;
    }
  }

  // ── Private helpers ───────────────────────────────────────────────────

  private parseFileReport(raw: Record<string, unknown>, submissionId: string): ThreatIntelResult {
    const dataObj = readProp(raw, 'data');
    const attrs = readProp(dataObj, 'attributes') as Record<string, unknown> | undefined ?? {};
    const stats = readProp(attrs, 'last_analysis_stats') as Record<string, number> | undefined ?? {};

    const malicious = stats['malicious'] ?? 0;
    const suspicious = stats['suspicious'] ?? 0;
    const undetected = stats['undetected'] ?? 0;
    const harmless = stats['harmless'] ?? 0;
    const total = malicious + suspicious + undetected + harmless;

    // Try to extract malware family from popular_threat_classification
    const classification = readProp(attrs, 'popular_threat_classification') as Record<string, unknown> | undefined;
    const suggestedLabel = classification ? readProp(classification, 'suggested_threat_label') : undefined;
    const suggestedFamily = typeof suggestedLabel === 'string' ? suggestedLabel : null;

    const rawFirstSub = readProp(attrs, 'first_submission_date');
    const firstSubmission = typeof rawFirstSub === 'number'
      ? new Date(rawFirstSub * 1000).toISOString()
      : null;

    const tags: string[] = [];
    const rawTags = readProp(attrs, 'tags');
    if (Array.isArray(rawTags)) {
      tags.push(...(rawTags as string[]));
    }
    if (classification) {
      const popularNames = readProp(classification, 'popular_threat_name');
      if (Array.isArray(popularNames)) {
        for (const entry of popularNames as Array<Record<string, unknown>>) {
          const val = entry['value'];
          if (typeof val === 'string') tags.push(val);
        }
      }
    }

    const reputation = readProp(attrs, 'reputation');

    return {
      submissionId,
      source: this.name,
      knownMalware: malicious > 0 || suspicious > 0,
      malwareFamily: suggestedFamily,
      firstSeenAt: firstSubmission,
      detectionRatio: total > 0 ? `${malicious}/${total}` : null,
      communityScore: typeof reputation === 'number' ? reputation : null,
      tags,
      rawResponse: raw,
      queriedAt: new Date().toISOString(),
    };
  }

  private parseUrlReport(raw: Record<string, unknown>, submissionId: string): ThreatIntelResult {
    const dataObj = readProp(raw, 'data');
    const attrs = readProp(dataObj, 'attributes') as Record<string, unknown> | undefined ?? {};
    const stats = readProp(attrs, 'last_analysis_stats') as Record<string, number> | undefined ?? {};

    const malicious = stats['malicious'] ?? 0;
    const suspicious = stats['suspicious'] ?? 0;
    const undetected = stats['undetected'] ?? 0;
    const harmless = stats['harmless'] ?? 0;
    const total = malicious + suspicious + undetected + harmless;

    const reputation = readProp(attrs, 'reputation');
    const rawTags = readProp(attrs, 'tags');

    return {
      submissionId,
      source: this.name,
      knownMalware: malicious > 0 || suspicious > 0,
      malwareFamily: null,
      firstSeenAt: null,
      detectionRatio: total > 0 ? `${malicious}/${total}` : null,
      communityScore: typeof reputation === 'number' ? reputation : null,
      tags: Array.isArray(rawTags) ? (rawTags as string[]) : [],
      rawResponse: raw,
      queriedAt: new Date().toISOString(),
    };
  }
}
