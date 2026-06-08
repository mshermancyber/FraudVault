import axios, { type AxiosInstance } from 'axios';
import type { ThreatIntelResult } from '@scanboy/shared';
import { BaseThreatIntelProvider } from './base.js';
import { config } from '../config.js';

/** Helper to safely read a nested property from unknown data. */
function readProp(obj: unknown, key: string): unknown {
  if (obj !== null && typeof obj === 'object') {
    return (obj as Record<string, unknown>)[key];
  }
  return undefined;
}

/**
 * AlienVault OTX (Open Threat Exchange) provider.
 *
 * API v1: https://otx.alienvault.com/api/v1/
 * Requires an OTX API key.
 */
export class OTXProvider extends BaseThreatIntelProvider {
  readonly name = 'AlienVault OTX';

  private readonly client: AxiosInstance;

  constructor() {
    super();
    this.client = axios.create({
      baseURL: 'https://otx.alienvault.com/api/v1',
      timeout: config.requestTimeoutMs,
      headers: {
        'X-OTX-API-KEY': config.providers.otx.apiKey,
        Accept: 'application/json',
      },
    });
  }

  isConfigured(): boolean {
    return config.providers.otx.apiKey.length > 0;
  }

  async lookup(hash: string, submissionId: string): Promise<ThreatIntelResult | null> {
    const hashType = this.detectHashType(hash);
    if (!hashType) return null;
    if (!/^[a-fA-F0-9]+$/.test(hash)) return null;

    try {
      const [generalResp, analysisResp] = await Promise.all([
        this.client.get(`/indicators/file/${encodeURIComponent(hash)}/general`),
        this.client.get(`/indicators/file/${encodeURIComponent(hash)}/analysis`).catch(() => null),
      ]);

      return this.parseFileResult(
        generalResp.data as Record<string, unknown>,
        analysisResp ? (analysisResp.data as Record<string, unknown>) : null,
        submissionId,
      );
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      throw err;
    }
  }

  async lookupUrl(url: string, submissionId: string): Promise<ThreatIntelResult | null> {
    try {
      const response = await this.client.get(`/indicators/url/${encodeURIComponent(url)}/general`);
      return this.parseIndicatorResult(response.data as Record<string, unknown>, submissionId);
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      throw err;
    }
  }

  override async lookupIp(ip: string, submissionId: string): Promise<ThreatIntelResult | null> {
    try {
      const response = await this.client.get(`/indicators/IPv4/${encodeURIComponent(ip)}/general`);
      return this.parseIndicatorResult(response.data as Record<string, unknown>, submissionId);
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      throw err;
    }
  }

  override async lookupDomain(domain: string, submissionId: string): Promise<ThreatIntelResult | null> {
    try {
      const response = await this.client.get(`/indicators/domain/${encodeURIComponent(domain)}/general`);
      return this.parseIndicatorResult(response.data as Record<string, unknown>, submissionId);
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      throw err;
    }
  }

  // ── Private helpers ───────────────────────────────────────────────────

  private detectHashType(hash: string): 'MD5' | 'SHA1' | 'SHA256' | null {
    switch (hash.length) {
      case 32:
        return 'MD5';
      case 40:
        return 'SHA1';
      case 64:
        return 'SHA256';
      default:
        return null;
    }
  }

  private parseFileResult(
    general: Record<string, unknown>,
    analysis: Record<string, unknown> | null,
    submissionId: string,
  ): ThreatIntelResult {
    const pulses = readProp(general, 'pulse_info') as Record<string, unknown> | undefined;
    const pulseCount = (typeof readProp(pulses, 'count') === 'number'
      ? readProp(pulses, 'count') : 0) as number;
    const pulseList = Array.isArray(readProp(pulses, 'pulses'))
      ? (readProp(pulses, 'pulses') as Array<Record<string, unknown>>)
      : [];

    const tags: string[] = [];
    for (const pulse of pulseList) {
      const pulseTags = readProp(pulse, 'tags');
      if (Array.isArray(pulseTags)) {
        tags.push(...(pulseTags as string[]));
      }
    }

    // Extract malware family from analysis if available
    let malwareFamily: string | null = null;
    if (analysis) {
      const analysisInfo = readProp(analysis, 'analysis') as Record<string, unknown> | undefined;
      const plugins = analysisInfo ? readProp(analysisInfo, 'plugins') as Record<string, unknown> | undefined : undefined;
      if (plugins) {
        const avast = readProp(plugins, 'avast') as Record<string, unknown> | undefined;
        const detection = avast ? readProp(avast, 'results') : undefined;
        if (typeof detection === 'string') malwareFamily = detection;
      }
    }

    return {
      submissionId,
      source: this.name,
      knownMalware: pulseCount > 0,
      malwareFamily,
      firstSeenAt: null,
      detectionRatio: `${pulseCount} pulses`,
      communityScore: pulseCount,
      tags: [...new Set(tags)],
      rawResponse: { general, analysis } as unknown as Record<string, unknown>,
      queriedAt: new Date().toISOString(),
    };
  }

  private parseIndicatorResult(
    data: Record<string, unknown>,
    submissionId: string,
  ): ThreatIntelResult {
    const pulses = readProp(data, 'pulse_info') as Record<string, unknown> | undefined;
    const pulseCount = (typeof readProp(pulses, 'count') === 'number'
      ? readProp(pulses, 'count') : 0) as number;
    const pulseList = Array.isArray(readProp(pulses, 'pulses'))
      ? (readProp(pulses, 'pulses') as Array<Record<string, unknown>>)
      : [];

    const tags: string[] = [];
    for (const pulse of pulseList) {
      const pulseTags = readProp(pulse, 'tags');
      if (Array.isArray(pulseTags)) {
        tags.push(...(pulseTags as string[]));
      }
    }

    return {
      submissionId,
      source: this.name,
      knownMalware: pulseCount > 0,
      malwareFamily: null,
      firstSeenAt: null,
      detectionRatio: `${pulseCount} pulses`,
      communityScore: pulseCount,
      tags: [...new Set(tags)],
      rawResponse: data,
      queriedAt: new Date().toISOString(),
    };
  }
}
