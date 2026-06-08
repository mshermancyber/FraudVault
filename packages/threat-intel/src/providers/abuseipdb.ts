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
 * AbuseIPDB provider.
 *
 * API v2: https://api.abuseipdb.com/api/v2/
 * Requires an API key.
 */
export class AbuseIPDBProvider extends BaseThreatIntelProvider {
  readonly name = 'AbuseIPDB';

  private readonly client: AxiosInstance;

  constructor() {
    super();
    this.client = axios.create({
      baseURL: 'https://api.abuseipdb.com/api/v2',
      timeout: config.requestTimeoutMs,
      headers: {
        Key: config.providers.abuseipdb.apiKey,
        Accept: 'application/json',
      },
    });
  }

  isConfigured(): boolean {
    return config.providers.abuseipdb.apiKey.length > 0;
  }

  async lookup(_hash: string, _submissionId: string): Promise<ThreatIntelResult | null> {
    // AbuseIPDB does not support file hash lookups
    return null;
  }

  async lookupUrl(_url: string, _submissionId: string): Promise<ThreatIntelResult | null> {
    // AbuseIPDB does not support URL lookups directly
    return null;
  }

  override async lookupIp(ip: string, submissionId: string): Promise<ThreatIntelResult | null> {
    try {
      const response = await this.client.get('/check', {
        params: {
          ipAddress: ip,
          maxAgeInDays: 90,
          verbose: true,
        },
      });

      return this.parseCheckResult(response.data as Record<string, unknown>, submissionId);
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      if (axios.isAxiosError(err) && err.response?.status === 422) {
        // Invalid IP address format
        return null;
      }
      throw err;
    }
  }

  // ── Private helpers ───────────────────────────────────────────────────

  private parseCheckResult(
    raw: Record<string, unknown>,
    submissionId: string,
  ): ThreatIntelResult {
    const data = readProp(raw, 'data') as Record<string, unknown> | undefined ?? {};

    const abuseConfidenceScore = (readProp(data, 'abuseConfidenceScore') ?? 0) as number;
    const totalReports = (readProp(data, 'totalReports') ?? 0) as number;
    const isp = readProp(data, 'isp') as string | null ?? null;
    const domain = readProp(data, 'domain') as string | null ?? null;
    const countryCode = readProp(data, 'countryCode') as string | null ?? null;
    const isWhitelisted = readProp(data, 'isWhitelisted') === true;
    const usageType = readProp(data, 'usageType') as string | null ?? null;
    const lastReportedAt = readProp(data, 'lastReportedAt') as string | null ?? null;

    const tags: string[] = [];
    if (isp) tags.push(`isp:${isp}`);
    if (domain) tags.push(`domain:${domain}`);
    if (countryCode) tags.push(`country:${countryCode}`);
    if (usageType) tags.push(`usage:${usageType}`);
    if (isWhitelisted) tags.push('whitelisted');

    // Extract report categories
    const reports = readProp(data, 'reports');
    const reportList = Array.isArray(reports) ? (reports as Array<Record<string, unknown>>) : [];
    const categories = new Set<number>();
    for (const report of reportList) {
      const cats = readProp(report, 'categories');
      if (Array.isArray(cats)) {
        for (const cat of cats as number[]) {
          categories.add(cat);
        }
      }
    }

    return {
      submissionId,
      source: this.name,
      knownMalware: abuseConfidenceScore >= 50,
      malwareFamily: null,
      firstSeenAt: null,
      detectionRatio: `${abuseConfidenceScore}% confidence, ${totalReports} reports`,
      communityScore: abuseConfidenceScore,
      tags,
      rawResponse: raw,
      queriedAt: lastReportedAt ?? new Date().toISOString(),
    };
  }
}
