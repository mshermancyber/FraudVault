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
 * URLhaus (abuse.ch) provider.
 *
 * Public API -- no API key required.
 * Endpoint: https://urlhaus-api.abuse.ch/v1/
 */
export class URLhausProvider extends BaseThreatIntelProvider {
  readonly name = 'URLhaus';

  private readonly client: AxiosInstance;

  constructor() {
    super();
    this.client = axios.create({
      baseURL: 'https://urlhaus-api.abuse.ch/v1/',
      timeout: config.requestTimeoutMs,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
    });
  }

  isConfigured(): boolean {
    return config.providers.urlhaus.enabled;
  }

  async lookup(hash: string, submissionId: string): Promise<ThreatIntelResult | null> {
    try {
      // URLhaus supports payload lookup by hash
      const hashType = hash.length === 32 ? 'md5_hash' : 'sha256_hash';
      const response = await this.client.post('/payload/', new URLSearchParams({
        [hashType]: hash,
      }));

      const body = response.data as Record<string, unknown>;
      const queryStatus = body['query_status'];
      if (queryStatus === 'no_results' || queryStatus === 'hash_not_found') {
        return null;
      }

      return this.parsePayloadResult(body, submissionId);
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      throw err;
    }
  }

  async lookupUrl(url: string, submissionId: string): Promise<ThreatIntelResult | null> {
    try {
      const response = await this.client.post('/url/', new URLSearchParams({
        url,
      }));

      const body = response.data as Record<string, unknown>;
      if (body['query_status'] === 'no_results') {
        return null;
      }

      return this.parseUrlResult(body, submissionId);
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      throw err;
    }
  }

  override async lookupDomain(domain: string, submissionId: string): Promise<ThreatIntelResult | null> {
    try {
      const response = await this.client.post('/host/', new URLSearchParams({
        host: domain,
      }));

      const body = response.data as Record<string, unknown>;
      if (body['query_status'] === 'no_results') {
        return null;
      }

      return this.parseHostResult(body, submissionId);
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return null;
      }
      throw err;
    }
  }

  override async lookupIp(ip: string, submissionId: string): Promise<ThreatIntelResult | null> {
    // URLhaus host endpoint accepts both domains and IPs
    return this.lookupDomain(ip, submissionId);
  }

  // ── Private helpers ───────────────────────────────────────────────────

  private parsePayloadResult(
    raw: Record<string, unknown>,
    submissionId: string,
  ): ThreatIntelResult {
    const signature = readProp(raw, 'signature');
    const signatureStr = typeof signature === 'string' ? signature : null;
    const urlCount = (readProp(raw, 'url_count') ?? 0) as number;
    const firstSeen = readProp(raw, 'firstseen');
    const firstSeenStr = typeof firstSeen === 'string' ? firstSeen : null;
    const lastSeen = readProp(raw, 'lastseen');
    const lastSeenStr = typeof lastSeen === 'string' ? lastSeen : null;
    const fileType = readProp(raw, 'file_type');
    const fileTypeStr = typeof fileType === 'string' ? fileType : null;

    const tags: string[] = [];
    if (signatureStr) tags.push(signatureStr);
    if (fileTypeStr) tags.push(`filetype:${fileTypeStr}`);
    if (lastSeenStr) tags.push(`last_seen:${lastSeenStr}`);

    // Collect tags from associated URLs
    const urls = readProp(raw, 'urls');
    const urlList = Array.isArray(urls) ? (urls as Array<Record<string, unknown>>) : [];
    for (const urlEntry of urlList) {
      const entryTags = readProp(urlEntry, 'tags');
      if (Array.isArray(entryTags)) {
        tags.push(...(entryTags as string[]));
      }
    }

    return {
      submissionId,
      source: this.name,
      knownMalware: true, // Present in URLhaus means known malicious
      malwareFamily: signatureStr,
      firstSeenAt: firstSeenStr,
      detectionRatio: `${urlCount} URLs`,
      communityScore: null,
      tags: [...new Set(tags)],
      rawResponse: raw,
      queriedAt: new Date().toISOString(),
    };
  }

  private parseUrlResult(
    raw: Record<string, unknown>,
    submissionId: string,
  ): ThreatIntelResult {
    const threat = readProp(raw, 'threat');
    const threatStr = typeof threat === 'string' ? threat : null;
    const urlStatus = readProp(raw, 'url_status');
    const urlStatusStr = typeof urlStatus === 'string' ? urlStatus : null;
    const dateAdded = readProp(raw, 'date_added');
    const dateAddedStr = typeof dateAdded === 'string' ? dateAdded : null;
    const rawTags = readProp(raw, 'tags');
    const tags: string[] = Array.isArray(rawTags) ? (rawTags as string[]) : [];

    const combinedTags = [...tags];
    if (threatStr) combinedTags.push(`threat:${threatStr}`);
    if (urlStatusStr) combinedTags.push(`status:${urlStatusStr}`);

    return {
      submissionId,
      source: this.name,
      knownMalware: urlStatusStr === 'online' || urlStatusStr === 'offline',
      malwareFamily: threatStr,
      firstSeenAt: dateAddedStr,
      detectionRatio: urlStatusStr,
      communityScore: null,
      tags: [...new Set(combinedTags)],
      rawResponse: raw,
      queriedAt: new Date().toISOString(),
    };
  }

  private parseHostResult(
    raw: Record<string, unknown>,
    submissionId: string,
  ): ThreatIntelResult {
    const urlCount = (readProp(raw, 'url_count') ?? 0) as number;
    const urlsOnline = (readProp(raw, 'urls_online') ?? 0) as number;
    const blacklists = readProp(raw, 'blacklists') as Record<string, string> | undefined;

    const tags: string[] = [];
    if (blacklists) {
      for (const [list, status] of Object.entries(blacklists)) {
        if (status === 'listed') tags.push(`blacklisted:${list}`);
      }
    }

    const urls = readProp(raw, 'urls');
    const urlList = Array.isArray(urls) ? (urls as Array<Record<string, unknown>>) : [];
    for (const urlEntry of urlList) {
      const entryTags = readProp(urlEntry, 'tags');
      if (Array.isArray(entryTags)) {
        tags.push(...(entryTags as string[]));
      }
    }

    return {
      submissionId,
      source: this.name,
      knownMalware: urlCount > 0,
      malwareFamily: null,
      firstSeenAt: null,
      detectionRatio: `${urlsOnline}/${urlCount} URLs online`,
      communityScore: null,
      tags: [...new Set(tags)],
      rawResponse: raw,
      queriedAt: new Date().toISOString(),
    };
  }
}
