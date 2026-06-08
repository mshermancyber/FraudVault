import type { ThreatIntelResult } from '@scanboy/shared';

/**
 * Abstract base class for threat intelligence providers.
 *
 * Each provider wraps an external API (VirusTotal, MalwareBazaar, OTX, etc.)
 * and normalises the response into FraudVault's ThreatIntelResult shape.
 */
export abstract class BaseThreatIntelProvider {
  /** Human-readable provider name (e.g. "VirusTotal"). */
  abstract readonly name: string;

  /**
   * Returns `true` when the provider has valid configuration (API key present, etc.).
   * Providers that are not configured will be silently skipped during enrichment.
   */
  abstract isConfigured(): boolean;

  /**
   * Look up a file hash (MD5, SHA-1 or SHA-256) against this provider.
   *
   * @param hash   The file hash to query.
   * @param submissionId  The FraudVault submission ID for context.
   * @returns Normalised ThreatIntelResult, or `null` if not found / not supported.
   */
  abstract lookup(hash: string, submissionId: string): Promise<ThreatIntelResult | null>;

  /**
   * Look up a URL against this provider.
   *
   * @param url    The URL to query.
   * @param submissionId  The FraudVault submission ID for context.
   * @returns Normalised ThreatIntelResult, or `null` if not found / not supported.
   */
  abstract lookupUrl(url: string, submissionId: string): Promise<ThreatIntelResult | null>;

  /**
   * Look up an IP address against this provider.
   * Not all providers support IP lookups; default returns null.
   */
  async lookupIp(_ip: string, _submissionId: string): Promise<ThreatIntelResult | null> {
    return null;
  }

  /**
   * Look up a domain against this provider.
   * Not all providers support domain lookups; default returns null.
   */
  async lookupDomain(_domain: string, _submissionId: string): Promise<ThreatIntelResult | null> {
    return null;
  }
}
