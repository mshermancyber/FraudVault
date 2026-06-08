// ── EDR Hash Blacklisting ───────────────────────────────────────────────────
//
// Pushes malicious file hashes to EDR platforms for automatic blocking.
// Supported: CrowdStrike, Microsoft Defender, SentinelOne, Custom REST API.

// ── Configuration Types ─────────────────────────────────────────────────────

export interface EdrConfig {
  type: 'crowdstrike' | 'defender' | 'sentinelone' | 'custom';
  endpoint: string;
  apiKey: string;
  /** OAuth2 client ID for CrowdStrike Falcon. */
  clientId?: string;
  /** OAuth2 client secret for CrowdStrike Falcon. */
  clientSecret?: string;
  /** Tenant ID for Microsoft Defender. */
  tenantId?: string;
  /** Site token for SentinelOne. */
  siteToken?: string;
}

// ── EDR-Specific Request Types ──────────────────────────────────────────────

interface CrowdStrikeIndicator {
  type: 'sha256';
  value: string;
  action: 'prevent';
  severity: 'critical' | 'high' | 'medium';
  description: string;
  platforms: string[];
  tags: string[];
  applied_globally: boolean;
}

interface CrowdStrikeIocRequest {
  indicators: CrowdStrikeIndicator[];
}

interface DefenderIndicator {
  indicatorValue: string;
  indicatorType: 'FileSha256';
  action: 'AlertAndBlock' | 'Block' | 'Alert';
  title: string;
  description: string;
  severity: 'High' | 'Medium' | 'Low' | 'Informational';
  recommendedActions: string;
  generateAlert: boolean;
}

interface SentinelOneBlacklistEntry {
  filter: {
    hashType: 'sha256';
    value: string;
  };
  data: {
    osType: 'windows' | 'linux' | 'macos';
    type: 'black_hash';
    description: string;
    source: string;
  };
}

// ── Severity Mapping ────────────────────────────────────────────────────────

function mapCrowdStrikeSeverity(score: number): 'critical' | 'high' | 'medium' {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  return 'medium';
}

function mapDefenderSeverity(score: number): 'High' | 'Medium' | 'Low' {
  if (score >= 90) return 'High';
  if (score >= 70) return 'Medium';
  return 'Low';
}

// ── CrowdStrike OAuth2 Token ────────────────────────────────────────────────

async function getCrowdStrikeToken(config: EdrConfig): Promise<string> {
  const clientId = config.clientId ?? '';
  const clientSecret = config.clientSecret ?? '';

  if (!clientId || !clientSecret) {
    throw new Error('CrowdStrike requires clientId and clientSecret for OAuth2');
  }

  const endpoint = config.endpoint.replace(/\/+$/, '');
  const tokenUrl = `${endpoint}/oauth2/token`;

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
    }),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`CrowdStrike OAuth2 failed (${response.status}): ${body}`);
  }

  const data = await response.json() as { access_token: string };
  return data.access_token;
}

// ── Microsoft Defender OAuth2 Token ─────────────────────────────────────────

async function getDefenderToken(config: EdrConfig): Promise<string> {
  const tenantId = config.tenantId ?? '';
  const clientId = config.clientId ?? '';
  const clientSecret = config.clientSecret ?? config.apiKey;

  if (!tenantId) {
    throw new Error('Microsoft Defender requires tenantId');
  }

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId)) {
    throw new Error('Microsoft Defender tenantId must be a valid GUID');
  }

  const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      scope: 'https://api.securitycenter.microsoft.com/.default',
      grant_type: 'client_credentials',
    }),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Defender OAuth2 failed (${response.status}): ${body}`);
  }

  const data = await response.json() as { access_token: string };
  return data.access_token;
}

// ── Core Push Functions ─────────────────────────────────────────────────────

/**
 * Push a malicious file hash to the configured EDR platform for blocking.
 * This creates an IOC/block rule that prevents execution of files matching the hash.
 */
export async function pushHashToEdr(
  config: EdrConfig,
  hash: string,
  family: string,
  score: number,
): Promise<void> {
  if (!isValidSha256(hash)) {
    throw new Error(`Invalid SHA-256 hash: ${hash.slice(0, 20)}`);
  }
  switch (config.type) {
    case 'crowdstrike':
      await pushToCrowdStrike(config, hash, family, score);
      break;
    case 'defender':
      await pushToDefender(config, hash, family, score);
      break;
    case 'sentinelone':
      await pushToSentinelOne(config, hash, family, score);
      break;
    case 'custom':
      await pushToCustomEdr(config, hash, family, score);
      break;
  }
}

async function pushToCrowdStrike(
  config: EdrConfig,
  hash: string,
  family: string,
  score: number,
): Promise<void> {
  const token = await getCrowdStrikeToken(config);
  const endpoint = config.endpoint.replace(/\/+$/, '');
  const url = `${endpoint}/indicators/entities/iocs/v1`;

  const indicator: CrowdStrikeIndicator = {
    type: 'sha256',
    value: hash,
    action: 'prevent',
    severity: mapCrowdStrikeSeverity(score),
    description: `FraudVault: ${family || 'Malicious file'} (score: ${score}/100)`,
    platforms: ['windows', 'mac', 'linux'],
    tags: ['fraudvault', 'automated'],
    applied_globally: true,
  };

  const body: CrowdStrikeIocRequest = { indicators: [indicator] };

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const respBody = await response.text().catch(() => '');
    throw new Error(`CrowdStrike IOC push failed (${response.status}): ${respBody}`);
  }
}

async function pushToDefender(
  config: EdrConfig,
  hash: string,
  family: string,
  score: number,
): Promise<void> {
  const token = await getDefenderToken(config);
  const url = 'https://api.securitycenter.microsoft.com/api/indicators';

  const indicator: DefenderIndicator = {
    indicatorValue: hash,
    indicatorType: 'FileSha256',
    action: score >= 90 ? 'AlertAndBlock' : 'Block',
    title: `FraudVault: ${family || 'Malicious file'}`,
    description: `Automated block from FraudVault analysis. Threat score: ${score}/100. Family: ${family || 'Unknown'}.`,
    severity: mapDefenderSeverity(score),
    recommendedActions: 'Quarantine the file and investigate the host for additional IOCs.',
    generateAlert: true,
  };

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(indicator),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Defender IOC push failed (${response.status}): ${body}`);
  }
}

async function pushToSentinelOne(
  config: EdrConfig,
  hash: string,
  family: string,
  score: number,
): Promise<void> {
  const endpoint = config.endpoint.replace(/\/+$/, '');
  const url = `${endpoint}/web/api/v2.1/restrictions`;

  const entry: SentinelOneBlacklistEntry = {
    filter: {
      hashType: 'sha256',
      value: hash,
    },
    data: {
      osType: 'windows',
      type: 'black_hash',
      description: `FraudVault: ${family || 'Malicious file'} (score: ${score}/100)`,
      source: 'scanboy-automated',
    },
  };

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `ApiToken ${config.apiKey}`,
    },
    body: JSON.stringify(entry),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`SentinelOne blacklist push failed (${response.status}): ${body}`);
  }
}

async function pushToCustomEdr(
  config: EdrConfig,
  hash: string,
  family: string,
  score: number,
): Promise<void> {
  const endpoint = config.endpoint.replace(/\/+$/, '');

  const body = {
    hash,
    hash_type: 'sha256',
    action: 'block',
    severity: score >= 90 ? 'critical' : score >= 70 ? 'high' : 'medium',
    family: family || null,
    score,
    source: 'fraudvault',
    timestamp: new Date().toISOString(),
  };

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${config.apiKey}`,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const respBody = await response.text().catch(() => '');
    throw new Error(`Custom EDR push failed (${response.status}): ${respBody}`);
  }
}

// ── Validation ──────────────────────────────────────────────────────────────

/**
 * Validate that a hash is a well-formed SHA-256 hex string.
 */
export function isValidSha256(hash: string): boolean {
  return /^[a-fA-F0-9]{64}$/.test(hash);
}

/**
 * Determine if a submission should be pushed to EDR based on score and confidence.
 * Only push hashes for high/critical threats to avoid false-positive blocks.
 */
export function shouldPushToEdr(threatScore: number, vtDetections: number, vtTotal: number): boolean {
  // Require score >= 80 AND at least some VT confirmations to avoid FP blocking
  if (threatScore < 80) return false;
  if (vtTotal > 0 && vtDetections / vtTotal < 0.1) return false;
  return true;
}
