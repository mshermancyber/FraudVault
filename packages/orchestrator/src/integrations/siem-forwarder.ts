// ── SIEM Forwarding / Webhook Alerts ────────────────────────────────────────
//
// Forwards high-severity scan results to SIEM platforms and generic webhooks.
// Supported targets: Splunk HEC, Azure Sentinel, Elasticsearch, QRadar, Webhooks (Slack, generic).

// ── Configuration Types ─────────────────────────────────────────────────────

export interface SiemConfig {
  type: 'splunk' | 'sentinel' | 'qradar' | 'elasticsearch' | 'webhook';
  endpoint: string;
  apiKey?: string;
  index?: string;
  /** Workspace ID for Azure Sentinel Log Analytics. */
  workspaceId?: string;
  /** Shared key for Azure Sentinel Log Analytics. */
  sharedKey?: string;
  /** Custom log type name for Azure Sentinel. */
  logType?: string;
}

export interface AlertPayload {
  submissionId: string;
  filename: string;
  threatScore: number;
  threatLevel: string;
  malwareFamily: string | null;
  iocs: Array<{ type: string; value: string }>;
  attackTechniques: string[];
  vtDetections: number;
  vtTotal: number;
  timestamp: string;
  detailUrl: string;
}

// ── Formatters ──────────────────────────────────────────────────────────────

interface SplunkHecEvent {
  event: Record<string, unknown>;
  index: string;
  sourcetype: string;
  time: number;
}

function formatForSplunk(payload: AlertPayload, index: string): SplunkHecEvent {
  return {
    event: {
      submission_id: payload.submissionId,
      filename: payload.filename,
      threat_score: payload.threatScore,
      threat_level: payload.threatLevel,
      malware_family: payload.malwareFamily,
      iocs: payload.iocs,
      attack_techniques: payload.attackTechniques,
      vt_detections: payload.vtDetections,
      vt_total: payload.vtTotal,
      detail_url: payload.detailUrl,
    },
    index,
    sourcetype: 'scanboy:alert',
    time: Math.floor(new Date(payload.timestamp).getTime() / 1000),
  };
}

interface SentinelLogEntry {
  TimeGenerated: string;
  SubmissionId: string;
  Filename: string;
  ThreatScore: number;
  ThreatLevel: string;
  MalwareFamily: string;
  IOCs: string;
  AttackTechniques: string;
  VTDetections: number;
  VTTotal: number;
  DetailUrl: string;
}

function formatForSentinel(payload: AlertPayload): SentinelLogEntry {
  return {
    TimeGenerated: payload.timestamp,
    SubmissionId: payload.submissionId,
    Filename: payload.filename,
    ThreatScore: payload.threatScore,
    ThreatLevel: payload.threatLevel,
    MalwareFamily: payload.malwareFamily ?? 'Unknown',
    IOCs: JSON.stringify(payload.iocs),
    AttackTechniques: JSON.stringify(payload.attackTechniques),
    VTDetections: payload.vtDetections,
    VTTotal: payload.vtTotal,
    DetailUrl: payload.detailUrl,
  };
}

interface SlackBlock {
  type: string;
  text?: { type: string; text: string };
  fields?: Array<{ type: string; text: string }>;
}

interface SlackMessage {
  blocks: SlackBlock[];
}

function formatForSlack(payload: AlertPayload): SlackMessage {
  const severityEmoji =
    payload.threatLevel === 'critical' ? ':rotating_light:'
    : payload.threatLevel === 'high' ? ':warning:'
    : ':information_source:';

  const iocSummary = payload.iocs.length > 0
    ? payload.iocs.slice(0, 5).map(i => `\`${i.type}\`: ${i.value}`).join('\n')
    : 'None extracted';

  const techniqueSummary = payload.attackTechniques.length > 0
    ? payload.attackTechniques.slice(0, 5).join(', ')
    : 'None mapped';

  const blocks: SlackBlock[] = [
    {
      type: 'header',
      text: {
        type: 'plain_text',
        text: `${severityEmoji} FraudVault Alert: ${payload.threatLevel.toUpperCase()} threat detected`,
      },
    },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*File:*\n${payload.filename}` },
        { type: 'mrkdwn', text: `*Threat Score:*\n${payload.threatScore}/100` },
        { type: 'mrkdwn', text: `*Threat Level:*\n${payload.threatLevel}` },
        { type: 'mrkdwn', text: `*Malware Family:*\n${payload.malwareFamily ?? 'Unknown'}` },
        { type: 'mrkdwn', text: `*VT Detections:*\n${payload.vtDetections}/${payload.vtTotal}` },
        { type: 'mrkdwn', text: `*Submission ID:*\n${payload.submissionId}` },
      ],
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*IOCs:*\n${iocSummary}`,
      },
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*ATT&CK Techniques:*\n${techniqueSummary}`,
      },
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `<${payload.detailUrl}|View Full Report>`,
      },
    },
  ];

  return { blocks };
}

// ── HMAC-SHA256 for Azure Sentinel ──────────────────────────────────────────

async function buildSentinelAuthHeader(
  workspaceId: string,
  sharedKey: string,
  contentLength: number,
  rfc1123Date: string,
): Promise<string> {
  const stringToSign = `POST\n${contentLength}\napplication/json\nx-ms-date:${rfc1123Date}\n/api/logs`;
  const encoder = new TextEncoder();
  const keyBytes = Uint8Array.from(atob(sharedKey), c => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signatureBytes = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(stringToSign));
  const signature = btoa(String.fromCharCode(...new Uint8Array(signatureBytes)));
  return `SharedKey ${workspaceId}:${signature}`;
}

// ── Core Forwarding Functions ───────────────────────────────────────────────

/**
 * Forward an alert payload to the configured SIEM target.
 * Throws on network/HTTP errors so the caller can log failures.
 */
export async function forwardToSiem(config: SiemConfig, payload: AlertPayload): Promise<void> {
  switch (config.type) {
    case 'splunk':
      await forwardToSplunk(config, payload);
      break;
    case 'sentinel':
      await forwardToSentinel(config, payload);
      break;
    case 'elasticsearch':
      await forwardToElasticsearch(config, payload);
      break;
    case 'qradar':
      await forwardToQRadar(config, payload);
      break;
    case 'webhook':
      await sendWebhookAlert(config.endpoint, payload);
      break;
  }
}

async function forwardToSplunk(config: SiemConfig, payload: AlertPayload): Promise<void> {
  const index = config.index ?? 'fraudvault';
  const event = formatForSplunk(payload, index);
  const endpoint = config.endpoint.replace(/\/+$/, '');
  const url = `${endpoint}/services/collector`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Splunk ${config.apiKey ?? ''}`,
    },
    body: JSON.stringify(event),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Splunk HEC returned ${response.status}: ${body}`);
  }
}

async function forwardToSentinel(config: SiemConfig, payload: AlertPayload): Promise<void> {
  const workspaceId = config.workspaceId ?? '';
  const sharedKey = config.sharedKey ?? config.apiKey ?? '';
  const logType = config.logType ?? 'FraudVaultAlert';

  if (!workspaceId || !sharedKey) {
    throw new Error('Azure Sentinel requires workspaceId and sharedKey');
  }

  const logEntry = formatForSentinel(payload);
  const body = JSON.stringify([logEntry]);
  const rfc1123Date = new Date().toUTCString();

  const authorization = await buildSentinelAuthHeader(
    workspaceId,
    sharedKey,
    body.length,
    rfc1123Date,
  );

  const url = `https://${workspaceId}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': authorization,
      'Log-Type': logType,
      'x-ms-date': rfc1123Date,
      'time-generated-field': 'TimeGenerated',
    },
    body,
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const respBody = await response.text().catch(() => '');
    throw new Error(`Azure Sentinel returned ${response.status}: ${respBody}`);
  }
}

async function forwardToElasticsearch(config: SiemConfig, payload: AlertPayload): Promise<void> {
  const index = config.index ?? 'scanboy-alerts';
  const endpoint = config.endpoint.replace(/\/+$/, '');
  const url = `${endpoint}/${index}/_doc`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (config.apiKey) {
    headers['Authorization'] = `ApiKey ${config.apiKey}`;
  }

  const doc = {
    '@timestamp': payload.timestamp,
    submission_id: payload.submissionId,
    filename: payload.filename,
    threat_score: payload.threatScore,
    threat_level: payload.threatLevel,
    malware_family: payload.malwareFamily,
    iocs: payload.iocs,
    attack_techniques: payload.attackTechniques,
    vt_detections: payload.vtDetections,
    vt_total: payload.vtTotal,
    detail_url: payload.detailUrl,
  };

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(doc),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Elasticsearch returned ${response.status}: ${body}`);
  }
}

async function forwardToQRadar(config: SiemConfig, payload: AlertPayload): Promise<void> {
  const endpoint = config.endpoint.replace(/\/+$/, '');
  const url = `${endpoint}/api/siem/offenses`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };
  if (config.apiKey) {
    headers['SEC'] = config.apiKey;
  }

  const qradarEvent = {
    description: `FraudVault Alert: ${payload.threatLevel} threat - ${payload.filename}`,
    severity: payload.threatLevel === 'critical' ? 10 : payload.threatLevel === 'high' ? 7 : 5,
    credibility: Math.min(10, Math.round(payload.threatScore / 10)),
    relevance: payload.vtDetections > 0 ? 10 : 5,
    source: 'fraudvault',
    payload: {
      submission_id: payload.submissionId,
      filename: payload.filename,
      threat_score: payload.threatScore,
      malware_family: payload.malwareFamily,
      iocs: payload.iocs,
      attack_techniques: payload.attackTechniques,
      vt_detections: payload.vtDetections,
      vt_total: payload.vtTotal,
      detail_url: payload.detailUrl,
    },
  };

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(qradarEvent),
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`QRadar returned ${response.status}: ${body}`);
  }
}

/**
 * Send a formatted alert to a generic webhook endpoint.
 * Auto-detects Slack webhook URLs and formats accordingly.
 */
export async function sendWebhookAlert(webhookUrl: string, payload: AlertPayload): Promise<void> {
  const isSlack = webhookUrl.includes('hooks.slack.com');
  const body = isSlack
    ? JSON.stringify(formatForSlack(payload))
    : JSON.stringify({
        source: 'fraudvault',
        event_type: 'malware_alert',
        ...payload,
      });

  const response = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const respBody = await response.text().catch(() => '');
    throw new Error(`Webhook returned ${response.status}: ${respBody}`);
  }
}

// ── Alert Threshold Check ───────────────────────────────────────────────────

/** Minimum threat score to trigger SIEM/webhook alerts. */
const ALERT_THRESHOLD_SCORE = 70;

/**
 * Determine if a submission should trigger SIEM forwarding.
 * Returns true if the threat score meets the alert threshold.
 */
export function shouldAlert(threatScore: number): boolean {
  return threatScore >= ALERT_THRESHOLD_SCORE;
}

/**
 * Build an AlertPayload from orchestrator finalization data.
 */
export function buildAlertPayload(opts: {
  submissionId: string;
  filename: string;
  threatScore: number;
  threatLevel: string;
  malwareFamily: string | null;
  iocs: Array<{ type: string; value: string }>;
  attackTechniques: string[];
  vtDetections: number;
  vtTotal: number;
  baseUrl: string;
}): AlertPayload {
  return {
    submissionId: opts.submissionId,
    filename: opts.filename,
    threatScore: opts.threatScore,
    threatLevel: opts.threatLevel,
    malwareFamily: opts.malwareFamily,
    iocs: opts.iocs,
    attackTechniques: opts.attackTechniques,
    vtDetections: opts.vtDetections,
    vtTotal: opts.vtTotal,
    timestamp: new Date().toISOString(),
    detailUrl: `${opts.baseUrl}/submissions/${opts.submissionId}`,
  };
}
