import type { DynamicAnalysisResult, NetworkConnection } from '@scanboy/shared';

/** Generated Snort rule. */
export interface SnortRule {
  sid: number;
  action: string;
  protocol: string;
  description: string;
  rule: string;
}

/**
 * Escape content for Snort rule `content:` keyword.
 */
function escapeContent(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/;/g, '\\;');
}

/**
 * Generate Snort rules from observed HTTP activity.
 */
function generateHttpRules(
  connections: NetworkConnection[],
  baseSid: number,
  submissionId: string,
): SnortRule[] {
  const rules: SnortRule[] = [];
  let sidOffset = 0;

  const httpConns = connections.filter(
    (c) => c.protocol === 'http' || (c.protocol === 'tcp' && (c.destinationPort === 80 || c.destinationPort === 8080)),
  );

  const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const PORT_RE = /^\d{1,5}$/;

  const seenDest = new Set<string>();
  for (const conn of httpConns) {
    if (!IP_RE.test(conn.destinationAddress) || !PORT_RE.test(String(conn.destinationPort))) continue;
    const key = `${conn.destinationAddress}:${conn.destinationPort}`;
    if (seenDest.has(key)) continue;
    seenDest.add(key);

    const sid = baseSid + sidOffset++;
    const description = `FraudVault: HTTP traffic to ${conn.destinationAddress}:${conn.destinationPort} [${submissionId}]`;

    let rule = `alert tcp $HOME_NET any -> ${conn.destinationAddress} ${conn.destinationPort} (`;
    rule += `msg:"${escapeContent(description)}"; `;

    if (conn.domain) {
      rule += `content:"${escapeContent(conn.domain)}"; http_header; nocase; `;
    }

    rule += `flow:established,to_server; `;
    rule += `classtype:trojan-activity; `;
    rule += `sid:${sid}; rev:1; `;
    rule += `reference:url,fraudvault.internal/submissions/${submissionId};`;
    rule += `)`;

    rules.push({
      sid,
      action: 'alert',
      protocol: 'tcp',
      description,
      rule,
    });
  }

  return rules;
}

/**
 * Generate Snort rules from observed DNS activity.
 */
function generateDnsRules(
  connections: NetworkConnection[],
  baseSid: number,
  submissionId: string,
): SnortRule[] {
  const rules: SnortRule[] = [];
  let sidOffset = 0;

  const dnsConns = connections.filter((c) => c.protocol === 'dns' && c.domain);
  const seenDomains = new Set<string>();

  for (const conn of dnsConns) {
    if (!conn.domain || seenDomains.has(conn.domain)) continue;
    seenDomains.add(conn.domain);

    const sid = baseSid + sidOffset++;
    const description = `FraudVault: DNS query for ${conn.domain} [${submissionId}]`;

    let rule = `alert udp $HOME_NET any -> any 53 (`;
    rule += `msg:"${escapeContent(description)}"; `;
    rule += `content:"${escapeContent(conn.domain)}"; nocase; `;
    rule += `flow:to_server; `;
    rule += `classtype:trojan-activity; `;
    rule += `sid:${sid}; rev:1; `;
    rule += `reference:url,fraudvault.internal/submissions/${submissionId};`;
    rule += `)`;

    rules.push({
      sid,
      action: 'alert',
      protocol: 'udp',
      description,
      rule,
    });
  }

  return rules;
}

/**
 * Generate Snort rules from observed TLS/HTTPS activity.
 */
function generateTlsRules(
  connections: NetworkConnection[],
  baseSid: number,
  submissionId: string,
): SnortRule[] {
  const rules: SnortRule[] = [];
  let sidOffset = 0;

  const tlsConns = connections.filter(
    (c) => c.protocol === 'tls' || c.protocol === 'https' || (c.protocol === 'tcp' && c.destinationPort === 443),
  );

  const seen = new Set<string>();
  for (const conn of tlsConns) {
    const key = conn.domain ?? `${conn.destinationAddress}:${conn.destinationPort}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const sid = baseSid + sidOffset++;
    const targetLabel = conn.domain ?? `${conn.destinationAddress}:${conn.destinationPort}`;
    const description = `FraudVault: TLS connection to ${targetLabel} [${submissionId}]`;

    // Snort 3 can detect TLS SNI; Snort 2 uses content matching on the ClientHello
    let rule: string;
    if (conn.domain) {
      rule = `alert tcp $HOME_NET any -> any 443 (`;
      rule += `msg:"${escapeContent(description)}"; `;
      rule += `content:"${escapeContent(conn.domain)}"; `;
      rule += `flow:established,to_server; `;
      rule += `classtype:trojan-activity; `;
      rule += `sid:${sid}; rev:1; `;
      rule += `reference:url,fraudvault.internal/submissions/${submissionId};`;
      rule += `)`;
    } else if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(conn.destinationAddress) && /^\d{1,5}$/.test(String(conn.destinationPort))) {
      rule = `alert tcp $HOME_NET any -> ${conn.destinationAddress} ${conn.destinationPort} (`;
      rule += `msg:"${escapeContent(description)}"; `;
      rule += `flow:established,to_server; `;
      rule += `classtype:trojan-activity; `;
      rule += `sid:${sid}; rev:1; `;
      rule += `reference:url,fraudvault.internal/submissions/${submissionId};`;
      rule += `)`;
    } else {
      continue;
    }

    rules.push({
      sid,
      action: 'alert',
      protocol: 'tcp',
      description,
      rule,
    });
  }

  return rules;
}

/**
 * Generate Snort rules for non-standard port connections.
 */
function generateNonStandardPortRules(
  connections: NetworkConnection[],
  baseSid: number,
  submissionId: string,
): SnortRule[] {
  const rules: SnortRule[] = [];
  let sidOffset = 0;

  const standardPorts = new Set([80, 443, 53, 25, 587, 993, 995, 110, 143, 21, 22, 23, 3389, 445, 139]);
  const seen = new Set<string>();

  const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const PORT_RE = /^\d{1,5}$/;

  for (const conn of connections) {
    if (standardPorts.has(conn.destinationPort)) continue;
    if (!IP_RE.test(conn.destinationAddress) || !PORT_RE.test(String(conn.destinationPort))) continue;
    const key = `${conn.destinationAddress}:${conn.destinationPort}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const sid = baseSid + sidOffset++;
    const description = `FraudVault: Non-standard port ${conn.destinationPort} to ${conn.destinationAddress} [${submissionId}]`;

    let rule = `alert tcp $HOME_NET any -> ${conn.destinationAddress} ${conn.destinationPort} (`;
    rule += `msg:"${escapeContent(description)}"; `;
    rule += `flow:established,to_server; `;
    rule += `classtype:misc-activity; `;
    rule += `sid:${sid}; rev:1; `;
    rule += `reference:url,fraudvault.internal/submissions/${submissionId};`;
    rule += `)`;

    rules.push({
      sid,
      action: 'alert',
      protocol: 'tcp',
      description,
      rule,
    });
  }

  return rules;
}

/**
 * Generate all Snort rules from dynamic analysis results.
 *
 * @param baseSid  Starting SID for generated rules.
 */
export function generateSnortRules(
  dynamicAnalysis: DynamicAnalysisResult,
  submissionId: string,
  baseSid: number,
): SnortRule[] {
  const rules: SnortRule[] = [];
  const conns = dynamicAnalysis.networkConnections;

  rules.push(...generateHttpRules(conns, baseSid, submissionId));
  rules.push(...generateDnsRules(conns, baseSid + 1000, submissionId));
  rules.push(...generateTlsRules(conns, baseSid + 2000, submissionId));
  rules.push(...generateNonStandardPortRules(conns, baseSid + 3000, submissionId));

  return rules;
}
