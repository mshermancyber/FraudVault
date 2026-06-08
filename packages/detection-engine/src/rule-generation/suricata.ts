import type { DynamicAnalysisResult, NetworkConnection } from '@scanboy/shared';

/** Generated Suricata rule. */
export interface SuricataRule {
  sid: number;
  action: string;
  protocol: string;
  description: string;
  rule: string;
}

/**
 * Escape content for Suricata rule `content:` keyword.
 * Suricata content uses | for hex and " as delimiters.
 */
function escapeContent(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/;/g, '\\;');
}

/**
 * Generate Suricata rules from observed HTTP activity.
 */
function generateHttpRules(
  connections: NetworkConnection[],
  baseSid: number,
  submissionId: string,
): SuricataRule[] {
  const rules: SuricataRule[] = [];
  let sidOffset = 0;

  // Collect HTTP connections
  const httpConns = connections.filter(
    (c) => c.protocol === 'http' || (c.protocol === 'tcp' && (c.destinationPort === 80 || c.destinationPort === 8080)),
  );

  const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const PORT_RE = /^\d{1,5}$/;

  // Deduplicate by destination
  const seenDest = new Set<string>();
  for (const conn of httpConns) {
    if (!IP_RE.test(conn.destinationAddress) || !PORT_RE.test(String(conn.destinationPort))) continue;
    const key = `${conn.destinationAddress}:${conn.destinationPort}`;
    if (seenDest.has(key)) continue;
    seenDest.add(key);

    const sid = baseSid + sidOffset++;
    const description = `FraudVault: HTTP traffic to ${conn.destinationAddress}:${conn.destinationPort} (submission ${submissionId})`;

    let rule = `alert http $HOME_NET any -> ${conn.destinationAddress} ${conn.destinationPort} (`;
    rule += `msg:"${escapeContent(description)}"; `;

    if (conn.domain) {
      rule += `content:"${escapeContent(conn.domain)}"; http_host; `;
    }

    rule += `flow:established,to_server; `;
    rule += `classtype:trojan-activity; `;
    rule += `sid:${sid}; rev:1; `;
    rule += `metadata:created_by fraudvault, submission ${submissionId};`;
    rule += `)`;

    rules.push({
      sid,
      action: 'alert',
      protocol: 'http',
      description,
      rule,
    });
  }

  return rules;
}

/**
 * Generate Suricata rules from observed DNS activity.
 */
function generateDnsRules(
  connections: NetworkConnection[],
  baseSid: number,
  submissionId: string,
): SuricataRule[] {
  const rules: SuricataRule[] = [];
  let sidOffset = 0;

  // Collect DNS connections with domain names
  const dnsConns = connections.filter((c) => c.protocol === 'dns' && c.domain);
  const seenDomains = new Set<string>();

  for (const conn of dnsConns) {
    if (!conn.domain || seenDomains.has(conn.domain)) continue;
    seenDomains.add(conn.domain);

    const sid = baseSid + sidOffset++;
    const description = `FraudVault: DNS query for ${conn.domain} (submission ${submissionId})`;

    let rule = `alert dns $HOME_NET any -> any any (`;
    rule += `msg:"${escapeContent(description)}"; `;
    rule += `dns.query; content:"${escapeContent(conn.domain)}"; nocase; `;
    rule += `flow:established,to_server; `;
    rule += `classtype:trojan-activity; `;
    rule += `sid:${sid}; rev:1; `;
    rule += `metadata:created_by fraudvault, submission ${submissionId};`;
    rule += `)`;

    rules.push({
      sid,
      action: 'alert',
      protocol: 'dns',
      description,
      rule,
    });
  }

  return rules;
}

/**
 * Generate Suricata rules from observed TLS/HTTPS activity.
 * Detects connections by SNI (Server Name Indication) and destination IP.
 */
function generateTlsRules(
  connections: NetworkConnection[],
  baseSid: number,
  submissionId: string,
): SuricataRule[] {
  const rules: SuricataRule[] = [];
  let sidOffset = 0;

  // Collect TLS connections
  const tlsConns = connections.filter(
    (c) => c.protocol === 'tls' || c.protocol === 'https' || (c.protocol === 'tcp' && c.destinationPort === 443),
  );

  const seenSni = new Set<string>();
  for (const conn of tlsConns) {
    if (conn.domain) {
      if (seenSni.has(conn.domain)) continue;
      seenSni.add(conn.domain);

      const sid = baseSid + sidOffset++;
      const description = `FraudVault: TLS connection to ${conn.domain} (submission ${submissionId})`;

      let rule = `alert tls $HOME_NET any -> any any (`;
      rule += `msg:"${escapeContent(description)}"; `;
      rule += `tls.sni; content:"${escapeContent(conn.domain)}"; nocase; `;
      rule += `flow:established,to_server; `;
      rule += `classtype:trojan-activity; `;
      rule += `sid:${sid}; rev:1; `;
      rule += `metadata:created_by fraudvault, submission ${submissionId};`;
      rule += `)`;

      rules.push({
        sid,
        action: 'alert',
        protocol: 'tls',
        description,
        rule,
      });
    } else if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(conn.destinationAddress) && /^\d{1,5}$/.test(String(conn.destinationPort))) {
      // No SNI -- match by IP
      const ipKey = `${conn.destinationAddress}:${conn.destinationPort}`;
      if (seenSni.has(ipKey)) continue;
      seenSni.add(ipKey);

      const sid = baseSid + sidOffset++;
      const description = `FraudVault: TLS connection to ${conn.destinationAddress}:${conn.destinationPort} (submission ${submissionId})`;

      let rule = `alert tls $HOME_NET any -> ${conn.destinationAddress} ${conn.destinationPort} (`;
      rule += `msg:"${escapeContent(description)}"; `;
      rule += `flow:established,to_server; `;
      rule += `classtype:trojan-activity; `;
      rule += `sid:${sid}; rev:1; `;
      rule += `metadata:created_by fraudvault, submission ${submissionId};`;
      rule += `)`;

      rules.push({
        sid,
        action: 'alert',
        protocol: 'tls',
        description,
        rule,
      });
    }
  }

  return rules;
}

/**
 * Generate Suricata rules for non-standard port activity.
 */
function generateNonStandardPortRules(
  connections: NetworkConnection[],
  baseSid: number,
  submissionId: string,
): SuricataRule[] {
  const rules: SuricataRule[] = [];
  let sidOffset = 0;

  const standardPorts = new Set([80, 443, 53, 25, 587, 993, 995, 110, 143, 21, 22, 23, 3389, 445, 139]);
  const seenPorts = new Set<string>();

  const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const PORT_RE = /^\d{1,5}$/;

  for (const conn of connections) {
    if (standardPorts.has(conn.destinationPort)) continue;
    if (!IP_RE.test(conn.destinationAddress) || !PORT_RE.test(String(conn.destinationPort))) continue;
    const key = `${conn.destinationAddress}:${conn.destinationPort}`;
    if (seenPorts.has(key)) continue;
    seenPorts.add(key);

    const sid = baseSid + sidOffset++;
    const description = `FraudVault: Non-standard port ${conn.destinationPort} to ${conn.destinationAddress} (submission ${submissionId})`;

    let rule = `alert tcp $HOME_NET any -> ${conn.destinationAddress} ${conn.destinationPort} (`;
    rule += `msg:"${escapeContent(description)}"; `;
    rule += `flow:established,to_server; `;
    rule += `classtype:misc-activity; `;
    rule += `sid:${sid}; rev:1; `;
    rule += `metadata:created_by fraudvault, submission ${submissionId};`;
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
 * Generate all Suricata rules from dynamic analysis results.
 *
 * @param baseSid  Starting SID for generated rules (should be unique per submission).
 */
export function generateSuricataRules(
  dynamicAnalysis: DynamicAnalysisResult,
  submissionId: string,
  baseSid: number,
): SuricataRule[] {
  const rules: SuricataRule[] = [];
  const conns = dynamicAnalysis.networkConnections;

  rules.push(...generateHttpRules(conns, baseSid, submissionId));
  rules.push(...generateDnsRules(conns, baseSid + 1000, submissionId));
  rules.push(...generateTlsRules(conns, baseSid + 2000, submissionId));
  rules.push(...generateNonStandardPortRules(conns, baseSid + 3000, submissionId));

  return rules;
}
