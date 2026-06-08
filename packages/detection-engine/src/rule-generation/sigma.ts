import type {
  DynamicAnalysisResult,
  ProcessInfo,
  RegistryModification,
  NetworkConnection,
} from '@scanboy/shared';

/** Generated Sigma rule. */
export interface SigmaRule {
  title: string;
  id: string;
  status: string;
  level: string;
  description: string;
  logsource: {
    category: string;
    product: string;
  };
  yaml: string;
}

/**
 * Escape a string for use inside a Sigma YAML value.
 */
function escapeYaml(value: string): string {
  if (/[:#\[\]{}|>!&*'"%@`]/.test(value) || value.includes('\n')) {
    return `'${value.replace(/'/g, "''")}'`;
  }
  return value;
}

/**
 * Generate a deterministic ID for a Sigma rule.
 */
function generateRuleId(prefix: string, value: string): string {
  let hash = 0;
  const str = `${prefix}:${value}`;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `${hex.slice(0, 8)}-${hex.slice(0, 4)}-${hex.slice(0, 4)}-${hex.slice(0, 4)}-${hex.padEnd(12, '0').slice(0, 12)}`;
}

/**
 * Generate Sigma rules from process creation events.
 */
function generateProcessCreationRules(processes: ProcessInfo[], submissionId: string): SigmaRule[] {
  const rules: SigmaRule[] = [];

  for (const proc of processes) {
    const cmdLine = proc.commandLine;
    if (!cmdLine || cmdLine.trim().length === 0) continue;

    // Skip sandbox infrastructure and common noise processes
    const name = proc.name.toLowerCase();
    const SKIP_PROCESSES = [
      'conhost.exe', 'sleep', 'sh', 'bash', 'strace', 'inotifywait',
      'tcpdump', 'timeout', 'cat', 'grep', 'ps', 'find', 'stat',
      'sha256sum', 'file', 'strings', 'head', 'tail', 'wc',
      'unzip', '7z', 'tar', 'gzip', 'gunzip', 'mkdir', 'chmod',
      'dpkg', 'sort', 'awk', 'sed', 'cut', 'ls', 'rm', 'cp', 'mv',
      'runc', 'runc:[2:INIT]',
    ];
    if (SKIP_PROCESSES.includes(name)) continue;
    if (proc.commandLine.includes('scanboy-logs') || proc.commandLine.includes('scanboy-exec')) continue;

    const ruleId = generateRuleId('sigma-proc', `${submissionId}-${proc.pid}`);
    const title = `FraudVault - Suspicious Process: ${proc.name}`;
    let level = 'medium';

    // Determine severity based on process characteristics
    if (['powershell.exe', 'pwsh.exe', 'cmd.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe'].includes(name)) {
      level = 'high';
    }
    if (['mimikatz.exe', 'procdump.exe'].includes(name)) {
      level = 'critical';
    }

    const yaml = [
      `title: ${escapeYaml(title)}`,
      `id: ${ruleId}`,
      `status: experimental`,
      `description: Process creation observed during FraudVault analysis of submission ${submissionId}`,
      `references:`,
      `    - https://fraudvault.internal/submissions/${submissionId}`,
      `date: ${new Date().toISOString().split('T')[0]}`,
      `author: FraudVault Detection Engine`,
      `logsource:`,
      `    category: process_creation`,
      `    product: windows`,
      `detection:`,
      `    selection:`,
      `        Image|endswith: '\\${escapeYaml(proc.name)}'`,
      ...(cmdLine.length < 500
        ? [`        CommandLine|contains: ${escapeYaml(cmdLine)}`]
        : []),
      ...(proc.parentPid > 0
        ? [`        ParentProcessId: ${proc.parentPid}`]
        : []),
      `    condition: selection`,
      `falsepositives:`,
      `    - Legitimate usage of ${proc.name}`,
      `level: ${level}`,
      `tags:`,
      `    - attack.execution`,
    ].join('\n');

    rules.push({
      title,
      id: ruleId,
      status: 'experimental',
      level,
      description: `Process creation observed during FraudVault analysis of submission ${submissionId}`,
      logsource: { category: 'process_creation', product: 'windows' },
      yaml,
    });
  }

  return rules;
}

/**
 * Generate Sigma rules from registry modification events.
 */
function generateRegistryRules(modifications: RegistryModification[], submissionId: string): SigmaRule[] {
  const rules: SigmaRule[] = [];

  for (const mod of modifications) {
    if (mod.operation === 'delete') continue; // Less interesting for detection

    const ruleId = generateRuleId('sigma-reg', `${submissionId}-${mod.key}`);
    const title = `FraudVault - Registry Modification: ${mod.key.split('\\').pop() ?? 'Unknown'}`;
    let level = 'medium';

    // Persistence-related registry keys are more severe
    const keyLower = mod.key.toLowerCase();
    if (keyLower.includes('run') || keyLower.includes('startup') || keyLower.includes('services')) {
      level = 'high';
    }
    if (keyLower.includes('winlogon') || keyLower.includes('disableantispyware')) {
      level = 'critical';
    }

    const yaml = [
      `title: ${escapeYaml(title)}`,
      `id: ${ruleId}`,
      `status: experimental`,
      `description: Registry modification observed during FraudVault analysis of submission ${submissionId}`,
      `references:`,
      `    - https://fraudvault.internal/submissions/${submissionId}`,
      `date: ${new Date().toISOString().split('T')[0]}`,
      `author: FraudVault Detection Engine`,
      `logsource:`,
      `    category: registry_set`,
      `    product: windows`,
      `detection:`,
      `    selection:`,
      `        TargetObject|contains: ${escapeYaml(mod.key)}`,
      ...(mod.valueName
        ? [`        Details|contains: ${escapeYaml(mod.valueName)}`]
        : []),
      `    condition: selection`,
      `falsepositives:`,
      `    - Legitimate software installation`,
      `level: ${level}`,
      `tags:`,
      `    - attack.persistence`,
    ].join('\n');

    rules.push({
      title,
      id: ruleId,
      status: 'experimental',
      level,
      description: `Registry modification observed during FraudVault analysis of submission ${submissionId}`,
      logsource: { category: 'registry_set', product: 'windows' },
      yaml,
    });
  }

  return rules;
}

/**
 * Generate Sigma rules from network connection events.
 */
function generateNetworkRules(connections: NetworkConnection[], submissionId: string): SigmaRule[] {
  const rules: SigmaRule[] = [];

  // Deduplicate by destination address + port
  const seen = new Set<string>();

  for (const conn of connections) {
    const key = `${conn.destinationAddress}:${conn.destinationPort}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const ruleId = generateRuleId('sigma-net', `${submissionId}-${key}`);
    const title = `FraudVault - Network Connection to ${conn.destinationAddress}:${conn.destinationPort}`;
    let level = 'low';

    if (conn.protocol === 'dns') {
      level = 'informational';
    }
    if (conn.destinationPort !== 80 && conn.destinationPort !== 443 && conn.destinationPort !== 53) {
      level = 'medium';
    }

    const yaml = [
      `title: ${escapeYaml(title)}`,
      `id: ${ruleId}`,
      `status: experimental`,
      `description: Network connection observed during FraudVault analysis of submission ${submissionId}`,
      `references:`,
      `    - https://fraudvault.internal/submissions/${submissionId}`,
      `date: ${new Date().toISOString().split('T')[0]}`,
      `author: FraudVault Detection Engine`,
      `logsource:`,
      `    category: firewall`,
      `    product: any`,
      `detection:`,
      `    selection:`,
      `        dst_ip: ${escapeYaml(conn.destinationAddress)}`,
      `        dst_port: ${conn.destinationPort}`,
      ...(conn.domain ? [`        query|contains: ${escapeYaml(conn.domain)}`] : []),
      `    condition: selection`,
      `falsepositives:`,
      `    - Legitimate traffic to this endpoint`,
      `level: ${level}`,
      `tags:`,
      `    - attack.command_and_control`,
    ].join('\n');

    rules.push({
      title,
      id: ruleId,
      status: 'experimental',
      level,
      description: `Network connection observed during FraudVault analysis of submission ${submissionId}`,
      logsource: { category: 'firewall', product: 'any' },
      yaml,
    });
  }

  return rules;
}

/**
 * Generate all Sigma rules from dynamic analysis results.
 */
export function generateSigmaRules(
  dynamicAnalysis: DynamicAnalysisResult,
  submissionId: string,
): SigmaRule[] {
  const rules: SigmaRule[] = [];

  rules.push(...generateProcessCreationRules(dynamicAnalysis.processesCreated, submissionId));
  rules.push(...generateRegistryRules(dynamicAnalysis.registryModifications, submissionId));
  rules.push(...generateNetworkRules(dynamicAnalysis.networkConnections, submissionId));

  return rules;
}
