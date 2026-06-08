import type {
  AnalysisReport,
  IOC,
  ATTACKTechnique,
  IOCType,
} from '@scanboy/shared';

// ── STIX 2.1 Types ────────────────────────────────────────────────────────

interface STIXBundle {
  type: 'bundle';
  id: string;
  objects: STIXObject[];
}

type STIXObject = MalwareSDO | IndicatorSDO | AttackPatternSDO | RelationshipSRO;

interface MalwareSDO {
  type: 'malware';
  spec_version: '2.1';
  id: string;
  created: string;
  modified: string;
  name: string;
  description: string;
  malware_types: string[];
  is_family: boolean;
  confidence: number;
}

interface IndicatorSDO {
  type: 'indicator';
  spec_version: '2.1';
  id: string;
  created: string;
  modified: string;
  name: string;
  description: string;
  indicator_types: string[];
  pattern: string;
  pattern_type: 'stix';
  valid_from: string;
  confidence: number;
}

interface AttackPatternSDO {
  type: 'attack-pattern';
  spec_version: '2.1';
  id: string;
  created: string;
  modified: string;
  name: string;
  description: string;
  external_references: Array<{
    source_name: string;
    external_id: string;
    url: string;
  }>;
}

interface RelationshipSRO {
  type: 'relationship';
  spec_version: '2.1';
  id: string;
  created: string;
  modified: string;
  relationship_type: string;
  source_ref: string;
  target_ref: string;
  description: string;
}

// ── ID Generation ──────────────────────────────────────────────────────────

function stixId(type: string): string {
  return `${type}--${crypto.randomUUID()}`;
}

// ── IOC to STIX Pattern Mapping ────────────────────────────────────────────

const IOC_TYPE_TO_STIX_PATTERN: Record<IOCType, (value: string) => string> = {
  ip: (v: string) => `[ipv4-addr:value = '${escapeStix(v)}']`,
  ipv6: (v: string) => `[ipv6-addr:value = '${escapeStix(v)}']`,
  domain: (v) => `[domain-name:value = '${escapeStix(v)}']`,
  url: (v) => `[url:value = '${escapeStix(v)}']`,
  email: (v) => `[email-addr:value = '${escapeStix(v)}']`,
  file_hash: (v) => {
    // Detect hash type by length
    if (v.length === 32) return `[file:hashes.MD5 = '${escapeStix(v)}']`;
    if (v.length === 40) return `[file:hashes.'SHA-1' = '${escapeStix(v)}']`;
    if (v.length === 64) return `[file:hashes.'SHA-256' = '${escapeStix(v)}']`;
    return `[file:hashes.MD5 = '${escapeStix(v)}']`;
  },
  mutex: (v) => `[mutex:name = '${escapeStix(v)}']`,
  registry_key: (v) => `[windows-registry-key:key = '${escapeStix(v)}']`,
  file_path: (v) => `[file:name = '${escapeStix(v)}']`,
  certificate: (v) => `[x509-certificate:serial_number = '${escapeStix(v)}']`,
};

function escapeStix(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\]/g, '\\]').replace(/\[/g, '\\[');
}

function getIndicatorType(iocType: IOCType): string[] {
  switch (iocType) {
    case 'ip':
    case 'ipv6':
    case 'domain':
    case 'url':
      return ['malicious-activity'];
    case 'file_hash':
    case 'file_path':
      return ['malicious-activity'];
    case 'email':
      return ['malicious-activity'];
    case 'mutex':
    case 'registry_key':
      return ['malicious-activity'];
    case 'certificate':
      return ['anomalous-activity'];
    default:
      return ['malicious-activity'];
  }
}

// ── STIX Bundle Generation ─────────────────────────────────────────────────

export function exportToSTIX(report: AnalysisReport): STIXBundle {
  const now = new Date().toISOString();
  const objects: STIXObject[] = [];

  // Create Malware SDO
  const malwareName = getMalwareName(report);
  const malwareId = stixId('malware');
  const malwareSDO: MalwareSDO = {
    type: 'malware',
    spec_version: '2.1',
    id: malwareId,
    created: now,
    modified: now,
    name: malwareName,
    description: report.summary,
    malware_types: determineMalwareTypes(report),
    is_family: false,
    confidence: Math.round(report.threatScore),
  };
  objects.push(malwareSDO);

  // Create Indicator SDOs for each IOC
  for (const ioc of report.iocs) {
    const indicatorId = stixId('indicator');
    const indicatorSDO = createIndicatorSDO(ioc, indicatorId, now);
    objects.push(indicatorSDO);

    // Create Relationship SRO: indicator -> indicates -> malware
    objects.push(createRelationship(indicatorId, 'indicates', malwareId, now, `IOC ${ioc.value} indicates ${malwareName}`));
  }

  // Create Attack Pattern SDOs for ATT&CK techniques
  for (const technique of report.attackTechniques) {
    const attackPatternId = stixId('attack-pattern');
    const attackPatternSDO = createAttackPatternSDO(technique, attackPatternId, now);
    objects.push(attackPatternSDO);

    // Create Relationship SRO: malware -> uses -> attack-pattern
    objects.push(createRelationship(malwareId, 'uses', attackPatternId, now, `${malwareName} uses ${technique.name}`));
  }

  return {
    type: 'bundle',
    id: stixId('bundle'),
    objects,
  };
}

function createIndicatorSDO(ioc: IOC, id: string, now: string): IndicatorSDO {
  const patternFn = IOC_TYPE_TO_STIX_PATTERN[ioc.type as IOCType] ?? ((v: string) => `[artifact:payload_bin = '${escapeStix(v)}']`);
  const pattern = patternFn(ioc.value);

  return {
    type: 'indicator',
    spec_version: '2.1',
    id,
    created: now,
    modified: now,
    name: `${ioc.type}: ${ioc.value}`,
    description: ioc.context ?? `Extracted ${ioc.type} indicator`,
    indicator_types: getIndicatorType(ioc.type),
    pattern,
    pattern_type: 'stix',
    valid_from: ioc.firstSeenAt,
    confidence: Math.min(100, Math.round(ioc.confidence)),
  };
}

function createAttackPatternSDO(
  technique: ATTACKTechnique,
  id: string,
  now: string,
): AttackPatternSDO {
  return {
    type: 'attack-pattern',
    spec_version: '2.1',
    id,
    created: now,
    modified: now,
    name: technique.name,
    description: technique.description,
    external_references: [
      {
        source_name: 'mitre-attack',
        external_id: technique.techniqueId,
        url: `https://attack.mitre.org/techniques/${technique.techniqueId.replace('.', '/')}/`,
      },
    ],
  };
}

function createRelationship(
  sourceRef: string,
  relationshipType: string,
  targetRef: string,
  now: string,
  description: string,
): RelationshipSRO {
  return {
    type: 'relationship',
    spec_version: '2.1',
    id: stixId('relationship'),
    created: now,
    modified: now,
    relationship_type: relationshipType,
    source_ref: sourceRef,
    target_ref: targetRef,
    description,
  };
}

function getMalwareName(report: AnalysisReport): string {
  // Try to get family name from threat intel
  for (const ti of report.threatIntel) {
    if (ti.malwareFamily) return ti.malwareFamily;
  }
  return report.submission.fileName;
}

function determineMalwareTypes(report: AnalysisReport): string[] {
  const types = new Set<string>();

  for (const ti of report.threatIntel) {
    for (const tag of ti.tags) {
      const lower = tag.toLowerCase();
      if (lower.includes('ransomware')) types.add('ransomware');
      else if (lower.includes('trojan')) types.add('trojan');
      else if (lower.includes('worm')) types.add('worm');
      else if (lower.includes('backdoor')) types.add('backdoor');
      else if (lower.includes('spyware')) types.add('spyware');
      else if (lower.includes('dropper')) types.add('dropper');
      else if (lower.includes('rootkit')) types.add('rootkit');
      else if (lower.includes('keylogger')) types.add('keylogger');
      else if (lower.includes('adware')) types.add('adware');
      else if (lower.includes('rat') || lower.includes('remote-access'))
        types.add('remote-access-trojan');
    }
  }

  if (types.size === 0) types.add('unknown');
  return Array.from(types);
}
