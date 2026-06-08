import type {
  StaticAnalysisResult,
  DynamicAnalysisResult,
  NetworkConnection,
  FileModification,
  RegistryModification,
} from '@scanboy/shared';
import { getTrancoRank } from '../domainReputation.js';

// ── Types ──────────────────────────────────────────────────────────────────

/** Describes a network communication pattern observed during detonation. */
export interface NetworkPattern {
  protocol: string;
  port: number;
  isDGA: boolean;
  usesEncryption: boolean;
  beaconInterval?: number;
}

/**
 * A normalised multi-dimensional behavioural vector that represents the
 * observable characteristics of a malware sample. Used as the basis for
 * similarity comparison and hierarchical clustering.
 */
export interface BehaviorVector {
  /** MITRE ATT&CK technique IDs observed (e.g. ['T1055', 'T1059.001']). */
  techniques: string[];
  /** Normalised network communication patterns. */
  networkPatterns: NetworkPattern[];
  /** Persistence mechanisms used (registry run keys, services, tasks, ...). */
  persistenceMethods: string[];
  /** Normalised filesystem activity patterns (extensions, directories). */
  filePatterns: string[];
  /** Normalised registry key patterns. */
  registryPatterns: string[];
  /** Suspicious / notable Windows API imports. */
  imports: string[];
}

// ── Persistence detection helpers ──────────────────────────────────────────

const PERSISTENCE_REGISTRY_PATTERNS: ReadonlyArray<{ pattern: string; label: string }> = [
  { pattern: 'currentversion\\run', label: 'registry_run_key' },
  { pattern: 'currentversion\\runonce', label: 'registry_runonce' },
  { pattern: 'currentcontrolset\\services', label: 'windows_service' },
  { pattern: 'winlogon', label: 'winlogon_helper' },
  { pattern: 'explorer\\shell folders', label: 'shell_folders' },
  { pattern: 'explorer\\user shell folders', label: 'user_shell_folders' },
  { pattern: 'currentversion\\explorer\\startup', label: 'startup_folder_reg' },
  { pattern: 'policies\\explorer\\run', label: 'policy_run_key' },
  { pattern: 'currentversion\\windows\\load', label: 'windows_load' },
  { pattern: 'currentversion\\windows\\run', label: 'windows_run' },
];

const PERSISTENCE_FILE_PATTERNS: ReadonlyArray<{ pattern: string; label: string }> = [
  { pattern: 'start menu\\programs\\startup', label: 'startup_folder' },
  { pattern: 'appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup', label: 'user_startup_folder' },
  { pattern: 'tasks\\', label: 'scheduled_task_file' },
];

const PERSISTENCE_PROCESS_PATTERNS: ReadonlyArray<{ pattern: string; label: string }> = [
  { pattern: 'schtasks', label: 'scheduled_task' },
  { pattern: 'sc create', label: 'service_creation' },
  { pattern: 'sc config', label: 'service_config' },
  { pattern: 'reg add', label: 'registry_add' },
  { pattern: 'wmic', label: 'wmi_persistence' },
];

// ── Network analysis helpers ───────────────────────────────────────────────

/** Heuristic check for domain generation algorithm (DGA) characteristics. */
function isDGADomain(domain: string): boolean {
  if (!domain || domain.length === 0) return false;

  // Known legitimate domains are never DGA
  if (getTrancoRank(domain) !== null) return false;

  // Strip TLD
  const parts = domain.split('.');
  const sld = parts.length >= 2 ? parts[parts.length - 2] : domain;
  if (!sld || sld.length === 0) return false;

  // Long random-looking second-level domains are suspicious
  if (sld.length > 16) return true;

  // High ratio of consonants to vowels
  const vowels = (sld.match(/[aeiou]/gi) ?? []).length;
  const consonants = sld.length - vowels;
  if (sld.length > 8 && vowels > 0 && consonants / vowels > 5) return true;

  // Many digits mixed with letters
  const digits = (sld.match(/\d/g) ?? []).length;
  const letters = (sld.match(/[a-z]/gi) ?? []).length;
  if (digits > 0 && letters > 0 && digits / sld.length > 0.4) return true;

  return false;
}

const ENCRYPTED_PROTOCOLS = new Set(['tls', 'https']);

function connectionUsesEncryption(conn: NetworkConnection): boolean {
  if (ENCRYPTED_PROTOCOLS.has(conn.protocol)) return true;
  if (conn.destinationPort === 443) return true;
  return false;
}

/**
 * Detect beaconing by looking for connections to the same destination with
 * roughly regular timing (heuristic: >3 connections to same dest:port pair).
 * Returns 0 when no clear interval is found.
 */
function detectBeaconInterval(connections: NetworkConnection[]): number {
  // Group by destination
  const groups = new Map<string, number>();
  for (const c of connections) {
    const key = `${c.destinationAddress}:${String(c.destinationPort)}`;
    groups.set(key, (groups.get(key) ?? 0) + 1);
  }

  // If any endpoint is contacted more than 3 times, assume beaconing
  for (const [, count] of groups) {
    if (count > 3) {
      // We don't have timestamps on individual connections, so return a
      // synthetic marker (count as proxy).
      return count;
    }
  }
  return 0;
}

// ── File pattern normalisation ─────────────────────────────────────────────

/** Normalise a file modification into a canonical pattern string. */
function normaliseFileMod(mod: FileModification): string {
  const lower = mod.path.toLowerCase();
  const ext = extractExtension(lower);
  const dir = normaliseDirectory(lower);
  return `${mod.operation}:${dir}:${ext}`;
}

function extractExtension(path: string): string {
  const dotIdx = path.lastIndexOf('.');
  if (dotIdx === -1 || dotIdx === path.length - 1) return 'none';
  return path.slice(dotIdx + 1);
}

function normaliseDirectory(path: string): string {
  if (path.includes('\\system32\\')) return 'system32';
  if (path.includes('\\syswow64\\')) return 'syswow64';
  if (path.includes('\\temp\\') || path.includes('\\tmp\\')) return 'temp';
  if (path.includes('\\appdata\\')) return 'appdata';
  if (path.includes('\\programdata\\')) return 'programdata';
  if (path.includes('\\windows\\')) return 'windows';
  if (path.includes('\\program files')) return 'program_files';
  if (path.includes('\\desktop\\')) return 'desktop';
  if (path.includes('\\documents\\')) return 'documents';
  return 'other';
}

// ── Registry pattern normalisation ─────────────────────────────────────────

function normaliseRegistryMod(mod: RegistryModification): string {
  const lower = mod.key.toLowerCase();

  // Collapse user-specific SIDs
  const normalised = lower.replace(
    /hku\\s-\d+-\d+-\d+-[\d-]+/g,
    'hku\\<sid>',
  );

  // Extract the meaningful suffix after well-known prefixes
  const suffixPatterns = [
    'software\\microsoft\\windows\\currentversion\\',
    'system\\currentcontrolset\\',
    'software\\classes\\',
    'software\\policies\\',
  ];

  for (const prefix of suffixPatterns) {
    const idx = normalised.indexOf(prefix);
    if (idx !== -1) {
      return `${mod.operation}:${normalised.slice(idx)}`;
    }
  }

  return `${mod.operation}:${normalised}`;
}

// ── Import normalisation ───────────────────────────────────────────────────

/** Set of notable API imports to extract as behavioural features. */
const NOTABLE_IMPORTS = new Set([
  'virtualalloc', 'virtualallocex', 'virtualprotect',
  'writeprocessmemory', 'readprocessmemory', 'ntwritevirtualmemory',
  'createremotethread', 'ntcreatethread', 'rtlcreateuserthread',
  'ntunmapviewofsection', 'zwunmapviewofsection', 'ntmapviewofsection',
  'loadlibrarya', 'loadlibraryw', 'getprocaddress',
  'setwindowshookexa', 'setwindowshookexw',
  'getasynckeystate', 'getkeystate',
  'internetopena', 'internetopenw', 'internetconnecta',
  'httpsendrequesta', 'httpopenrequesta',
  'urldownloadtofilea', 'urldownloadtofilew',
  'wsastartup', 'connect', 'send', 'recv', 'socket',
  'createservicea', 'createservicew', 'openservicea',
  'regsetvalueexa', 'regsetvalueexw', 'regcreatekeyexa',
  'cryptencrypt', 'cryptdecrypt', 'cryptacquirecontexta',
  'isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess',
  'createfilea', 'createfilew', 'writefile', 'readfile',
  'openprocess', 'terminateprocess',
  'bitblt', 'getdc', 'getdesktopwindow',
  'openclipboard', 'getclipboarddata',
  'lsaretrieveprivatedata', 'credenumeratea', 'credenumeratew',
  'adjusttokenprivileges', 'lookupprivilegevaluea',
  'registerrawinputdevices', 'getrawinputdata',
]);

function normaliseImports(imports: string[]): string[] {
  const matched: string[] = [];
  for (const imp of imports) {
    const lower = imp.toLowerCase();
    for (const notable of NOTABLE_IMPORTS) {
      if (lower.includes(notable)) {
        matched.push(notable);
      }
    }
  }
  return [...new Set(matched)].sort();
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Build a normalised behavioural vector from the combined static + dynamic
 * analysis results of a submission. The vector captures the observable
 * characteristics that define how a sample behaves and is used downstream
 * for similarity scoring and malware family clustering.
 */
export function buildBehaviorVector(
  staticAnalysis: StaticAnalysisResult | null,
  dynamicAnalysis: DynamicAnalysisResult | null,
): BehaviorVector {
  // ── Techniques ─────────────────────────────────────────────────────
  const techniques: string[] = [];
  if (staticAnalysis?.attackTechniques) {
    for (const t of staticAnalysis.attackTechniques) {
      techniques.push(t.techniqueId);
    }
  }
  if (dynamicAnalysis?.attackTechniques) {
    for (const t of dynamicAnalysis.attackTechniques) {
      techniques.push(t.techniqueId);
    }
  }
  const uniqueTechniques = [...new Set(techniques)].sort();

  // ── Network patterns ───────────────────────────────────────────────
  const networkPatterns: NetworkPattern[] = [];
  if (dynamicAnalysis?.networkConnections) {
    const seenPorts = new Map<string, NetworkPattern>();
    const beaconInterval = detectBeaconInterval(dynamicAnalysis.networkConnections);

    for (const conn of dynamicAnalysis.networkConnections) {
      const key = `${conn.protocol}:${String(conn.destinationPort)}`;
      if (!seenPorts.has(key)) {
        const domain = conn.domain ?? '';
        seenPorts.set(key, {
          protocol: conn.protocol,
          port: conn.destinationPort,
          isDGA: isDGADomain(domain),
          usesEncryption: connectionUsesEncryption(conn),
          ...(beaconInterval > 0 ? { beaconInterval } : {}),
        });
      }
    }
    networkPatterns.push(...seenPorts.values());
  }

  // ── Persistence methods ────────────────────────────────────────────
  const persistenceMethods = new Set<string>();

  if (dynamicAnalysis) {
    // Check registry modifications
    for (const mod of dynamicAnalysis.registryModifications) {
      const keyLower = mod.key.toLowerCase();
      for (const { pattern, label } of PERSISTENCE_REGISTRY_PATTERNS) {
        if (keyLower.includes(pattern)) {
          persistenceMethods.add(label);
        }
      }
    }

    // Check file modifications
    for (const mod of dynamicAnalysis.filesModified) {
      const pathLower = mod.path.toLowerCase();
      for (const { pattern, label } of PERSISTENCE_FILE_PATTERNS) {
        if (pathLower.includes(pattern)) {
          persistenceMethods.add(label);
        }
      }
    }

    // Check process creation
    for (const proc of dynamicAnalysis.processesCreated) {
      const cmdLower = proc.commandLine.toLowerCase();
      for (const { pattern, label } of PERSISTENCE_PROCESS_PATTERNS) {
        if (cmdLower.includes(pattern)) {
          persistenceMethods.add(label);
        }
      }
    }
  }

  // ── File patterns ──────────────────────────────────────────────────
  const filePatterns = new Set<string>();
  if (dynamicAnalysis?.filesModified) {
    for (const mod of dynamicAnalysis.filesModified) {
      filePatterns.add(normaliseFileMod(mod));
    }
  }

  // ── Registry patterns ──────────────────────────────────────────────
  const registryPatterns = new Set<string>();
  if (dynamicAnalysis?.registryModifications) {
    for (const mod of dynamicAnalysis.registryModifications) {
      registryPatterns.add(normaliseRegistryMod(mod));
    }
  }

  // ── Imports ────────────────────────────────────────────────────────
  const imports = normaliseImports(staticAnalysis?.imports ?? []);

  return {
    techniques: uniqueTechniques,
    networkPatterns,
    persistenceMethods: [...persistenceMethods].sort(),
    filePatterns: [...filePatterns].sort(),
    registryPatterns: [...registryPatterns].sort(),
    imports,
  };
}

/**
 * Compute a flat numerical feature vector from a BehaviorVector.
 * This is used by cosine similarity for dense feature comparisons.
 *
 * Features are counts/indicators grouped into the same categories
 * as the BehaviorVector itself.
 */
export function toNumericalVector(vector: BehaviorVector): number[] {
  return [
    vector.techniques.length,
    vector.networkPatterns.length,
    vector.networkPatterns.filter((p) => p.isDGA).length,
    vector.networkPatterns.filter((p) => p.usesEncryption).length,
    vector.networkPatterns.filter((p) => p.beaconInterval !== undefined && p.beaconInterval > 0).length,
    vector.persistenceMethods.length,
    vector.filePatterns.length,
    vector.filePatterns.filter((p) => p.startsWith('create:')).length,
    vector.filePatterns.filter((p) => p.startsWith('modify:')).length,
    vector.filePatterns.filter((p) => p.startsWith('delete:')).length,
    vector.registryPatterns.length,
    vector.imports.length,
  ];
}
