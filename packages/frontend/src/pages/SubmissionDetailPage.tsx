import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useState, useCallback, type ReactNode } from 'react';
import {
  FileSearch,
  Shield,
  Cpu,
  Eye,
  Clock,
  Hash,
  AlertTriangle,
  ChevronRight,
  Activity,
  Copy,
  Check,
  ExternalLink,
  Globe,
  Mail,
  HardDrive,
  Key,
  FileText,
  Bug,
  Target,
  ChevronDown,
  ChevronUp,
  Folder,
  Terminal,
  Wifi,
  Server,
  Lock,
  Download,
  Code,
  ShieldAlert,
  Info,
  Package,
  Microscope,
  ShieldCheck,
  XCircle,
  Boxes,
  Database,
} from 'lucide-react';
import { clsx } from 'clsx';

// ── Type Definitions ────────────────────────────────────────────────────────

interface ThreatIntelEntry {
  provider: string;
  verdict: string;
  detection_count: number;
  total_engines: number;
  malware_family: string | null;
  first_seen: string | null;
  last_seen: string | null;
  raw_response: Record<string, unknown> | null;
}

interface IOCEntry {
  type: string;
  value: string;
  context: string | null;
  confidence: number;
}

interface AttackTechniqueEntry {
  tacticId: string;
  techniqueId: string;
  evidence: Record<string, unknown> | string | null;
  confidence: number;
}

interface AnalysisJob {
  id: string;
  jobType: string;
  status: string;
  startedAt: string | null;
  completedAt: string | null;
}

interface NoteEntry {
  id: string;
  content: string;
  username: string;
  createdAt: string;
}

interface ProcessTreeNode {
  pid: number;
  name: string;
  commandLine: string;
  children: ProcessTreeNode[];
}

interface ProcessTree {
  root: ProcessTreeNode;
  totalProcesses: number;
  maxDepth: number;
}

interface ProcessInfoEntry {
  pid: number;
  parentPid: number;
  name: string;
  commandLine: string;
  user: string;
  startTime: string;
}

interface FileChangeEntry {
  path: string;
  timestamp: string;
}

interface ConnectionEntry {
  protocol: string;
  sourceAddress: string;
  sourcePort: number;
  destinationAddress: string;
  destinationPort: number;
  timestamp: string;
}

interface DnsQueryEntry {
  domain: string;
  queryType: string;
  responseAddress: string | null;
  timestamp: string;
}

interface DroppedFileEntry {
  path: string;
  size: number;
  sha256: string | null;
  mimeType: string | null;
  isSuspiciousLocation: boolean;
}

interface SuspiciousIndicatorEntry {
  category: string;
  description: string;
  severity: string;
  evidence: string;
}

interface PESectionEntry {
  name: string;
  size: number;
  entropy: number;
}

interface ExtractedFileEntry {
  path: string;
  size: number;
  sha256: string;
  sha1: string;
  md5: string;
  entropy: number;
  fileType: string;
  isPE: boolean;
  isELF: boolean;
  imphash?: string;
  ssdeep?: string;
  compileTimestamp?: { unix: number; utc: string };
  pdbPaths?: string[];
  peInfo?: { machine: string; sections: number };
  imports?: string[];
  suspiciousImports?: string[];
  suspiciousStrings?: string[];
  totalStrings?: number;
  urls?: string[];
  ips?: string[];
  emails?: string[];
  domains?: string[];
  registryKeys?: string[];
  mutexPatterns?: string[];
  filePaths?: string[];
  sections?: PESectionEntry[];
  versionInfo?: Record<string, string>;
  signature?: {
    hasCertificate: boolean;
    isValidVendor: boolean;
    isForged?: boolean;
    signer?: string;
    issuer?: string;
  };
  error?: string;
}

interface CveDisplayEntry {
  id: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvssScore: number;
  publishedDate: string;
  isKev: boolean;
  epssScore: number;
  epssPercentile: number;
  references: string[];
}

interface VulnResultData {
  cves: CveDisplayEntry[];
  softwareName: string;
  softwareVersion: string;
}

interface TechDebtData {
  productName: string;
  installedVersion: string;
  latestVersion: string;
  majorsBehind: number;
  isEol: boolean;
  eolDate: string | null;
  releaseDate: string | null;
}

interface DynamicAnalysisData {
  processes: Array<Record<string, unknown>> | null;
  network_activity: Record<string, unknown> | null;
  memory_activity: Record<string, unknown> | null;
  file_activity: Record<string, unknown> | null;
  registry_activity: Record<string, unknown> | null;
  duration_seconds: number | null;
}

// ── Deep Analysis Types ─────────────────────────────────────────────────────

interface DeepAnalysisPeSectionRatio {
  name: string;
  virtualSize: number;
  rawSize: number;
  ratio: number;
}

interface DeepAnalysisRichHeaderEntry {
  buildId: number;
  count: number;
  product: string;
}

interface DeepAnalysisPe {
  delayLoadImports?: string[];
  loadConfig?: { sehHandlerCount: number; guardCfCount: number; hasSecurityCookie: boolean };
  checksumValid?: boolean;
  sectionAnomalyScore?: number;
  sectionRatios?: DeepAnalysisPeSectionRatio[];
  iatEntropy?: number;
  dosStubSize?: number;
  exportAnomalies?: number;
  tlsDataSize?: number;
  richHeader?: { entries: DeepAnalysisRichHeaderEntry[] };
  resourceLanguages?: string[];
  manifest?: { requestedLevel: string };
  dotnetVersion?: string;
  mitigations?: { aslr?: boolean; dep?: boolean; seh?: boolean; cfg?: boolean };
}

interface DeepAnalysisElf {
  buildId?: string;
  compiler?: string;
  hasGnuHash?: boolean;
  interpreter?: string;
  fullRelro?: boolean;
  fortifyRatio?: number;
  minGlibc?: string;
}

interface DeepAnalysisEmbeddedFile {
  offset: number;
  type: string;
  size: number;
}

interface DeepAnalysisXorResult {
  key: string;
  result: string;
}

interface DeepAnalysisFormat {
  isZipBomb?: boolean;
  isPolyglot?: boolean;
  embeddedFiles?: DeepAnalysisEmbeddedFile[];
  entropyHistogram?: { chiSquaredUniform: number; distribution: string };
  xorDecrypted?: DeepAnalysisXorResult[];
}

interface DeepAnalysisSynPacket {
  dstIp: string;
  dstPort: number;
}

interface DeepAnalysisNetwork {
  synPackets?: DeepAnalysisSynPacket[];
  ja3Hash?: string;
  sniDomains?: string[];
  icmpDestinations?: number;
  dnsQps?: number;
  arpRequests?: number;
}

interface DeepAnalysisRuntime {
  rwxTransitions?: number;
  procReads?: string[];
  directoryScans?: string[];
  masquerading?: boolean;
  peakMemoryMb?: number;
  threadCount?: number;
  tracerPidDetected?: boolean;
  dllLoadOrder?: string[];
  wineExitCode?: string;
  driveC_newFiles?: string[];
}

interface DeepAnalysisData {
  pe?: DeepAnalysisPe;
  elf?: DeepAnalysisElf;
  format?: DeepAnalysisFormat;
  runtime?: DeepAnalysisRuntime;
  network?: DeepAnalysisNetwork;
}

interface StaticAnalysisData {
  file_metadata: Record<string, unknown> | null;
  strings: Array<Record<string, unknown>> | null;
  entropy_data: Record<string, unknown> | null;
  pe_analysis: Record<string, unknown> | null;
  elf_analysis: Record<string, unknown> | null;
  script_analysis: Record<string, unknown> | null;
  certificates: Record<string, unknown> | null;
}

interface SubmissionDetail {
  id: string;
  filename: string;
  fileSize: number;
  fileType: string;
  mimeType: string;
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
  tlsh: string;
  ssdeep: string;
  status: string;
  threatLevel: string;
  threatScore: number;
  submissionType: string;
  createdAt: string;
  updatedAt: string;
  staticAnalysis: StaticAnalysisData | null;
  dynamicAnalysis: DynamicAnalysisData | null;
  threatIntel: ThreatIntelEntry[];
  iocs: IOCEntry[];
  attackTechniques: AttackTechniqueEntry[];
  notes: NoteEntry[];
  jobs: AnalysisJob[];
}

// ── MITRE ATT&CK Kill Chain Phase Mappings ──────────────────────────────────

const TACTIC_DISPLAY_ORDER: readonly string[] = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

const TACTIC_LABELS: Record<string, string> = {
  'reconnaissance': 'Reconnaissance',
  'resource-development': 'Resource Development',
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Movement',
  'collection': 'Collection',
  'command-and-control': 'Command & Control',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
};

const TECHNIQUE_NAMES: Record<string, string> = {
  'T1027': 'Obfuscated Files or Information',
  'T1027.002': 'Software Packing',
  'T1027.005': 'Indicator Removal from Tools',
  'T1036.008': 'Masquerade File Type',
  'T1055': 'Process Injection',
  'T1059': 'Command and Scripting Interpreter',
  'T1071': 'Application Layer Protocol',
  'T1071.004': 'DNS',
  'T1105': 'Ingress Tool Transfer',
  'T1003': 'OS Credential Dumping',
  'T1053.003': 'Cron',
  'T1490': 'Inhibit System Recovery',
  'T1486': 'Data Encrypted for Impact',
  'T1547.001': 'Registry Run Keys / Startup Folder',
};

// ── IOC Type Icons & Labels ─────────────────────────────────────────────────

const IOC_TYPE_CONFIG: Record<string, { label: string; icon: typeof Globe; color: string }> = {
  domain: { label: 'Domains', icon: Globe, color: 'text-blue-400' },
  url: { label: 'URLs', icon: ExternalLink, color: 'text-cyan-400' },
  ip: { label: 'IP Addresses', icon: Server, color: 'text-orange-400' },
  hash_md5: { label: 'MD5 Hashes', icon: Hash, color: 'text-purple-400' },
  hash_sha1: { label: 'SHA1 Hashes', icon: Hash, color: 'text-purple-400' },
  hash_sha256: { label: 'SHA256 Hashes', icon: Hash, color: 'text-purple-400' },
  registry_key: { label: 'Registry Keys', icon: Key, color: 'text-yellow-400' },
  file_path: { label: 'File Paths', icon: Folder, color: 'text-green-400' },
  mutex: { label: 'Mutexes', icon: Lock, color: 'text-red-400' },
  email: { label: 'Email Addresses', icon: Mail, color: 'text-pink-400' },
  certificate: { label: 'Certificates', icon: Shield, color: 'text-emerald-400' },
  service: { label: 'Services', icon: HardDrive, color: 'text-slate-400' },
};

// ── Data Parsing Helpers ────────────────────────────────────────────────────

function parseMemActivity(da: DynamicAnalysisData | null): Record<string, unknown> | null {
  if (!da) return null;
  let mem = da.memory_activity as Record<string, unknown> | string | null;
  if (typeof mem === 'string') {
    try { mem = JSON.parse(mem) as Record<string, unknown>; } catch { return null; }
  }
  return mem as Record<string, unknown> | null;
}

function getExtractedFiles(da: DynamicAnalysisData | null): ExtractedFileEntry[] {
  const mem = parseMemActivity(da);
  if (!mem) return [];
  const raw = mem['extractedFiles'];
  if (Array.isArray(raw)) return raw as ExtractedFileEntry[];
  if (typeof raw === 'string') {
    try { return JSON.parse(raw) as ExtractedFileEntry[]; } catch { return []; }
  }
  return [];
}

function getDeepAnalysis(da: DynamicAnalysisData | null): DeepAnalysisData | null {
  const mem = parseMemActivity(da);
  if (!mem) return null;
  const raw = mem['deepAnalysis'];
  if (!raw) return null;
  if (typeof raw === 'string') {
    try { return JSON.parse(raw) as DeepAnalysisData; } catch { return null; }
  }
  return raw as DeepAnalysisData;
}

// ── Utility Components ──────────────────────────────────────────────────────

function SectionHeader({
  icon: Icon,
  title,
}: {
  icon: typeof FileSearch;
  title: string;
}) {
  return (
    <div className="flex items-center gap-2 mb-4">
      <Icon className="w-5 h-5 text-gray-400" />
      <h2 className="text-lg font-semibold text-white">{title}</h2>
    </div>
  );
}

function HashRow({ label, value }: { label: string; value: string }) {
  if (!value) return null;
  return (
    <div className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0">
      <span className="text-sm text-gray-400">{label}</span>
      <CopyableText text={value} className="text-xs text-gray-300 font-mono" />
    </div>
  );
}

function CopyableText({ text, className }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }).catch(() => {
      // Fallback: select text
    });
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      className={clsx(
        'inline-flex items-center gap-1 select-all cursor-pointer hover:text-white transition-colors',
        className,
      )}
      title="Click to copy"
    >
      <span className="truncate max-w-[400px]">{text}</span>
      {copied
        ? <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
        : <Copy className="w-3 h-3 text-gray-600 flex-shrink-0 hover:text-gray-400" />}
    </button>
  );
}

function ThreatScoreRing({ score, level }: { score: number; level: string }) {
  const colors: Record<string, string> = {
    critical: 'text-red-500',
    high: 'text-orange-500',
    medium: 'text-yellow-500',
    low: 'text-blue-500',
    informational: 'text-gray-500',
  };
  const circumference = 2 * Math.PI * 42;
  const dashOffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-24 h-24">
        <svg className="w-24 h-24 -rotate-90" viewBox="0 0 96 96">
          <circle cx="48" cy="48" r="42" fill="none" stroke="currentColor"
            className="text-gray-800" strokeWidth="4" />
          <circle cx="48" cy="48" r="42" fill="none" stroke="currentColor"
            className={colors[level] ?? 'text-gray-500'}
            strokeWidth="4" strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset} />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={clsx('text-2xl font-bold', colors[level] ?? 'text-gray-500')}>
            {score}
          </span>
        </div>
      </div>
      <span className={clsx('mt-2 text-sm font-medium uppercase', colors[level] ?? 'text-gray-500')}>
        {level}
      </span>
    </div>
  );
}

function ConfidenceBar({ confidence }: { confidence: number }) {
  const color = confidence >= 80 ? 'bg-red-500' : confidence >= 60 ? 'bg-orange-500' : confidence >= 40 ? 'bg-yellow-500' : 'bg-blue-500';
  return (
    <div className="flex items-center gap-2 min-w-[100px]">
      <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <div className={clsx('h-full rounded-full transition-all', color)}
          style={{ width: `${Math.min(100, confidence)}%` }} />
      </div>
      <span className="text-xs text-gray-500 w-8 text-right">{confidence}%</span>
    </div>
  );
}

function CollapsibleSection({
  icon: Icon,
  title,
  defaultOpen = false,
  children,
  badge,
}: {
  icon: typeof FileSearch;
  title: string;
  defaultOpen?: boolean;
  children: ReactNode;
  badge?: string | number;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-6 text-left hover:bg-gray-800/30 transition-colors rounded-xl"
      >
        <div className="flex items-center gap-2">
          <Icon className="w-5 h-5 text-gray-400" />
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          {badge !== undefined && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-gray-800 text-gray-400">
              {badge}
            </span>
          )}
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
      </button>
      {open && <div className="px-6 pb-6">{children}</div>}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

// ── Report Summary Generator ────────────────────────────────────────────────

function generateSummary(submission: SubmissionDetail): string {
  const parts: string[] = [];

  // File description
  const mime = submission.mimeType ?? '';
  const ftype = submission.fileType ?? '';
  const fileDesc = mime.includes('zip') || ftype === '.tar' ? 'a container/archive image'
    : mime.includes('rar') ? 'a RAR archive'
    : mime.includes('x-dosexec') || ftype === '.exe' ? 'a Windows PE executable'
    : mime.includes('x-elf') ? 'a Linux ELF binary'
    : `a ${ftype || mime || 'unknown'} file`;
  parts.push(`This file is ${fileDesc} (${formatBytes(submission.fileSize)}).`);

  // Extracted file info
  const memActivity = parseMemActivity(submission.dynamicAnalysis ?? null);
  const extractedFiles = memActivity?.['extractedFiles'] as ExtractedFileEntry[] | undefined;
  if (extractedFiles && extractedFiles.length > 0) {
    const peFiles = extractedFiles.filter(f => f.isPE);
    if (peFiles.length > 0) {
      const pe = peFiles[0];
      if (pe) {
        const peDetails: string[] = [];
        peDetails.push(`It contains a PE32 executable`);
        if (pe.compileTimestamp) peDetails.push(`compiled ${pe.compileTimestamp.utc}`);
        if (pe.sha256) peDetails.push(`(SHA256: ${pe.sha256})`);
        if (pe.imphash) peDetails.push(`(Imphash: ${pe.imphash})`);
        parts.push(peDetails.join(' ') + '.');
        if (pe.imports && pe.imports.length > 0) {
          const notableImports = pe.imports.filter((i: string) => /WININET|WSOCK|CRYPT|ADVAPI|SHELL32/i.test(i));
          if (notableImports.length > 0) {
            parts.push(`Notable imports: ${notableImports.join(', ')}.`);
          }
        }
        if (pe.suspiciousStrings && pe.suspiciousStrings.length > 0) {
          parts.push(`${pe.suspiciousStrings.length} suspicious strings found in the executable.`);
        }
      }
    }
  }

  // VT detection
  const vtResult = submission.threatIntel.find(
    ti => ti.provider.includes('virustotal'),
  );
  if (vtResult && vtResult.detection_count > 0) {
    parts.push(
      `VirusTotal identifies it as ${vtResult.malware_family ? `"${vtResult.malware_family}"` : 'malicious'} with ${vtResult.detection_count}/${vtResult.total_engines} detection rate.`,
    );
  }

  // Packing / obfuscation
  const packingTechs = submission.attackTechniques.filter(
    t => t.techniqueId === 'T1027.002' || t.techniqueId === 'T1027',
  );
  if (packingTechs.length > 0) {
    const hasUPX = submission.attackTechniques.some(
      t => t.techniqueId === 'T1027.002',
    );
    if (hasUPX) {
      parts.push('The executable appears to be packed (UPX or similar), indicating obfuscation.');
    } else {
      parts.push('High entropy in the file suggests obfuscation or encryption.');
    }
  }

  // Ransom / encryption
  const ransomTech = submission.attackTechniques.find(
    t => t.techniqueId === 'T1486',
  );
  if (ransomTech) {
    parts.push('Ransomware-related indicators were detected, including encryption and ransom note strings.');
  }

  // Network indicators
  const networkIOCs = submission.iocs.filter(
    i => i.type === 'domain' || i.type === 'url' || i.type === 'ip',
  );
  if (networkIOCs.length > 0) {
    parts.push(`${networkIOCs.length} network indicators were extracted (IPs, domains, URLs).`);
  }

  // Signature status
  const sigMemActivity = parseMemActivity(submission.dynamicAnalysis ?? null);
  const sigExtractedFiles = (sigMemActivity?.['extractedFiles'] ?? []) as Array<Record<string, unknown>>;
  const sigPeFile = sigExtractedFiles.find(f => f['isPE'] === true);
  const sigData = sigPeFile?.['signature'] as Record<string, unknown> | undefined;
  if (sigData) {
    const hasCert = sigData['hasCertificate'] === true;
    const isValidVendor = sigData['isValidVendor'] === true;
    const isForged = sigData['isForged'] === true;
    if (isForged) {
      parts.push('The digital signature is forged or invalid.');
    } else if (hasCert && isValidVendor) {
      parts.push(`The binary carries a valid digital signature from "${String(sigData['signer'] ?? 'unknown')}".`);
    } else if (hasCert && !isValidVendor) {
      parts.push('The binary has a certificate from an unknown/untrusted CA.');
    } else {
      parts.push('The binary is unsigned.');
    }
  }

  // Version info from PE metadata
  const versionInfoForSummary = sigPeFile?.['versionInfo'] as Record<string, string> | undefined;
  if (versionInfoForSummary?.['ProductName'] && versionInfoForSummary?.['FileVersion']) {
    parts.push(`PE metadata identifies it as "${versionInfoForSummary['ProductName']}" version ${versionInfoForSummary['FileVersion']}.`);
  }

  // Vulnerability count
  const cveLookupEntry = submission.threatIntel.find(ti => ti.provider === 'cve-lookup');
  if (cveLookupEntry) {
    const vulnRaw = cveLookupEntry.raw_response as unknown as { cves?: Array<{ isKev?: boolean }> } | null;
    const cveCount = vulnRaw?.cves?.length ?? 0;
    const kevCount = vulnRaw?.cves?.filter(c => c.isKev).length ?? 0;
    if (cveCount > 0) {
      const kevNote = kevCount > 0 ? ` (${kevCount} actively exploited)` : '';
      parts.push(`${cveCount} known CVEs affect this software version${kevNote}.`);
    }
  }

  // Kill chain phases
  const tacticIds = [...new Set(submission.attackTechniques.map(t => t.tacticId))];
  const tacticNames = tacticIds
    .map(id => TACTIC_LABELS[id])
    .filter((name): name is string => name !== undefined);
  if (tacticNames.length > 0) {
    parts.push(`ATT&CK techniques span: ${tacticNames.join(', ')}.`);
  }

  return parts.join(' ');
}

// ── Section Components ──────────────────────────────────────────────────────

function ThreatIntelSection({ threatIntel }: { threatIntel: ThreatIntelEntry[] }) {
  if (threatIntel.length === 0) return null;

  // Find the best VT result
  const vtResult = threatIntel.find(
    ti => ti.provider.includes('virustotal') && ti.detection_count > 0,
  ) ?? threatIntel.find(ti => ti.provider.includes('virustotal'));

  // Find malware family from any provider
  const familyResult = threatIntel.find(ti => ti.malware_family);
  const malwareFamily = familyResult?.malware_family;

  // Alternative names from VT raw response
  const vtRaw = vtResult?.raw_response;
  const altNames = (vtRaw?.['names'] as string[] | undefined) ?? [];

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <SectionHeader icon={Shield} title="Threat Intelligence" />

      {/* VT Detection Ratio */}
      {vtResult && vtResult.total_engines > 0 && (
        <div className="mb-5">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-300">
              VirusTotal Detection
            </span>
            <span className={clsx(
              'text-sm font-bold',
              vtResult.detection_count > 0 ? 'text-red-400' : 'text-green-400',
            )}>
              {vtResult.detection_count}/{vtResult.total_engines} engines
            </span>
          </div>
          <div className="w-full h-3 bg-gray-800 rounded-full overflow-hidden">
            <div
              className={clsx(
                'h-full rounded-full transition-all',
                vtResult.detection_count / vtResult.total_engines > 0.5 ? 'bg-red-500'
                  : vtResult.detection_count / vtResult.total_engines > 0.2 ? 'bg-orange-500'
                  : vtResult.detection_count > 0 ? 'bg-yellow-500'
                  : 'bg-green-500',
              )}
              style={{ width: `${Math.round((vtResult.detection_count / vtResult.total_engines) * 100)}%` }}
            />
          </div>
        </div>
      )}

      {/* Malware Family */}
      {malwareFamily != null ? (
        <div className="mb-4 p-3 bg-red-900/20 border border-red-800/50 rounded-lg">
          <div className="text-xs text-red-400 uppercase tracking-wider mb-1">Malware Family</div>
          <div className="text-lg font-bold text-red-300">{malwareFamily}</div>
        </div>
      ) : null}

      {/* First/Last seen */}
      <div className="grid grid-cols-2 gap-4 mb-4">
        {vtResult?.first_seen != null ? (
          <div>
            <div className="text-xs text-gray-500 mb-1">First Seen</div>
            <div className="text-sm text-gray-300">
              {new Date(vtResult.first_seen).toLocaleDateString()}
            </div>
          </div>
        ) : null}
        {vtResult?.last_seen != null ? (
          <div>
            <div className="text-xs text-gray-500 mb-1">Last Seen</div>
            <div className="text-sm text-gray-300">
              {new Date(vtResult.last_seen).toLocaleDateString()}
            </div>
          </div>
        ) : null}
      </div>

      {/* Alternative Names */}
      {altNames.length > 0 ? (
        <div className="mb-4">
          <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Alternative Names</div>
          <div className="flex flex-wrap gap-1">
            {altNames.slice(0, 8).map((name, i) => (
              <span key={i} className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-400">
                {name}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {/* VT Report Link */}
      {typeof vtRaw?.['vtLink'] === 'string' && String(vtRaw['vtLink']).startsWith('https://www.virustotal.com/') && (
        <div className="mb-4">
          <a
            href={vtRaw['vtLink']}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-4 py-2 bg-scanboy-600/20 border border-scanboy-600/30 rounded-lg text-scanboy-400 hover:bg-scanboy-600/30 transition-colors text-sm"
          >
            <ExternalLink className="w-4 h-4" />
            View Full VirusTotal Report
          </a>
          {typeof vtRaw['hash'] === 'string' && (
            <div className="mt-2">
              <span className="text-xs text-gray-500">Analyzed hash: </span>
              <CopyableText text={vtRaw['hash']} className="text-xs text-gray-400 font-mono" />
            </div>
          )}
        </div>
      )}

      {/* Tags */}
      {Array.isArray(vtRaw?.['tags']) && (vtRaw['tags'] as string[]).length > 0 ? (
        <div className="mb-4">
          <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Tags</div>
          <div className="flex flex-wrap gap-1">
            {(vtRaw['tags'] as string[]).slice(0, 15).map((tag: string, i: number) => (
              <span key={i} className="text-xs px-2 py-0.5 rounded bg-red-900/20 text-red-400 border border-red-800/30">
                {tag}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {/* Detection Engines */}
      {Array.isArray(vtRaw?.['detectionEngines']) && (vtRaw['detectionEngines'] as Array<Record<string, string>>).length > 0 ? (
        <div className="mb-4">
          <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">
            Detection Engines ({(vtRaw['detectionEngines'] as Array<Record<string, string>>).length} hits)
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 max-h-48 overflow-y-auto">
            {(vtRaw['detectionEngines'] as Array<Record<string, string>>).map((det: Record<string, string>, i: number) => (
              <div key={i} className="flex items-center justify-between py-1 px-2 bg-gray-800/50 rounded text-xs">
                <span className="text-gray-300 truncate">{det['engine']}</span>
                <span className="text-red-400 truncate ml-2">{det['result']}</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {/* All Provider Results */}
      <div className="space-y-2 mt-4 pt-4 border-t border-gray-800">
        <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">All Providers</div>
        {threatIntel.map((intel, i) => (
          <div key={i} className="flex items-center justify-between py-1.5">
            <span className="text-sm text-gray-300">{intel.provider}</span>
            <span className={clsx(
              'text-xs px-2 py-0.5 rounded',
              intel.verdict === 'malicious' ? 'bg-red-900/30 text-red-400'
                : intel.verdict === 'clean' ? 'bg-green-900/30 text-green-400'
                : intel.verdict?.includes('vulnerable') ? 'bg-orange-900/30 text-orange-400'
                : intel.verdict === 'suspicious' ? 'bg-yellow-900/30 text-yellow-400'
                : 'bg-gray-800 text-gray-500',
            )}>
              {intel.verdict ?? 'unknown'} {intel.detection_count > 0 ? `(${intel.detection_count}/${intel.total_engines})` : ''}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function IOCsSection({ iocs }: { iocs: IOCEntry[] }) {
  if (iocs.length === 0) return null;

  // Group IOCs by type
  const grouped = new Map<string, IOCEntry[]>();
  for (const ioc of iocs) {
    const existing = grouped.get(ioc.type);
    if (existing) {
      existing.push(ioc);
    } else {
      grouped.set(ioc.type, [ioc]);
    }
  }

  // Sort by type order
  const sortedTypes = [...grouped.keys()].sort((a, b) => {
    const aConf = IOC_TYPE_CONFIG[a];
    const bConf = IOC_TYPE_CONFIG[b];
    return (aConf?.label ?? a).localeCompare(bConf?.label ?? b);
  });

  return (
    <CollapsibleSection
      icon={AlertTriangle}
      title="Indicators of Compromise"
      badge={iocs.length}
      defaultOpen
    >
      <div className="space-y-5">
        {sortedTypes.map(type => {
          const config = IOC_TYPE_CONFIG[type] ?? { label: type, icon: FileText, color: 'text-gray-400' };
          const TypeIcon = config.icon;
          const items = grouped.get(type) ?? [];

          return (
            <div key={type}>
              <div className="flex items-center gap-2 mb-2">
                <TypeIcon className={clsx('w-4 h-4', config.color)} />
                <span className="text-sm font-medium text-gray-300">
                  {config.label}
                </span>
                <span className="text-xs text-gray-600">({items.length})</span>
              </div>
              <div className="space-y-1 ml-6">
                {items.map((ioc, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between py-1.5 border-b border-gray-800/50 last:border-0 group"
                  >
                    <div className="flex-1 min-w-0">
                      <CopyableText
                        text={ioc.value}
                        className="text-sm text-gray-200 font-mono"
                      />
                      {ioc.context && (
                        <div className="text-xs text-gray-600 mt-0.5 truncate">
                          {ioc.context}
                        </div>
                      )}
                    </div>
                    <ConfidenceBar confidence={ioc.confidence} />
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </CollapsibleSection>
  );
}

function ATTACKSection({ techniques }: { techniques: AttackTechniqueEntry[] }) {
  if (techniques.length === 0) return null;

  // Group by tactic (kill chain phase)
  const grouped = new Map<string, AttackTechniqueEntry[]>();
  for (const tech of techniques) {
    const existing = grouped.get(tech.tacticId);
    if (existing) {
      existing.push(tech);
    } else {
      grouped.set(tech.tacticId, [tech]);
    }
  }

  // Sort tactics by kill chain order
  const sortedTactics = [...grouped.keys()].sort((a, b) => {
    const aIdx = TACTIC_DISPLAY_ORDER.indexOf(a);
    const bIdx = TACTIC_DISPLAY_ORDER.indexOf(b);
    return (aIdx === -1 ? 999 : aIdx) - (bIdx === -1 ? 999 : bIdx);
  });

  const getEvidenceDescription = (evidence: Record<string, unknown> | string | null): string => {
    if (!evidence) return '';
    if (typeof evidence === 'string') {
      try {
        const parsed = JSON.parse(evidence) as Record<string, unknown>;
        return String(parsed['description'] ?? parsed['evidence'] ?? evidence);
      } catch {
        return evidence;
      }
    }
    return String(evidence['description'] ?? evidence['evidence'] ?? '');
  };

  return (
    <CollapsibleSection
      icon={Target}
      title="MITRE ATT&CK Mapping"
      badge={techniques.length}
      defaultOpen
    >
      <div className="space-y-4">
        {sortedTactics.map(tacticId => {
          const tacticLabel = TACTIC_LABELS[tacticId] ?? tacticId;
          const techs = grouped.get(tacticId) ?? [];

          return (
            <div key={tacticId}>
              <div className="flex items-center gap-2 mb-2">
                <div className="w-2 h-2 rounded-full bg-scanboy-400" />
                <span className="text-sm font-semibold text-gray-200 uppercase tracking-wider">
                  {tacticLabel}
                </span>
              </div>
              <div className="ml-4 space-y-2">
                {techs.map((tech, i) => {
                  const techniqueName = TECHNIQUE_NAMES[tech.techniqueId] ?? '';
                  const evidenceDesc = getEvidenceDescription(tech.evidence);
                  const isMitreTechId = /^T\d{4}/.test(tech.techniqueId);

                  return (
                    <div
                      key={i}
                      className="p-3 bg-gray-800/50 rounded-lg border border-gray-800"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          {isMitreTechId ? (
                            <a
                              href={`https://attack.mitre.org/techniques/${tech.techniqueId.replace('.', '/')}/`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-sm font-mono text-scanboy-400 hover:text-scanboy-300 flex items-center gap-1"
                            >
                              {tech.techniqueId}
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          ) : (
                            <span className="text-sm font-mono text-gray-400">
                              {tech.techniqueId}
                            </span>
                          )}
                          {techniqueName && (
                            <span className="text-sm text-gray-300">
                              {techniqueName}
                            </span>
                          )}
                        </div>
                        <ConfidenceBar confidence={tech.confidence} />
                      </div>
                      {evidenceDesc && (
                        <p className="text-xs text-gray-500 mt-1">
                          {evidenceDesc}
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </CollapsibleSection>
  );
}

function DynamicAnalysisSection({ submission }: { submission: SubmissionDetail }) {
  const dynData = submission.dynamicAnalysis;
  if (!dynData) return null;

  const memActivity = dynData.memory_activity as Record<string, unknown> | null;
  const riskScore = typeof memActivity?.['riskScore'] === 'number' ? memActivity['riskScore'] as number : 0;

  // Process tree
  const processTree = memActivity?.['processActivity'] as Record<string, unknown> | null;
  const tree = processTree?.['tree'] as ProcessTree | null;
  const processes = (processTree?.['processes'] as ProcessInfoEntry[] | null) ?? (dynData.processes as unknown as ProcessInfoEntry[] | null);

  // File activity
  const fileActivity = memActivity?.['fileActivity'] as Record<string, unknown> | null;
  const filesCreated = (fileActivity?.['created'] as FileChangeEntry[] | null) ?? [];
  const filesModified = (fileActivity?.['modified'] as FileChangeEntry[] | null) ?? [];
  const filesDeleted = (fileActivity?.['deleted'] as FileChangeEntry[] | null) ?? [];

  // Network activity
  const netActivity = memActivity?.['networkActivity'] as Record<string, unknown> | null;
  const connections = (netActivity?.['connections'] as ConnectionEntry[] | null) ?? [];
  const dnsQueries = (netActivity?.['dnsQueries'] as DnsQueryEntry[] | null) ?? [];

  // Dropped files
  const droppedFiles = (memActivity?.['droppedFiles'] as DroppedFileEntry[] | null) ?? [];

  // Suspicious indicators
  const suspiciousIndicators = (memActivity?.['suspiciousIndicators'] as SuspiciousIndicatorEntry[] | null) ?? [];

  // Wine registry changes
  const wineRegChanges = memActivity?.['wineRegistryChanges'] as Record<string, unknown> | null;
  const sysRegChanges = (wineRegChanges?.['system'] as string[] | null) ?? [];
  const userRegChanges = (wineRegChanges?.['user'] as string[] | null) ?? [];

  // Duration
  const duration = dynData.duration_seconds;

  return (
    <CollapsibleSection icon={Activity} title="Dynamic Analysis" defaultOpen>
      {/* Behavioral Risk Score */}
      <div className="flex items-center justify-between mb-4 p-3 bg-gray-800/50 rounded-lg">
        <span className="text-sm text-gray-300">Behavioral Risk Score</span>
        <div className="flex items-center gap-3">
          <div className="w-32 h-2 bg-gray-800 rounded-full overflow-hidden">
            <div
              className={clsx(
                'h-full rounded-full',
                riskScore >= 70 ? 'bg-red-500' : riskScore >= 40 ? 'bg-orange-500' : riskScore >= 20 ? 'bg-yellow-500' : 'bg-green-500',
              )}
              style={{ width: `${Math.min(100, riskScore)}%` }}
            />
          </div>
          <span className={clsx(
            'text-sm font-bold',
            riskScore >= 70 ? 'text-red-400' : riskScore >= 40 ? 'text-orange-400' : riskScore >= 20 ? 'text-yellow-400' : 'text-green-400',
          )}>
            {riskScore}/100
          </span>
          {duration !== null && (
            <span className="text-xs text-gray-600 ml-2">
              {duration}s
            </span>
          )}
        </div>
      </div>

      {/* Process Tree */}
      {(tree ?? (processes && processes.length > 0)) && (
        <div className="mb-4">
          <h3 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-1">
            <Terminal className="w-4 h-4" />
            Process Tree
            {tree && <span className="text-xs text-gray-600">({tree.totalProcesses} processes, depth {tree.maxDepth})</span>}
          </h3>
          <div className="bg-gray-800/30 rounded-lg p-3 font-mono text-xs max-h-60 overflow-auto">
            {tree ? (
              <ProcessTreeView node={tree.root} depth={0} />
            ) : (
              processes?.slice(0, 20).map((proc, i) => (
                <div key={i} className="text-gray-400 py-0.5">
                  <span className="text-gray-600">[PID {proc.pid}]</span>{' '}
                  <span className="text-gray-300">{proc.name}</span>{' '}
                  <span className="text-gray-500">{proc.commandLine}</span>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* File Activity */}
      {(filesCreated.length > 0 || filesModified.length > 0 || filesDeleted.length > 0) && (
        <div className="mb-4">
          <h3 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-1">
            <FileText className="w-4 h-4" />
            File Activity
          </h3>
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-green-900/10 border border-green-900/30 rounded-lg p-2">
              <div className="text-xs text-green-400 mb-1">Created ({filesCreated.length})</div>
              <div className="max-h-24 overflow-auto">
                {filesCreated.slice(0, 10).map((f, i) => (
                  <div key={i} className="text-xs text-gray-400 truncate py-0.5" title={f.path}>
                    {f.path.split('/').pop()}
                  </div>
                ))}
              </div>
            </div>
            <div className="bg-yellow-900/10 border border-yellow-900/30 rounded-lg p-2">
              <div className="text-xs text-yellow-400 mb-1">Modified ({filesModified.length})</div>
              <div className="max-h-24 overflow-auto">
                {filesModified.slice(0, 10).map((f, i) => (
                  <div key={i} className="text-xs text-gray-400 truncate py-0.5" title={f.path}>
                    {f.path.split('/').pop()}
                  </div>
                ))}
              </div>
            </div>
            <div className="bg-red-900/10 border border-red-900/30 rounded-lg p-2">
              <div className="text-xs text-red-400 mb-1">Deleted ({filesDeleted.length})</div>
              <div className="max-h-24 overflow-auto">
                {filesDeleted.slice(0, 10).map((f, i) => (
                  <div key={i} className="text-xs text-gray-400 truncate py-0.5" title={f.path}>
                    {f.path.split('/').pop()}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Network Connections */}
      {(connections.length > 0 || dnsQueries.length > 0) && (
        <div className="mb-4">
          <h3 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-1">
            <Wifi className="w-4 h-4" />
            Network Activity
          </h3>
          {connections.length > 0 && (
            <div className="mb-2">
              <div className="text-xs text-gray-500 mb-1">Connections ({connections.length})</div>
              <div className="bg-gray-800/30 rounded-lg p-2 max-h-32 overflow-auto">
                {connections.slice(0, 15).map((conn, i) => (
                  <div key={i} className="text-xs text-gray-400 font-mono py-0.5">
                    <span className="text-gray-600">{conn.protocol.toUpperCase()}</span>{' '}
                    {conn.sourceAddress}:{conn.sourcePort} {'->'}{' '}
                    <span className="text-orange-400">{conn.destinationAddress}:{conn.destinationPort}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {dnsQueries.length > 0 && (
            <div>
              <div className="text-xs text-gray-500 mb-1">DNS Queries ({dnsQueries.length})</div>
              <div className="bg-gray-800/30 rounded-lg p-2 max-h-32 overflow-auto">
                {dnsQueries.slice(0, 15).map((dns, i) => (
                  <div key={i} className="text-xs text-gray-400 font-mono py-0.5">
                    <span className="text-blue-400">{dns.domain}</span>{' '}
                    <span className="text-gray-600">{dns.queryType}</span>
                    {dns.responseAddress && <span className="text-gray-500"> {'->'} {dns.responseAddress}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Registry Changes */}
      {(sysRegChanges.length > 0 || userRegChanges.length > 0) && (
        <div className="mb-4">
          <h3 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-1">
            <Key className="w-4 h-4" />
            Registry Changes ({sysRegChanges.length + userRegChanges.length})
          </h3>
          <div className="bg-gray-800/30 rounded-lg p-2 max-h-40 overflow-auto">
            {[...sysRegChanges, ...userRegChanges].slice(0, 20).map((change, i) => (
              <div key={i} className="text-xs text-gray-400 font-mono py-0.5 truncate" title={change}>
                {/Run|Startup/i.test(change) && <span className="text-red-400 mr-1">[!]</span>}
                {change}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Dropped Files */}
      {droppedFiles.length > 0 && (
        <div className="mb-4">
          <h3 className="text-sm font-medium text-gray-400 mb-2">
            Dropped Files ({droppedFiles.length})
          </h3>
          <div className="space-y-1 max-h-40 overflow-auto">
            {droppedFiles.slice(0, 15).map((file, i) => (
              <div key={i} className="flex items-center justify-between text-xs py-1 border-b border-gray-800/30 last:border-0">
                <div className="flex items-center gap-2 truncate">
                  {file.isSuspiciousLocation && (
                    <AlertTriangle className="w-3 h-3 text-red-400 flex-shrink-0" />
                  )}
                  <span className="text-gray-400 truncate font-mono" title={file.path}>
                    {file.path}
                  </span>
                </div>
                <span className="text-gray-600 flex-shrink-0 ml-2">
                  {file.size > 0 ? formatBytes(file.size) : ''}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Suspicious Indicators */}
      {suspiciousIndicators.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-1">
            <Bug className="w-4 h-4" />
            Suspicious Indicators ({suspiciousIndicators.length})
          </h3>
          <div className="space-y-1 max-h-48 overflow-auto">
            {suspiciousIndicators.map((ind, i) => {
              const severityColors: Record<string, string> = {
                critical: 'border-red-500/50 bg-red-900/10',
                high: 'border-orange-500/50 bg-orange-900/10',
                medium: 'border-yellow-500/50 bg-yellow-900/10',
                low: 'border-blue-500/50 bg-blue-900/10',
              };
              const severityTextColors: Record<string, string> = {
                critical: 'text-red-400',
                high: 'text-orange-400',
                medium: 'text-yellow-400',
                low: 'text-blue-400',
              };
              return (
                <div key={i} className={clsx('px-3 py-2 rounded border', severityColors[ind.severity] ?? 'border-gray-800')}>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-300">{ind.description}</span>
                    <span className={clsx('text-xs uppercase font-medium', severityTextColors[ind.severity] ?? 'text-gray-500')}>
                      {ind.severity}
                    </span>
                  </div>
                  {ind.evidence && (
                    <div className="text-xs text-gray-600 mt-0.5 truncate" title={ind.evidence}>
                      {ind.evidence}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </CollapsibleSection>
  );
}

function ProcessTreeView({ node, depth }: { node: ProcessTreeNode; depth: number }) {
  const indent = depth * 20;
  return (
    <div>
      <div className="py-0.5 flex items-center" style={{ paddingLeft: `${indent}px` }}>
        {depth > 0 && <span className="text-gray-700 mr-1">{'|--'}</span>}
        <span className="text-gray-600">[{node.pid}]</span>{' '}
        <span className="text-gray-300 ml-1">{node.name}</span>
        {node.commandLine && node.commandLine !== node.name && (
          <span className="text-gray-600 ml-2 truncate">{node.commandLine}</span>
        )}
      </div>
      {node.children?.map((child, i) => (
        <ProcessTreeView key={i} node={child} depth={depth + 1} />
      ))}
    </div>
  );
}

// ── Deep Analysis Section ──────────────────────────────────────────────────

/** Standard section names for PE binaries. Non-standard names are flagged. */
const STANDARD_PE_SECTIONS = new Set([
  '.text', '.rdata', '.data', '.bss', '.rsrc', '.reloc', '.idata', '.edata',
  '.pdata', '.tls', '.debug', '.CRT', '.sxdata', '.gfids', '.00cfg',
]);

function BoolBadge({ value, label }: { value: boolean; label: string }) {
  return (
    <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-gray-800/60">
      {value
        ? <ShieldCheck className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
        : <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />}
      <span className={clsx('text-xs font-medium', value ? 'text-green-300' : 'text-red-300')}>
        {label}
      </span>
    </div>
  );
}

function DeepAnalysisSubTab({
  label,
  active,
  onClick,
  badge,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  badge?: number;
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        'px-3 py-1.5 text-xs font-medium rounded-lg transition-colors',
        active
          ? 'bg-scanboy-600/30 text-scanboy-300 border border-scanboy-600/40'
          : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/50',
      )}
    >
      {label}
      {badge !== undefined && badge > 0 && (
        <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded-full bg-gray-700 text-gray-400">
          {badge}
        </span>
      )}
    </button>
  );
}

function DeepAnalysisBinaryHardening({ pe, elf }: { pe?: DeepAnalysisPe; elf?: DeepAnalysisElf }) {
  if (!pe && !elf) return null;

  return (
    <div className="space-y-4">
      {/* PE Mitigations */}
      {pe?.mitigations && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">Security Mitigations</h4>
          <div className="flex flex-wrap gap-2">
            <BoolBadge value={pe.mitigations.aslr ?? false} label="ASLR" />
            <BoolBadge value={pe.mitigations.dep ?? false} label="DEP" />
            <BoolBadge value={pe.mitigations.seh ?? false} label="SEH" />
            <BoolBadge value={pe.mitigations.cfg ?? false} label="CFG" />
          </div>
        </div>
      )}

      {/* ELF Hardening */}
      {elf && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">ELF Hardening</h4>
          <div className="flex flex-wrap gap-2">
            {elf.fullRelro !== undefined && <BoolBadge value={elf.fullRelro} label="Full RELRO" />}
            {elf.hasGnuHash !== undefined && <BoolBadge value={elf.hasGnuHash} label="GNU Hash" />}
          </div>
          <div className="grid grid-cols-2 gap-3 mt-3">
            {elf.compiler && (
              <div className="text-xs">
                <span className="text-gray-500">Compiler: </span>
                <span className="text-gray-300 font-mono">{elf.compiler}</span>
              </div>
            )}
            {elf.interpreter && (
              <div className="text-xs">
                <span className="text-gray-500">Interpreter: </span>
                <span className="text-gray-300 font-mono">{elf.interpreter}</span>
              </div>
            )}
            {elf.minGlibc && (
              <div className="text-xs">
                <span className="text-gray-500">Min glibc: </span>
                <span className="text-gray-300 font-mono">{elf.minGlibc}</span>
              </div>
            )}
            {elf.fortifyRatio !== undefined && (
              <div className="text-xs">
                <span className="text-gray-500">Fortify Ratio: </span>
                <span className={clsx(
                  'font-mono',
                  elf.fortifyRatio >= 0.7 ? 'text-green-400' : elf.fortifyRatio >= 0.4 ? 'text-yellow-400' : 'text-red-400',
                )}>
                  {(elf.fortifyRatio * 100).toFixed(0)}%
                </span>
              </div>
            )}
            {elf.buildId && (
              <div className="text-xs col-span-2">
                <span className="text-gray-500">Build ID: </span>
                <CopyableText text={elf.buildId} className="text-xs text-gray-400 font-mono" />
              </div>
            )}
          </div>
        </div>
      )}

      {/* Rich Header */}
      {pe?.richHeader && pe.richHeader.entries.length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">Rich Header (Build Tools)</h4>
          <div className="bg-gray-800/30 rounded-lg p-2 max-h-32 overflow-auto">
            {pe.richHeader.entries.map((entry, i) => (
              <div key={i} className="text-xs text-gray-400 font-mono py-0.5 flex items-center justify-between">
                <span className="text-gray-300">{entry.product}</span>
                <span className="text-gray-600">Build {entry.buildId} x{entry.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Manifest Privilege Level */}
      {pe?.manifest?.requestedLevel && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">Manifest</h4>
          <div className={clsx(
            'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium',
            pe.manifest.requestedLevel === 'requireAdministrator'
              ? 'bg-red-900/20 text-red-400 border border-red-800/40'
              : pe.manifest.requestedLevel === 'highestAvailable'
                ? 'bg-yellow-900/20 text-yellow-400 border border-yellow-800/40'
                : 'bg-gray-800 text-gray-400',
          )}>
            <Shield className="w-3 h-3" />
            Requested Level: {pe.manifest.requestedLevel}
          </div>
        </div>
      )}

      {/* .NET Version */}
      {pe?.dotnetVersion && (
        <div className="text-xs">
          <span className="text-gray-500">.NET Version: </span>
          <span className="text-gray-300 font-mono">{pe.dotnetVersion}</span>
        </div>
      )}

      {/* Resource Languages */}
      {pe?.resourceLanguages && pe.resourceLanguages.length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">Resource Languages</h4>
          <div className="flex flex-wrap gap-1.5">
            {pe.resourceLanguages.map((lang, i) => {
              const suspicious = /russian|chinese|arabic|farsi|persian|korean|north/i.test(lang);
              return (
                <span key={i} className={clsx(
                  'text-xs px-2 py-0.5 rounded',
                  suspicious
                    ? 'bg-orange-900/20 text-orange-400 border border-orange-800/40'
                    : 'bg-gray-800 text-gray-400',
                )}>
                  {suspicious && <AlertTriangle className="w-3 h-3 inline mr-1" />}
                  {lang}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {/* Misc PE metrics */}
      {pe && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {pe.checksumValid !== undefined && (
            <div className="bg-gray-800/40 rounded-lg p-2 text-center">
              <div className="text-xs text-gray-500 mb-1">Checksum</div>
              <span className={clsx('text-xs font-bold', pe.checksumValid ? 'text-green-400' : 'text-red-400')}>
                {pe.checksumValid ? 'Valid' : 'Invalid'}
              </span>
            </div>
          )}
          {pe.iatEntropy !== undefined && (
            <div className="bg-gray-800/40 rounded-lg p-2 text-center">
              <div className="text-xs text-gray-500 mb-1">IAT Entropy</div>
              <span className="text-xs text-gray-300 font-mono">{pe.iatEntropy.toFixed(2)}</span>
            </div>
          )}
          {pe.tlsDataSize !== undefined && pe.tlsDataSize > 0 && (
            <div className="bg-gray-800/40 rounded-lg p-2 text-center">
              <div className="text-xs text-gray-500 mb-1">TLS Data</div>
              <span className="text-xs text-gray-300 font-mono">{formatBytes(pe.tlsDataSize)}</span>
            </div>
          )}
          {pe.exportAnomalies !== undefined && pe.exportAnomalies > 0 && (
            <div className="bg-red-900/10 rounded-lg p-2 text-center border border-red-800/30">
              <div className="text-xs text-gray-500 mb-1">Export Anomalies</div>
              <span className="text-xs text-red-400 font-bold">{pe.exportAnomalies}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DeepAnalysisSectionTable({ pe }: { pe?: DeepAnalysisPe }) {
  if (!pe?.sectionRatios || pe.sectionRatios.length === 0) return null;

  return (
    <div>
      {pe.sectionAnomalyScore !== undefined && pe.sectionAnomalyScore > 0 && (
        <div className={clsx(
          'mb-3 px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-2',
          pe.sectionAnomalyScore >= 5 ? 'bg-red-900/20 text-red-400 border border-red-800/40'
            : pe.sectionAnomalyScore >= 3 ? 'bg-orange-900/20 text-orange-400 border border-orange-800/40'
            : 'bg-yellow-900/20 text-yellow-400 border border-yellow-800/40',
        )}>
          <AlertTriangle className="w-3.5 h-3.5" />
          Section Anomaly Score: {pe.sectionAnomalyScore}/10
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="text-left py-2 px-2 text-gray-500 font-medium">Section</th>
              <th className="text-right py-2 px-2 text-gray-500 font-medium">Virtual Size</th>
              <th className="text-right py-2 px-2 text-gray-500 font-medium">Raw Size</th>
              <th className="text-right py-2 px-2 text-gray-500 font-medium">Ratio</th>
            </tr>
          </thead>
          <tbody>
            {pe.sectionRatios.map((sec, i) => {
              const isAnomalousRatio = sec.ratio > 10;
              const isNonStandard = !STANDARD_PE_SECTIONS.has(sec.name);
              const rowColor = isAnomalousRatio ? 'bg-red-900/10' : isNonStandard ? 'bg-yellow-900/10' : '';
              return (
                <tr key={i} className={clsx('border-b border-gray-800/50', rowColor)}>
                  <td className="py-1.5 px-2">
                    <span className={clsx(
                      'font-mono',
                      isNonStandard ? 'text-yellow-400' : 'text-gray-300',
                    )}>
                      {sec.name}
                    </span>
                    {isNonStandard && (
                      <span className="ml-1.5 text-[10px] px-1 py-0.5 rounded bg-yellow-900/30 text-yellow-500">
                        non-standard
                      </span>
                    )}
                  </td>
                  <td className="text-right py-1.5 px-2 text-gray-400 font-mono">
                    {formatBytes(sec.virtualSize)}
                  </td>
                  <td className="text-right py-1.5 px-2 text-gray-400 font-mono">
                    {formatBytes(sec.rawSize)}
                  </td>
                  <td className={clsx(
                    'text-right py-1.5 px-2 font-mono',
                    isAnomalousRatio ? 'text-red-400 font-bold' : 'text-gray-400',
                  )}>
                    {sec.ratio.toFixed(1)}x
                    {isAnomalousRatio && (
                      <AlertTriangle className="w-3 h-3 inline ml-1 text-red-400" />
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DeepAnalysisFormatSection({ format }: { format?: DeepAnalysisFormat }) {
  if (!format) return null;

  const hasContent = format.isZipBomb || format.isPolyglot ||
    (format.embeddedFiles && format.embeddedFiles.length > 0) ||
    format.entropyHistogram ||
    (format.xorDecrypted && format.xorDecrypted.length > 0);

  if (!hasContent) return null;

  return (
    <div className="space-y-4">
      {/* Warnings */}
      {(format.isZipBomb || format.isPolyglot) && (
        <div className="space-y-2">
          {format.isZipBomb && (
            <div className="px-3 py-2 rounded-lg bg-red-900/20 border border-red-800/40 text-xs text-red-400 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span className="font-bold">ZIP Bomb Detected</span> -- File decompresses to an extreme ratio
            </div>
          )}
          {format.isPolyglot && (
            <div className="px-3 py-2 rounded-lg bg-orange-900/20 border border-orange-800/40 text-xs text-orange-400 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span className="font-bold">Polyglot File</span> -- Valid as multiple file formats
            </div>
          )}
        </div>
      )}

      {/* Embedded Files */}
      {format.embeddedFiles && format.embeddedFiles.length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">
            Embedded Files ({format.embeddedFiles.length})
          </h4>
          <div className="space-y-1">
            {format.embeddedFiles.map((ef, i) => (
              <div key={i} className="flex items-center justify-between text-xs py-1.5 px-2 bg-gray-800/40 rounded">
                <div className="flex items-center gap-2">
                  <Boxes className="w-3 h-3 text-gray-500" />
                  <span className="text-gray-300 font-medium">{ef.type}</span>
                </div>
                <div className="flex items-center gap-3 text-gray-500 font-mono">
                  <span>offset 0x{ef.offset.toString(16)}</span>
                  <span>{formatBytes(ef.size)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Entropy Distribution */}
      {format.entropyHistogram && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">Entropy Distribution</h4>
          <div className="flex items-center gap-3">
            <span className={clsx(
              'text-xs px-2 py-1 rounded font-medium',
              format.entropyHistogram.distribution === 'encrypted'
                ? 'bg-red-900/20 text-red-400 border border-red-800/40'
                : format.entropyHistogram.distribution === 'compressed'
                  ? 'bg-orange-900/20 text-orange-400 border border-orange-800/40'
                  : 'bg-gray-800 text-gray-400',
            )}>
              {format.entropyHistogram.distribution}
            </span>
            <span className="text-xs text-gray-500">
              Chi-squared: {format.entropyHistogram.chiSquaredUniform.toFixed(3)}
            </span>
          </div>
        </div>
      )}

      {/* XOR Decrypted Strings */}
      {format.xorDecrypted && format.xorDecrypted.length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">
            XOR Decrypted Strings ({format.xorDecrypted.length})
          </h4>
          <div className="bg-gray-800/30 rounded-lg p-2 max-h-40 overflow-auto space-y-1">
            {format.xorDecrypted.map((xor, i) => (
              <div key={i} className="flex items-center gap-2 text-xs py-1 border-b border-gray-800/50 last:border-0">
                <span className="text-gray-600 font-mono flex-shrink-0">key={xor.key}</span>
                <CopyableText text={xor.result} className="text-xs text-red-400 font-mono" />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/** Strings that indicate anti-debug behavior when found in /proc reads */
const ANTI_DEBUG_PROC_PATHS = new Set([
  '/proc/self/status',
  '/proc/self/maps',
  '/proc/self/exe',
  '/proc/self/cmdline',
]);

function DeepAnalysisRuntimeSection({ runtime }: { runtime?: DeepAnalysisRuntime }) {
  if (!runtime) return null;

  return (
    <div className="space-y-4">
      {/* Key Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {runtime.rwxTransitions !== undefined && (
          <div className={clsx(
            'rounded-lg p-2.5 text-center',
            runtime.rwxTransitions > 0
              ? 'bg-red-900/15 border border-red-800/40'
              : 'bg-gray-800/40',
          )}>
            <div className="text-xs text-gray-500 mb-1">RWX Transitions</div>
            <span className={clsx(
              'text-sm font-bold',
              runtime.rwxTransitions > 0 ? 'text-red-400' : 'text-green-400',
            )}>
              {runtime.rwxTransitions}
            </span>
          </div>
        )}
        {runtime.peakMemoryMb !== undefined && (
          <div className="bg-gray-800/40 rounded-lg p-2.5 text-center">
            <div className="text-xs text-gray-500 mb-1">Peak Memory</div>
            <span className="text-sm text-gray-300 font-mono">{runtime.peakMemoryMb} MB</span>
          </div>
        )}
        {runtime.threadCount !== undefined && (
          <div className="bg-gray-800/40 rounded-lg p-2.5 text-center">
            <div className="text-xs text-gray-500 mb-1">Threads</div>
            <span className="text-sm text-gray-300 font-mono">{runtime.threadCount}</span>
          </div>
        )}
        {runtime.masquerading !== undefined && (
          <div className={clsx(
            'rounded-lg p-2.5 text-center',
            runtime.masquerading
              ? 'bg-red-900/15 border border-red-800/40'
              : 'bg-gray-800/40',
          )}>
            <div className="text-xs text-gray-500 mb-1">Masquerading</div>
            <span className={clsx(
              'text-sm font-bold',
              runtime.masquerading ? 'text-red-400' : 'text-green-400',
            )}>
              {runtime.masquerading ? 'Detected' : 'None'}
            </span>
          </div>
        )}
      </div>

      {/* Tracer PID detection */}
      {runtime.tracerPidDetected && (
        <div className="px-3 py-2 rounded-lg bg-orange-900/20 border border-orange-800/40 text-xs text-orange-400 flex items-center gap-2">
          <Bug className="w-3.5 h-3.5 flex-shrink-0" />
          <span className="font-bold">Anti-Debug:</span> TracerPid check detected
        </div>
      )}

      {/* /proc reads */}
      {runtime.procReads && runtime.procReads.length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">
            /proc Reads ({runtime.procReads.length})
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {runtime.procReads.map((path, i) => {
              const isAntiDebug = ANTI_DEBUG_PROC_PATHS.has(path);
              return (
                <span key={i} className={clsx(
                  'text-xs px-2 py-0.5 rounded font-mono',
                  isAntiDebug
                    ? 'bg-orange-900/20 text-orange-400 border border-orange-800/40'
                    : 'bg-gray-800 text-gray-400',
                )}>
                  {isAntiDebug && <Bug className="w-3 h-3 inline mr-1" />}
                  {path}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {/* Directory Scans */}
      {runtime.directoryScans && runtime.directoryScans.length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">
            Directory Scans ({runtime.directoryScans.length})
          </h4>
          <div className="bg-gray-800/30 rounded-lg p-2 max-h-24 overflow-auto">
            {runtime.directoryScans.map((dir, i) => (
              <div key={i} className="text-xs text-gray-400 font-mono py-0.5">
                <Folder className="w-3 h-3 inline mr-1 text-gray-600" />
                {dir}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* DLL Load Order */}
      {runtime.dllLoadOrder && runtime.dllLoadOrder.length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">
            DLL Load Order ({runtime.dllLoadOrder.length})
          </h4>
          <div className="flex flex-wrap gap-1">
            {runtime.dllLoadOrder.map((dll, i) => (
              <span key={i} className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 font-mono">
                <span className="text-gray-600 mr-1">{i + 1}.</span>
                {dll}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Wine Exit Code */}
      {runtime.wineExitCode && (
        <div className="text-xs">
          <span className="text-gray-500">Wine Exit: </span>
          <span className={clsx(
            'font-mono font-medium',
            runtime.wineExitCode.includes('VIOLATION') || runtime.wineExitCode.includes('ERROR')
              ? 'text-red-400'
              : 'text-gray-300',
          )}>
            {runtime.wineExitCode}
          </span>
        </div>
      )}

      {/* New files in drive_c */}
      {runtime.driveC_newFiles && runtime.driveC_newFiles.length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">
            New Files in drive_c ({runtime.driveC_newFiles.length})
          </h4>
          <div className="bg-gray-800/30 rounded-lg p-2 max-h-32 overflow-auto">
            {runtime.driveC_newFiles.map((file, i) => (
              <div key={i} className="text-xs text-orange-400 font-mono py-0.5">
                {file}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function DeepAnalysisNetworkSection({ network }: { network?: DeepAnalysisNetwork }) {
  if (!network) return null;

  const hasContent = (network.synPackets && network.synPackets.length > 0) ||
    network.ja3Hash ||
    (network.sniDomains && network.sniDomains.length > 0) ||
    network.dnsQps !== undefined;

  if (!hasContent) return null;

  return (
    <div className="space-y-4">
      {/* SYN Packets */}
      {network.synPackets && network.synPackets.length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">
            SYN Packets ({network.synPackets.length})
          </h4>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left py-2 px-2 text-gray-500 font-medium">Destination IP</th>
                  <th className="text-right py-2 px-2 text-gray-500 font-medium">Port</th>
                </tr>
              </thead>
              <tbody>
                {network.synPackets.map((pkt, i) => (
                  <tr key={i} className="border-b border-gray-800/50">
                    <td className="py-1.5 px-2">
                      <CopyableText text={pkt.dstIp} className="text-xs text-orange-400 font-mono" />
                    </td>
                    <td className="text-right py-1.5 px-2 text-gray-300 font-mono">{pkt.dstPort}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* JA3 Hash */}
      {network.ja3Hash && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">JA3 Fingerprint</h4>
          <CopyableText text={network.ja3Hash} className="text-xs text-scanboy-400 font-mono" />
        </div>
      )}

      {/* SNI Domains */}
      {network.sniDomains && network.sniDomains.length > 0 && (
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">
            SNI Domains ({network.sniDomains.length})
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {network.sniDomains.map((domain, i) => (
              <span key={i} className="text-xs px-2 py-0.5 rounded bg-blue-900/20 text-blue-400 border border-blue-800/40 font-mono">
                {domain}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* DNS / ICMP / ARP stats */}
      <div className="grid grid-cols-3 gap-3">
        {network.dnsQps !== undefined && (
          <div className="bg-gray-800/40 rounded-lg p-2.5 text-center">
            <div className="text-xs text-gray-500 mb-1">DNS QPS</div>
            <span className="text-sm text-gray-300 font-mono">{network.dnsQps.toFixed(1)}</span>
          </div>
        )}
        {network.icmpDestinations !== undefined && (
          <div className="bg-gray-800/40 rounded-lg p-2.5 text-center">
            <div className="text-xs text-gray-500 mb-1">ICMP Dest.</div>
            <span className="text-sm text-gray-300 font-mono">{network.icmpDestinations}</span>
          </div>
        )}
        {network.arpRequests !== undefined && (
          <div className="bg-gray-800/40 rounded-lg p-2.5 text-center">
            <div className="text-xs text-gray-500 mb-1">ARP Requests</div>
            <span className="text-sm text-gray-300 font-mono">{network.arpRequests}</span>
          </div>
        )}
      </div>
    </div>
  );
}

/** Top-level tabs for deep analysis section */
type DeepAnalysisTab = 'hardening' | 'sections' | 'format' | 'runtime' | 'network';

function DeepAnalysisSection({ submission }: { submission: SubmissionDetail }) {
  const deepAnalysis = getDeepAnalysis(submission.dynamicAnalysis ?? null);
  const [activeTab, setActiveTab] = useState<DeepAnalysisTab>('hardening');

  if (!deepAnalysis) return null;

  const { pe, elf, format, runtime, network } = deepAnalysis;

  // Determine which tabs have data so we only show relevant ones
  const tabs: Array<{ id: DeepAnalysisTab; label: string; badge?: number; hasData: boolean }> = [
    {
      id: 'hardening',
      label: 'Binary Hardening',
      hasData: pe !== undefined || elf !== undefined,
    },
    {
      id: 'sections',
      label: 'Section Analysis',
      badge: pe?.sectionRatios?.length,
      hasData: (pe?.sectionRatios?.length ?? 0) > 0,
    },
    {
      id: 'format',
      label: 'Format Analysis',
      hasData: format !== undefined && (
        format.isZipBomb === true ||
        format.isPolyglot === true ||
        (format.embeddedFiles !== undefined && format.embeddedFiles.length > 0) ||
        format.entropyHistogram !== undefined ||
        (format.xorDecrypted !== undefined && format.xorDecrypted.length > 0)
      ),
    },
    {
      id: 'runtime',
      label: 'Runtime Behavior',
      hasData: runtime !== undefined,
    },
    {
      id: 'network',
      label: 'Network Intel',
      badge: network?.synPackets?.length,
      hasData: network !== undefined && (
        (network.synPackets !== undefined && network.synPackets.length > 0) ||
        network.ja3Hash !== undefined ||
        (network.sniDomains !== undefined && network.sniDomains.length > 0) ||
        network.dnsQps !== undefined
      ),
    },
  ];

  const visibleTabs = tabs.filter(t => t.hasData);
  if (visibleTabs.length === 0) return null;

  // If the current active tab has no data, fall back to the first visible tab
  const resolvedTab = visibleTabs.find(t => t.id === activeTab) ? activeTab : visibleTabs[0]?.id ?? 'hardening';

  const totalFindings = (pe?.sectionRatios?.length ?? 0) +
    (format?.embeddedFiles?.length ?? 0) +
    (format?.xorDecrypted?.length ?? 0) +
    (runtime?.procReads?.length ?? 0) +
    (network?.synPackets?.length ?? 0);

  return (
    <CollapsibleSection icon={Microscope} title="Deep Analysis" badge={totalFindings > 0 ? totalFindings : undefined}>
      {/* Tab Bar */}
      <div className="flex flex-wrap gap-1.5 mb-4 pb-3 border-b border-gray-800">
        {visibleTabs.map(tab => (
          <DeepAnalysisSubTab
            key={tab.id}
            label={tab.label}
            active={resolvedTab === tab.id}
            onClick={() => setActiveTab(tab.id)}
            badge={tab.badge}
          />
        ))}
      </div>

      {/* Tab Content */}
      {resolvedTab === 'hardening' && <DeepAnalysisBinaryHardening pe={pe} elf={elf} />}
      {resolvedTab === 'sections' && <DeepAnalysisSectionTable pe={pe} />}
      {resolvedTab === 'format' && <DeepAnalysisFormatSection format={format} />}
      {resolvedTab === 'runtime' && <DeepAnalysisRuntimeSection runtime={runtime} />}
      {resolvedTab === 'network' && <DeepAnalysisNetworkSection network={network} />}
    </CollapsibleSection>
  );
}

function ExtractedFilesSection({ submission }: { submission: SubmissionDetail }) {
  const memActivity = parseMemActivity(submission.dynamicAnalysis ?? null);
  const extractedFiles = memActivity?.['extractedFiles'] as ExtractedFileEntry[] | undefined;

  if (!extractedFiles || extractedFiles.length === 0) return null;

  return (
    <CollapsibleSection icon={FileSearch} title="Extracted File Analysis" badge={extractedFiles.length}>
      <div className="space-y-4">
        {extractedFiles.map((file, i) => (
          <div key={i} className="bg-gray-800/40 rounded-lg p-4 border border-gray-800">
            {file.error ? (
              <div className="text-sm text-red-400">Error analyzing {file.path}: {file.error}</div>
            ) : (
              <>
                {/* File Header */}
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <div className="text-sm font-medium text-white">
                      {file.path.split('/').pop()}
                    </div>
                    <div className="text-xs text-gray-500">
                      {file.fileType} | {formatBytes(file.size)}
                      {file.isPE && ' | PE32'}
                      {file.isELF && ' | ELF'}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={clsx(
                      'text-xs font-mono',
                      file.entropy > 7.5 ? 'text-red-400' : file.entropy > 7.0 ? 'text-orange-400' : 'text-gray-400',
                    )}>
                      Entropy: {file.entropy.toFixed(2)}
                    </div>
                    {file.compileTimestamp && (
                      <div className="text-xs text-gray-500">
                        Compiled: {file.compileTimestamp.utc}
                      </div>
                    )}
                  </div>
                </div>

                {/* Hashes */}
                <div className="grid grid-cols-1 gap-1 mb-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-500">SHA256</span>
                    <CopyableText text={file.sha256} className="text-xs text-gray-400 font-mono" />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-500">SHA1</span>
                    <CopyableText text={file.sha1} className="text-xs text-gray-400 font-mono" />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-500">MD5</span>
                    <CopyableText text={file.md5} className="text-xs text-gray-400 font-mono" />
                  </div>
                  {file.imphash && (
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-500">Imphash</span>
                      <CopyableText text={file.imphash} className="text-xs text-gray-400 font-mono" />
                    </div>
                  )}
                  {file.ssdeep && (
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-500">Fuzzy Hash</span>
                      <CopyableText text={file.ssdeep} className="text-xs text-gray-400 font-mono" />
                    </div>
                  )}
                </div>

                {/* Version Info & Metadata Warnings */}
                {file.versionInfo && (
                  <div className="mb-3">
                    <div className="text-xs text-gray-500 mb-1">Version Info</div>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
                      {Object.entries(file.versionInfo).map(([key, val]) => {
                        const cleaned = val ? String(val).replace(/[\x00-\x1F]/g, '').trim() : '';
                        if (!cleaned) return null;
                        return (
                          <div key={key} className="flex items-baseline gap-1">
                            <span className="text-xs text-gray-600">{key}:</span>
                            <span className="text-xs text-gray-400 truncate">{cleaned}</span>
                          </div>
                        );
                      })}
                    </div>
                    {file.signature && !file.signature.hasCertificate && (
                      <div className="mt-1 text-xs text-orange-400">No digital signature present</div>
                    )}
                  </div>
                )}

                {/* Kernel driver warning */}
                {file.isPE && /\(native\)/i.test(file.fileType) && (
                  <div className="mb-3 px-3 py-2 rounded border border-red-500/50 bg-red-900/10">
                    <span className="text-xs text-red-400 font-medium">Kernel-mode driver</span>
                    <span className="text-xs text-gray-500 ml-2">Cannot execute in sandbox (requires Windows kernel)</span>
                  </div>
                )}

                {/* PDB Path */}
                {file.pdbPaths && file.pdbPaths.length > 0 && (
                  <div className="mb-3">
                    <span className="text-xs text-gray-500">PDB Path:</span>
                    {file.pdbPaths.map((pdb, j) => (
                      <div key={j} className="text-xs text-yellow-400 font-mono ml-2">{pdb}</div>
                    ))}
                  </div>
                )}

                {/* PE Sections */}
                {file.sections && file.sections.length > 0 && (
                  <div className="mb-3">
                    <div className="text-xs text-gray-500 mb-1">PE Sections</div>
                    <div className="grid grid-cols-3 gap-1">
                      {file.sections.map((sec, j) => (
                        <div key={j} className={clsx(
                          'text-xs px-2 py-1 rounded',
                          sec.entropy > 7.0 ? 'bg-red-900/20 text-red-400'
                            : /UPX|packed/i.test(sec.name) ? 'bg-orange-900/20 text-orange-400'
                            : 'bg-gray-800 text-gray-400',
                        )}>
                          <span className="font-mono">{sec.name}</span>{' '}
                          <span className="text-gray-600">{formatBytes(sec.size)}</span>{' '}
                          <span className={sec.entropy > 7.0 ? 'text-red-400' : 'text-gray-500'}>
                            H:{sec.entropy.toFixed(1)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Imports */}
                {file.imports && file.imports.length > 0 && (
                  <div className="mb-3">
                    <div className="text-xs text-gray-500 mb-1">
                      Imports ({file.imports.length} DLLs)
                      {file.suspiciousImports && file.suspiciousImports.length > 0 && (
                        <span className="text-orange-400 ml-1">
                          ({file.suspiciousImports.length} suspicious)
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {file.imports.slice(0, 25).map((imp, j) => {
                        const isSuspicious = file.suspiciousImports?.includes(imp);
                        return (
                          <span key={j} className={clsx(
                            'text-xs px-1.5 py-0.5 rounded font-mono',
                            isSuspicious ? 'bg-orange-900/20 text-orange-400' : 'bg-gray-800 text-gray-500',
                          )}>
                            {imp}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Suspicious Strings */}
                {file.suspiciousStrings && file.suspiciousStrings.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-500 mb-1">
                      Suspicious Strings ({file.suspiciousStrings.length}
                      {file.totalStrings ? ` / ${file.totalStrings} total` : ''})
                    </div>
                    <div className="bg-gray-900/50 rounded p-2 max-h-32 overflow-auto">
                      {file.suspiciousStrings.slice(0, 30).map((s, j) => (
                        <div key={j} className="text-xs text-gray-400 font-mono py-0.5 truncate" title={s}>
                          {s}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        ))}
      </div>
    </CollapsibleSection>
  );
}

// ── File Metadata Panel ───────────────────────────────────────────────────────

/**
 * Strip null bytes and control characters from a string,
 * and return null if the result looks like garbage
 * (mostly non-printable or contains control chars).
 */
function cleanMetaValue(raw: string): string | null {
  // Strip null bytes, control chars (0x00-0x1F except tab/newline), and DEL
  const cleaned = raw.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim();
  if (!cleaned || cleaned.length < 2) return null;
  // Reject if more than 20% of characters are non-printable/non-ASCII
  const printable = cleaned.replace(/[^\x20-\x7E\xA0-\xFF]/g, '');
  if (printable.length < cleaned.length * 0.8) return null;
  // Reject values that look like parser garbage (starts with punctuation, contains field names)
  if (/^[,;|<>]/.test(cleaned)) return null;
  if (/ProductName|FileVersion|CompanyName|InternalName|LegalCopyright|OriginalFilename|FileDescription/.test(cleaned)) return null;
  return cleaned;
}

function FileMetadataPanel({ submission }: { submission: SubmissionDetail }) {
  const extractedFiles = getExtractedFiles(submission.dynamicAnalysis ?? null);
  const peFile = extractedFiles.find(f => f.isPE);
  if (!peFile) return null;

  const versionInfo = peFile.versionInfo;
  const compileTimestamp = peFile.compileTimestamp;
  const imphash = peFile.imphash;
  const signature = peFile.signature;

  if (!versionInfo && !compileTimestamp && !imphash && !signature) return null;

  // Build signature display
  const hasCert = signature?.hasCertificate === true;
  const signerName = signature?.signer ? cleanMetaValue(signature.signer) : null;
  const issuerName = signature?.issuer ? cleanMetaValue(signature.issuer) : null;

  const metaItems: Array<{ label: string; value: string }> = [];

  // Clean version info fields before displaying
  const versionFields: Array<{ key: string; label: string }> = [
    { key: 'ProductName', label: 'Product Name' },
    { key: 'FileVersion', label: 'Version' },
    { key: 'CompanyName', label: 'Company/Publisher' },
    { key: 'OriginalFilename', label: 'Original Filename' },
    { key: 'FileDescription', label: 'File Description' },
  ];
  for (const { key, label } of versionFields) {
    const raw = versionInfo?.[key];
    if (!raw) continue;
    const cleaned = cleanMetaValue(raw);
    if (cleaned) metaItems.push({ label, value: cleaned });
  }

  if (compileTimestamp) metaItems.push({ label: 'Compile Timestamp', value: compileTimestamp.utc });
  if (imphash) metaItems.push({ label: 'Imphash', value: imphash });
  metaItems.push({ label: 'File Size', value: formatBytes(peFile.size) });

  // Application Classification from CPE
  const cpeEntry = submission.threatIntel.find(ti => ti.provider === 'cpe-classification');
  const cpeData = cpeEntry?.raw_response as Record<string, unknown> | null;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <SectionHeader icon={Info} title="File Metadata" />

      {/* Application Classification */}
      {cpeData && (
        <div className="mb-4 pb-3 border-b border-gray-800">
          <div className="flex items-center gap-2 mb-2">
            <Package className="w-4 h-4 text-scanboy-400" />
            <span className="text-sm font-medium text-scanboy-400">Application Classification</span>
          </div>
          <div className="text-lg font-bold text-white mb-1">
            {String(cpeData['classification'] ?? 'Unknown')}
          </div>
          {!!cpeData['cpeUri'] && (
            <code className="text-xs text-gray-500 font-mono block truncate" title={String(cpeData['cpeUri'])}>
              {String(cpeData['cpeUri'])}
            </code>
          )}
        </div>
      )}

      {/* Digital Signature Status — shown prominently */}
      <div className="mb-4 pb-3 border-b border-gray-800">
        {hasCert && signerName ? (
          <>
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-4 h-4 text-green-400" />
              <span className="text-sm font-medium text-green-400">Signed by:</span>
              <span className="text-sm text-gray-200 font-medium">{signerName}</span>
            </div>
            {issuerName && (
              <div className="flex items-center gap-2 ml-6">
                <span className="text-xs text-gray-500">Certificate Authority:</span>
                <span className="text-xs text-gray-400">{issuerName}</span>
              </div>
            )}
          </>
        ) : hasCert ? (
          <>
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-4 h-4 text-yellow-400" />
              <span className="text-sm font-medium text-yellow-400">Signed</span>
              <span className="text-xs text-gray-500">(signer unknown)</span>
            </div>
            {issuerName && (
              <div className="flex items-center gap-2 ml-6">
                <span className="text-xs text-gray-500">Certificate Authority:</span>
                <span className="text-xs text-gray-400">{issuerName}</span>
              </div>
            )}
          </>
        ) : (
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-red-400" />
            <span className="text-sm font-medium text-red-400">Unsigned</span>
          </div>
        )}
      </div>

      {metaItems.length > 0 && (
        <div className="space-y-2">
          {metaItems.map((item, i) => (
            <div key={i} className="flex items-center justify-between py-1.5 border-b border-gray-800 last:border-0">
              <span className="text-sm text-gray-400">{item.label}</span>
              <span className="text-sm text-gray-200 font-mono truncate max-w-[220px]" title={item.value}>
                {item.value}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Vulnerability Section ─────────────────────────────────────────────────────

function VulnerabilitySection({ threatIntel }: { threatIntel: ThreatIntelEntry[] }) {
  const cveLookup = threatIntel.find(ti => ti.provider === 'cve-lookup');
  const rawData = cveLookup?.raw_response as unknown as VulnResultData | null;
  const peCves = rawData?.cves ?? [];
  const softwareName = rawData?.softwareName ?? '';
  const softwareVersion = rawData?.softwareVersion ?? '';

  // Also include SBOM container vulnerability results
  const sbomEntries = threatIntel.filter(ti => ti.provider === 'sbom-vuln');
  const sbomCves = sbomEntries.map(ti => {
    const r = ti.raw_response as Record<string, unknown> | null;
    return {
      id: String(r?.['cve'] ?? ''),
      severity: String(r?.['severity'] ?? 'low').toLowerCase(),
      cvssScore: Number(r?.['score'] ?? 0),
      epssScore: 0,
      isKev: Boolean(r?.['kev']),
      description: `${String(r?.['package'] ?? '')}@${String(r?.['version'] ?? '')}`,
      references: [] as string[],
      publishedDate: '',
      epssPercentile: 0,
    };
  });
  const cves = [...peCves, ...sbomCves];

  // Get CPE classification
  const cpeEntry = threatIntel.find(ti => ti.provider === 'cpe-classification');
  const cpeData = cpeEntry?.raw_response as Record<string, unknown> | null;

  const severityColors: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-600 text-white',
    medium: 'bg-yellow-600 text-black',
    low: 'bg-blue-600 text-white',
  };

  const severityBorderColors: Record<string, string> = {
    critical: 'border-red-700/50',
    high: 'border-orange-700/50',
    medium: 'border-yellow-700/50',
    low: 'border-blue-700/50',
  };

  return (
    <CollapsibleSection
      icon={ShieldAlert}
      title="Known Vulnerabilities"
      badge={cves.length}
      defaultOpen={cves.length > 0}
    >
      {/* CPE Classification */}
      {cpeData && (
        <div className="mb-4 p-3 bg-gray-800/50 rounded-lg">
          <div className="grid grid-cols-2 gap-3 text-sm">
            {!!cpeData['classification'] && (
              <div><span className="text-gray-500">Classification: </span><span className="text-white font-medium">{String(cpeData['classification'])}</span></div>
            )}
            {!!cpeData['cpeUri'] && (
              <div><span className="text-gray-500">CPE: </span><code className="text-xs text-scanboy-400 font-mono">{String(cpeData['cpeUri'])}</code></div>
            )}
            {!!cpeData['product'] && (
              <div><span className="text-gray-500">Product: </span><span className="text-gray-200">{String(cpeData['product'])}</span></div>
            )}
            {!!cpeData['confidence'] && (
              <div><span className="text-gray-500">Confidence: </span><span className="text-gray-200">{String(cpeData['confidence'])}%</span></div>
            )}
          </div>
        </div>
      )}

      {softwareName && (
        <div className="mb-4 text-sm text-gray-400">
          Scanned: <span className="text-gray-200 font-medium">{softwareName}</span>
          {softwareVersion && <span className="text-gray-500"> v{softwareVersion}</span>}
        </div>
      )}

      {cves.length === 0 ? (
        <div className="flex items-center gap-2 p-4 bg-green-900/10 border border-green-800/30 rounded-lg">
          <Check className="w-5 h-5 text-green-400" />
          <span className="text-sm text-green-300">No known vulnerabilities found{softwareName ? ` for ${softwareName}${softwareVersion ? ` v${softwareVersion}` : ''}` : ''}</span>
        </div>
      ) : (
        <div className="space-y-3">
          {cves.map((cve) => (
            <div
              key={cve.id}
              className={clsx(
                'p-4 bg-gray-800/40 rounded-lg border',
                severityBorderColors[cve.severity] ?? 'border-gray-800',
              )}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm font-mono text-scanboy-400 hover:text-scanboy-300 flex items-center gap-1"
                  >
                    {cve.id}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                  <span className={clsx(
                    'text-xs px-2 py-0.5 rounded font-bold uppercase',
                    severityColors[cve.severity] ?? 'bg-gray-700 text-gray-300',
                  )}>
                    CVSS {cve.cvssScore.toFixed(1)}
                  </span>
                  {cve.isKev && (
                    <span className="text-xs px-2 py-0.5 rounded bg-red-700 text-white font-bold animate-pulse">
                      EXPLOITED IN WILD
                    </span>
                  )}
                </div>
                {cve.epssScore > 0 && (
                  <span className="text-xs text-gray-400">
                    EPSS: {(cve.epssScore * 100).toFixed(1)}%
                  </span>
                )}
              </div>
              <p className="text-xs text-gray-400 leading-relaxed line-clamp-3">
                {cve.description}
              </p>
            </div>
          ))}
        </div>
      )}
    </CollapsibleSection>
  );
}

// ── Tech Debt / Version Check Section ─────────────────────────────────────────

function TechDebtSection({ threatIntel }: { threatIntel: ThreatIntelEntry[] }) {
  const techDebtEntry = threatIntel.find(ti => ti.provider === 'tech-debt');
  const data = techDebtEntry?.raw_response as unknown as TechDebtData | null;

  if (!data) {
    return (
      <CollapsibleSection icon={Package} title="Tech Debt / Version Status" badge={0} defaultOpen={false}>
        <div className="flex items-center gap-2 p-4 bg-gray-800/30 border border-gray-700/30 rounded-lg">
          <Info className="w-5 h-5 text-gray-500" />
          <span className="text-sm text-gray-400">Version data not available — feeds service may be initializing. Data refreshes daily.</span>
        </div>
      </CollapsibleSection>
    );
  }

  const { productName, installedVersion, latestVersion, majorsBehind, isEol, eolDate } = data;

  const statusColor = isEol ? 'text-red-400'
    : (majorsBehind ?? 0) >= 2 ? 'text-orange-400'
    : (majorsBehind ?? 0) === 1 ? 'text-yellow-400'
    : 'text-green-400';

  const statusBg = isEol ? 'bg-red-900/10 border-red-800/30'
    : (majorsBehind ?? 0) >= 2 ? 'bg-orange-900/10 border-orange-800/30'
    : (majorsBehind ?? 0) === 1 ? 'bg-yellow-900/10 border-yellow-800/30'
    : 'bg-green-900/10 border-green-800/30';

  const statusLabel = isEol ? 'END OF LIFE'
    : majorsBehind >= 2 ? `${majorsBehind} major versions behind`
    : majorsBehind === 1 ? '1 major version behind'
    : 'Up to date';

  return (
    <div className={clsx('p-4 rounded-lg border', statusBg)}>
      <div className="flex items-center gap-2 mb-2">
        <Package className="w-4 h-4 text-gray-400" />
        <span className="text-sm font-medium text-gray-300">{productName} Version Status</span>
      </div>
      <div className="flex items-center gap-3 text-sm">
        <span className="text-gray-400">
          Installed: <span className="text-gray-200 font-mono">{installedVersion}</span>
        </span>
        <span className="text-gray-600">|</span>
        <span className="text-gray-400">
          Latest: <span className="text-gray-200 font-mono">{latestVersion}</span>
        </span>
        <span className="text-gray-600">|</span>
        <span className={clsx('font-medium', statusColor)}>
          {statusLabel}
        </span>
      </div>
      {isEol && eolDate && (
        <p className="text-xs text-red-400 mt-1">
          End-of-life date: {eolDate}
        </p>
      )}
    </div>
  );
}

// ── Configuration Extraction Placeholder ──────────────────────────────────────

function ConfigExtractionSection({ submission }: { submission: SubmissionDetail }) {
  // Look for config_extraction indicators
  const configIndicators = submission.iocs.filter(ioc => ioc.type === 'config_extraction');

  // Also detect known families from threat intel or YARA
  const vtResult = submission.threatIntel.find(ti => ti.provider.includes('virustotal'));
  const malwareFamily = vtResult?.malware_family;
  const knownFamilies = ['Cobalt Strike', 'CobaltStrike', 'Emotet', 'TrickBot', 'QakBot', 'IcedID', 'BazarLoader', 'Dridex', 'AgentTesla'];
  const detectedFamily = knownFamilies.find(family =>
    malwareFamily?.toLowerCase().includes(family.toLowerCase()) ||
    configIndicators.some(ioc => ioc.value.toLowerCase().includes(family.toLowerCase())),
  );

  if (!detectedFamily && configIndicators.length === 0) return null;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <SectionHeader icon={Code} title="Configuration Extraction" />
      <div className="p-4 bg-yellow-900/10 border border-yellow-800/30 rounded-lg">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-yellow-300 font-medium mb-1">
              {detectedFamily ? `${detectedFamily} Family Detected` : 'Known Malware Family Detected'}
            </p>
            <p className="text-xs text-gray-400">
              This sample matches signatures for the <span className="text-yellow-400 font-medium">{detectedFamily ?? 'unknown'}</span> malware family.
              Configuration data may be embedded in the binary. Manual extraction and analysis is recommended
              using dedicated tools (e.g., CAPE sandbox, malduck, or family-specific config extractors).
            </p>
            {configIndicators.length > 0 && (
              <div className="mt-2 space-y-1">
                {configIndicators.map((ind, i) => (
                  <div key={i} className="text-xs text-gray-500 font-mono">
                    {ind.value}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main Page Component ─────────────────────────────────────────────────────

export function SubmissionDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [sigmaRules, setSigmaRules] = useState<string[] | null>(null);
  const [sigmaLoading, setSigmaLoading] = useState(false);
  const [sigmaCopied, setSigmaCopied] = useState(false);
  const [autoYaraRules, setAutoYaraRules] = useState<Array<{ name: string; rule: string; confidence: number }> | null>(null);
  const [yaraGenLoading, setYaraGenLoading] = useState(false);

  const { data: submission, isLoading } = useQuery<SubmissionDetail>({
    queryKey: ['submission', id],
    queryFn: async () => {
      const res = await api.get(`/submissions/${id}`);
      return res.data.data;
    },
  });

  const downloadWithAuth = useCallback(async (url: string, fallbackFilename: string) => {
    try {
      const res = await api.get(url, { responseType: 'blob' });
      const disposition = res.headers['content-disposition'] as string | undefined;
      const serverFilename = disposition?.match(/filename="([^"]+)"/)?.[1];
      const blob = new Blob([res.data as BlobPart]);
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = serverFilename ?? fallbackFilename;
      a.click();
      URL.revokeObjectURL(blobUrl);
    } catch { /* ignore */ }
  }, []);

  const handleDownloadReport = useCallback(() => {
    downloadWithAuth(`/reports/${id}/pdf`, `fraudvault-report-${id}.pdf`);
  }, [id, downloadWithAuth]);

  const handleDownloadPcap = useCallback(() => {
    downloadWithAuth(`/submissions/${id}/pcap`, `fraudvault-capture-${id}.pcap`);
  }, [id, downloadWithAuth]);

  const handleExportStix = useCallback(() => {
    downloadWithAuth(`/reports/${id}/export/stix`, `fraudvault-stix-${id}.json`);
  }, [id, downloadWithAuth]);

  const handleDownloadSbom = useCallback(async () => {
    try {
      const res = await api.get(`/submissions/${id}`);
      const sub = res.data?.data;
      const mem = sub?.dynamicAnalysis?.memory_activity;
      const sbom = mem?.containerSbom?.cyclonedx ?? mem?.containerSbom;
      if (sbom) {
        const fname = (sub?.fileName ?? sub?.filename ?? 'container').replace(/\.[^.]+$/, '');
        const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${fname}-sbom.cdx.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch { /* ignore */ }
  }, [id]);

  const handleGenerateSigma = useCallback(async () => {
    setSigmaLoading(true);
    try {
      const res = await api.get(`/analysis/${id}/detection-results`);
      const data = res.data?.data;
      if (data?.sigmaRules && Array.isArray(data.sigmaRules) && data.sigmaRules.length > 0) {
        setSigmaRules(data.sigmaRules.map((r: Record<string, unknown>) => String(r.yaml ?? r.content ?? r.rule ?? JSON.stringify(r, null, 2))));
      } else {
        setSigmaRules([]);
      }
    } catch {
      setSigmaRules([]);
    } finally {
      setSigmaLoading(false);
    }
  }, [id]);

  const handleGenerateYara = useCallback(async () => {
    setYaraGenLoading(true);
    try {
      const res = await api.get(`/analysis/${id}/detection-results`);
      const data = res.data?.data;
      if (data?.yaraRecommendations && Array.isArray(data.yaraRecommendations)) {
        setAutoYaraRules(data.yaraRecommendations.map((r: Record<string, unknown>) => ({
          name: String(r.ruleName ?? r.name ?? 'unnamed'),
          rule: String(r.ruleContent ?? r.rule ?? ''),
          confidence: Number(r.confidence ?? 0),
        })));
      } else {
        setAutoYaraRules([]);
      }
    } catch {
      setAutoYaraRules([]);
    } finally {
      setYaraGenLoading(false);
    }
  }, [id]);

  const handleCopySigma = useCallback(() => {
    if (sigmaRules) {
      navigator.clipboard.writeText(sigmaRules.join('\n---\n')).then(() => {
        setSigmaCopied(true);
        setTimeout(() => setSigmaCopied(false), 2000);
      }).catch(() => {});
    }
  }, [sigmaRules]);

  if (isLoading) {
    return (
      <div className="p-8 text-center text-gray-500">
        <Clock className="w-8 h-8 mx-auto mb-3 animate-spin" />
        Loading analysis...
      </div>
    );
  }

  if (!submission) {
    return (
      <div className="p-8 text-center text-gray-500">Submission not found</div>
    );
  }

  const summary = generateSummary(submission);

  return (
    <div className="p-4 md:p-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start justify-between gap-4 mb-6 md:mb-8">
        <div>
          <div className="flex items-center gap-2 text-sm text-gray-400 mb-2">
            <span>Submissions</span>
            <ChevronRight className="w-4 h-4" />
            <span className="text-gray-200">{submission.filename}</span>
          </div>
          <h1 className="text-2xl font-bold text-white">
            {submission.filename}
          </h1>
          <p className="text-gray-400 mt-1">
            {submission.fileType} &middot;{' '}
            {formatBytes(submission.fileSize)} &middot; Submitted{' '}
            {new Date(submission.createdAt).toLocaleString()}
          </p>
          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2 mt-4">
            <button
              onClick={handleDownloadReport}
              className="inline-flex items-center gap-2 px-3 py-1.5 bg-scanboy-600/20 border border-scanboy-600/30 rounded-lg text-scanboy-400 hover:bg-scanboy-600/30 transition-colors text-sm"
            >
              <Download className="w-4 h-4" />
              Download Report
            </button>
            <button
              onClick={handleDownloadPcap}
              className="inline-flex items-center gap-2 px-3 py-1.5 bg-blue-600/20 border border-blue-600/30 rounded-lg text-blue-400 hover:bg-blue-600/30 transition-colors text-sm"
            >
              <Wifi className="w-4 h-4" />
              Download PCAP
            </button>
            <button
              onClick={handleExportStix}
              className="inline-flex items-center gap-2 px-3 py-1.5 bg-purple-600/20 border border-purple-600/30 rounded-lg text-purple-400 hover:bg-purple-600/30 transition-colors text-sm"
            >
              <Shield className="w-4 h-4" />
              Export STIX
            </button>
            <button
              onClick={handleDownloadSbom}
              className="inline-flex items-center gap-2 px-3 py-1.5 bg-teal-600/20 border border-teal-600/30 rounded-lg text-teal-400 hover:bg-teal-600/30 transition-colors text-sm"
            >
              <Database className="w-4 h-4" />
              Download SBOM
            </button>
            <button
              onClick={handleGenerateSigma}
              disabled={sigmaLoading}
              className="inline-flex items-center gap-2 px-3 py-1.5 bg-orange-600/20 border border-orange-600/30 rounded-lg text-orange-400 hover:bg-orange-600/30 transition-colors text-sm disabled:opacity-50"
            >
              <Code className="w-4 h-4" />
              {sigmaLoading ? 'Generating...' : 'Generate Sigma Rules'}
            </button>
            <button
              onClick={handleGenerateYara}
              disabled={yaraGenLoading}
              className="inline-flex items-center gap-2 px-3 py-1.5 bg-scanboy-600/20 border border-scanboy-600/30 rounded-lg text-scanboy-400 hover:bg-scanboy-600/30 transition-colors text-sm disabled:opacity-50"
            >
              <Shield className="w-4 h-4" />
              {yaraGenLoading ? 'Generating...' : 'Generate YARA Rules'}
            </button>
          </div>
        </div>
        <div className="flex items-start gap-6">
          <ThreatScoreRing
            score={submission.threatScore}
            level={submission.threatLevel}
          />
          {(() => {
            const cveTi = submission.threatIntel.find(ti => ti.provider === 'cve-lookup');
            if (!cveTi) return null;
            const rawResp = cveTi.raw_response as unknown as { cves?: Array<{ isKev?: boolean; cvssScore?: number; epssScore?: number; epssPercentile?: number; id?: string }> } | null;
            const cves = rawResp?.cves ?? [];
            if (cves.length === 0) return null;
            const kevCves = cves.filter(c => c.isKev);
            const maxEpss = Math.max(0, ...cves.map(c => c.epssScore ?? 0));
            const maxCvss = Math.max(0, ...cves.map(c => c.cvssScore ?? 0));
            return (
              <div className="flex flex-col gap-1.5 text-sm">
                {kevCves.length > 0 && (
                  <span className="px-2.5 py-1 rounded-lg bg-red-900/30 text-red-400 border border-red-700/50 font-medium">
                    CISA KEV: {kevCves.length} actively exploited
                  </span>
                )}
                {maxCvss > 0 && (
                  <span className={clsx('px-2.5 py-1 rounded-lg border font-medium', maxCvss >= 9 ? 'bg-red-900/20 text-red-400 border-red-700/50' : maxCvss >= 7 ? 'bg-orange-900/20 text-orange-400 border-orange-700/50' : 'bg-yellow-900/20 text-yellow-400 border-yellow-700/50')}>
                    CVSS: {maxCvss.toFixed(1)}
                  </span>
                )}
                {maxEpss > 0 && (
                  <span className="px-2.5 py-1 rounded-lg bg-purple-900/20 text-purple-400 border border-purple-700/50 font-medium">
                    EPSS: {(maxEpss * 100).toFixed(1)}%
                  </span>
                )}
                <span className="text-gray-500">{cves.length} CVE{cves.length > 1 ? 's' : ''}</span>
              </div>
            );
          })()}
        </div>
      </div>

      {/* Digital Signature Banner — top of report, high visibility */}
      {(() => {
        const memActivity = parseMemActivity(submission.dynamicAnalysis ?? null);
        const extractedFiles = (memActivity?.['extractedFiles'] ?? []) as Array<Record<string, unknown>>;
        const peFile = extractedFiles.find(f => f['isPE'] === true);
        const sig = peFile?.['signature'] as Record<string, unknown> | undefined;
        if (!sig && !peFile) return null;

        const hasCert = sig?.['hasCertificate'] === true;
        const isValidVendor = sig?.['isValidVendor'] === true;
        const isForged = sig?.['isForged'] === true;
        const signer = sig?.['signer'] as string | undefined;
        const issuer = sig?.['issuer'] as string | undefined;

        // 4-state logic:
        // GREEN = valid signature from known CA
        // YELLOW = cert present but unknown issuer
        // RED = forged/invalid signature
        // GRAY = unsigned binary (no cert at all)
        type SigState = 'valid' | 'unknown-ca' | 'forged' | 'unsigned';
        const sigState: SigState = isForged ? 'forged'
          : hasCert && isValidVendor ? 'valid'
          : hasCert && !isValidVendor ? 'unknown-ca'
          : 'unsigned';

        const bannerStyles: Record<SigState, { bg: string; icon: string; text: string; badge: string; badgeBorder: string }> = {
          valid: { bg: 'bg-green-900/10 border-green-700/50', icon: 'bg-green-900/30', text: 'text-green-400', badge: 'bg-green-900/40 text-green-400', badgeBorder: 'border-green-700/50' },
          'unknown-ca': { bg: 'bg-yellow-900/10 border-yellow-700/50', icon: 'bg-yellow-900/30', text: 'text-yellow-400', badge: 'bg-yellow-900/40 text-yellow-400', badgeBorder: 'border-yellow-700/50' },
          forged: { bg: 'bg-red-900/10 border-red-700/50', icon: 'bg-red-900/30', text: 'text-red-400', badge: 'bg-red-900/40 text-red-400', badgeBorder: 'border-red-700/50' },
          unsigned: { bg: 'bg-gray-900/10 border-gray-700/50', icon: 'bg-gray-800/50', text: 'text-gray-400', badge: 'bg-gray-800 text-gray-400', badgeBorder: 'border-gray-700/50' },
        };
        const bannerLabels: Record<SigState, { title: string; badge: string }> = {
          valid: { title: 'Valid Digital Signature', badge: 'Trusted' },
          'unknown-ca': { title: 'Unknown Certificate Authority', badge: 'Unverified' },
          forged: { title: 'Invalid/Forged Signature', badge: 'Forged' },
          unsigned: { title: 'Unsigned Binary', badge: 'Unsigned' },
        };

        const styles = bannerStyles[sigState];
        const labels = bannerLabels[sigState];

        return (
          <div className={clsx('mb-6 rounded-xl p-5 border', styles.bg)}>
            <div className="flex items-start gap-4">
              <div className={clsx('p-2.5 rounded-lg', styles.icon)}>
                <Shield className={clsx('w-6 h-6', styles.text)} />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-1">
                  <h3 className={clsx('text-lg font-bold', styles.text)}>
                    {labels.title}
                  </h3>
                  <span className={clsx('text-xs px-2 py-0.5 rounded-full border', styles.badge, styles.badgeBorder)}>
                    {labels.badge}
                  </span>
                </div>
                {signer && (
                  <p className="text-sm text-gray-200">
                    <span className="text-gray-500">Signed by: </span>
                    <span className="font-medium">{signer}</span>
                  </p>
                )}
                {issuer && (
                  <p className="text-sm text-gray-300">
                    <span className="text-gray-500">Certificate Authority: </span>
                    <span className="font-medium">{issuer}</span>
                  </p>
                )}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Auto-Generated YARA Rules */}
      {autoYaraRules !== null && (
        <div className="mb-6 bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-scanboy-400" />
              <h2 className="text-lg font-semibold text-white">Auto-Generated YARA Rules</h2>
              <span className="text-xs px-2 py-0.5 rounded-full bg-gray-800 text-gray-400">
                {autoYaraRules.length}
              </span>
            </div>
            {autoYaraRules.length > 0 && (
              <button
                onClick={() => {
                  navigator.clipboard.writeText(autoYaraRules.map(r => r.rule).join('\n\n')).catch(() => {});
                }}
                className="inline-flex items-center gap-1 px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-300 hover:bg-gray-700 transition-colors text-sm"
              >
                <Copy className="w-3 h-3" />
                Copy All
              </button>
            )}
          </div>
          {autoYaraRules.length === 0 ? (
            <p className="text-sm text-gray-500">No YARA rules generated. Static analysis data may be required.</p>
          ) : (
            <div className="space-y-4">
              {autoYaraRules.map((r, i) => (
                <div key={i} className="bg-gray-800/50 rounded-lg overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-2 border-b border-gray-700/50">
                    <span className="text-sm font-mono text-scanboy-400">{r.name}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-scanboy-600/20 text-scanboy-400">
                      {r.confidence}% confidence
                    </span>
                  </div>
                  <pre className="text-xs text-gray-300 font-mono p-4 max-h-64 overflow-auto whitespace-pre">
                    {r.rule}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Sigma Rules Output */}
      {sigmaRules !== null && (
        <div className="mb-6 bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Code className="w-5 h-5 text-orange-400" />
              <h2 className="text-lg font-semibold text-white">Generated Sigma Rules</h2>
              <span className="text-xs px-2 py-0.5 rounded-full bg-gray-800 text-gray-400">
                {sigmaRules.length}
              </span>
            </div>
            {sigmaRules.length > 0 && (
              <button
                onClick={handleCopySigma}
                className="inline-flex items-center gap-1 px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-gray-300 hover:bg-gray-700 transition-colors text-sm"
              >
                {sigmaCopied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                {sigmaCopied ? 'Copied' : 'Copy All'}
              </button>
            )}
          </div>
          {sigmaRules.length === 0 ? (
            <p className="text-sm text-gray-500">No Sigma rules generated. Dynamic analysis data may be required.</p>
          ) : (
            <pre className="text-xs text-gray-300 font-mono bg-gray-800/50 rounded-lg p-4 max-h-96 overflow-auto whitespace-pre-wrap">
              {sigmaRules.join('\n---\n')}
            </pre>
          )}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Column */}
        <div className="lg:col-span-2 space-y-6">
          {/* Report Summary */}
          {summary && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
              <SectionHeader icon={FileText} title="Report Summary" />
              <p className="text-sm text-gray-300 leading-relaxed">
                {summary}
              </p>
            </div>
          )}

          {/* Threat Intelligence */}
          <ThreatIntelSection threatIntel={submission.threatIntel} />

          {/* Known Vulnerabilities */}
          <VulnerabilitySection threatIntel={submission.threatIntel} />

          {/* Tech Debt / Version Status */}
          <TechDebtSection threatIntel={submission.threatIntel} />

          {/* Configuration Extraction */}
          <ConfigExtractionSection submission={submission} />

          {/* IOCs */}
          <IOCsSection iocs={submission.iocs} />

          {/* MITRE ATT&CK */}
          <ATTACKSection techniques={submission.attackTechniques} />

          {/* Dynamic Analysis */}
          <DynamicAnalysisSection submission={submission} />

          {/* Deep Analysis */}
          <DeepAnalysisSection submission={submission} />

          {/* Extracted Files */}
          <ExtractedFilesSection submission={submission} />

          {/* Static Analysis */}
          {submission.staticAnalysis && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
              <SectionHeader icon={Eye} title="Static Analysis" />
              {(() => {
                const sa = submission.staticAnalysis;
                const md = (typeof sa.file_metadata === 'string' ? JSON.parse(sa.file_metadata) : sa.file_metadata) as Record<string, unknown> | null;
                const ent = (typeof sa.entropy_data === 'string' ? JSON.parse(sa.entropy_data) : sa.entropy_data) as Record<string, unknown> | null;
                const pe = (typeof sa.pe_analysis === 'string' ? JSON.parse(sa.pe_analysis) : sa.pe_analysis) as Record<string, unknown> | null;
                const strings = Array.isArray(sa.strings) ? sa.strings : (typeof sa.strings === 'string' ? JSON.parse(sa.strings) : []) as Array<Record<string, unknown>>;

                return (
                  <div className="space-y-4">
                    {md && (
                      <div className="grid grid-cols-2 gap-4">
                        {!!md['fileType'] && <div><span className="text-xs text-gray-500">File Type</span><p className="text-sm text-white">{String(md['fileType'])}</p></div>}
                        {!!md['magic'] && <div><span className="text-xs text-gray-500">Magic</span><p className="text-sm text-white">{String(md['magic'])}</p></div>}
                        {md['isPacked'] !== undefined && <div><span className="text-xs text-gray-500">Packed</span><p className={clsx('text-sm font-medium', md['isPacked'] ? 'text-red-400' : 'text-green-400')}>{md['isPacked'] ? 'Yes' + (md['packerName'] ? ` (${String(md['packerName'])})` : '') : 'No'}</p></div>}
                      </div>
                    )}
                    {ent && (
                      <div>
                        <span className="text-xs text-gray-500">Entropy</span>
                        <div className="flex items-center gap-3 mt-1">
                          <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                            <div className={clsx('h-full rounded-full', typeof ent['overallEntropy'] === 'number' && ent['overallEntropy'] > 7.5 ? 'bg-red-500' : ent['overallEntropy'] as number > 6.5 ? 'bg-yellow-500' : 'bg-green-500')} style={{ width: `${((typeof ent['overallEntropy'] === 'number' ? ent['overallEntropy'] : 0) / 8) * 100}%` }} />
                          </div>
                          <span className="text-sm text-gray-300">{typeof ent['overallEntropy'] === 'number' ? ent['overallEntropy'].toFixed(2) : '?'} / 8.0</span>
                        </div>
                      </div>
                    )}
                    {pe && !!pe['isPE'] && (
                      <div>
                        <span className="text-xs text-gray-500">PE Imports ({Array.isArray(pe['imports']) ? (pe['imports'] as string[]).length : 0})</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {(Array.isArray(pe['imports']) ? pe['imports'] as string[] : []).slice(0, 20).map((imp, i) => (
                            <span key={i} className={clsx('text-xs px-1.5 py-0.5 rounded', /WININET|WSOCK|CRYPT|ADVAPI|SHELL32/i.test(imp) ? 'bg-red-900/30 text-red-400' : 'bg-gray-800 text-gray-400')}>{imp}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {strings.length > 0 && (
                      <div>
                        <span className="text-xs text-gray-500">Strings ({strings.length} extracted)</span>
                        <div className="mt-1 max-h-32 overflow-y-auto text-xs font-mono text-gray-400 bg-gray-800/50 rounded p-2 space-y-0.5">
                          {strings.slice(0, 30).map((s, i) => <div key={i} className="truncate">{String(s['value'] ?? '')}</div>)}
                          {strings.length > 30 && <div className="text-gray-600">... and {strings.length - 30} more</div>}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {/* File Hashes */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <SectionHeader icon={Hash} title="File Hashes" />
            <HashRow label="MD5" value={submission.md5} />
            <HashRow label="SHA1" value={submission.sha1} />
            <HashRow label="SHA256" value={submission.sha256} />
            <HashRow label="SHA512" value={submission.sha512} />
            <HashRow label="TLSH" value={submission.tlsh} />
            <HashRow label="ssdeep" value={submission.ssdeep} />
          </div>

          {/* Analysis Jobs */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <SectionHeader icon={Cpu} title="Analysis Jobs" />
            <div className="space-y-3">
              {submission.jobs && submission.jobs.length > 0
                ? submission.jobs.map((job, i) => {
                    const statusColors: Record<string, string> = {
                      completed: 'bg-green-900/30 text-green-400',
                      running: 'bg-blue-900/30 text-blue-400',
                      failed: 'bg-red-900/30 text-red-400',
                      pending: 'bg-gray-800 text-gray-500',
                    };
                    return (
                      <div key={i} className="flex items-center justify-between">
                        <span className="text-sm text-gray-300">
                          {job.jobType.replace(/_/g, ' ')}
                        </span>
                        <span className={`text-xs px-2 py-0.5 rounded ${statusColors[job.status] ?? 'bg-gray-800 text-gray-500'}`}>
                          {job.status}
                        </span>
                      </div>
                    );
                  })
                : ['static', 'dynamic', 'threat_intel', 'yara', 'network'].map(
                    (jobType) => (
                      <div key={jobType} className="flex items-center justify-between">
                        <span className="text-sm text-gray-300">
                          {jobType.replace(/_/g, ' ')}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded bg-yellow-900/30 text-yellow-400">
                          queued
                        </span>
                      </div>
                    ),
                  )}
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* File Metadata Panel */}
          <FileMetadataPanel submission={submission} />

          {/* Notes */}
          {submission.notes && submission.notes.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
              <SectionHeader icon={FileText} title="Analyst Notes" />
              <div className="space-y-3">
                {submission.notes.map((note) => (
                  <div key={note.id} className="p-3 bg-gray-800 rounded-lg">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium text-gray-300">{note.username}</span>
                      <span className="text-xs text-gray-600">
                        {new Date(note.createdAt).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-sm text-gray-400">{note.content}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
