// ── Enums ────────────────────────────────────────────────────────────────────

export enum UserRole {
  Viewer = 'viewer',
  Analyst = 'analyst',
  Admin = 'admin',
  SuperAdmin = 'super_admin',
}

export enum ThreatLevel {
  Informational = 'informational',
  Low = 'low',
  Medium = 'medium',
  High = 'high',
  Critical = 'critical',
}

export enum SubmissionStatus {
  Pending = 'pending',
  Queued = 'queued',
  Processing = 'processing',
  StaticAnalysis = 'static_analysis',
  DynamicAnalysis = 'dynamic_analysis',
  DetectionEngineRunning = 'detection_engine_running',
  Scoring = 'scoring',
  Completed = 'completed',
  Failed = 'failed',
  Cancelled = 'cancelled',
}

export enum JobType {
  HashLookup = 'hash_lookup',
  ThreatIntel = 'threat_intel',
  StaticAnalysis = 'static_analysis',
  YaraScan = 'yara_scan',
  DynamicAnalysis = 'dynamic_analysis',
  Detection = 'detection',
  Scoring = 'scoring',
  ReportGeneration = 'report_generation',
}

export enum JobStatus {
  Queued = 'queued',
  Running = 'running',
  Completed = 'completed',
  Failed = 'failed',
  TimedOut = 'timed_out',
  Cancelled = 'cancelled',
}

export enum IOCType {
  IPv4 = 'ip',
  IPv6 = 'ipv6',
  Domain = 'domain',
  URL = 'url',
  Email = 'email',
  FileHash = 'file_hash',
  Mutex = 'mutex',
  RegistryKey = 'registry_key',
  FilePath = 'file_path',
  Certificate = 'certificate',
}

export enum SandboxStatus {
  Available = 'available',
  Provisioning = 'provisioning',
  Running = 'running',
  Snapshotting = 'snapshotting',
  Cleaning = 'cleaning',
  Error = 'error',
  Offline = 'offline',
}

export enum InternetMode {
  Disabled = 'disabled',
  Simulated = 'simulated',
  Monitored = 'monitored',
}

// ── Core Entities ────────────────────────────────────────────────────────────

export interface User {
  id: string;
  email: string;
  displayName: string;
  role: UserRole;
  status: string;
  mfaEnabled: boolean;
  lastLoginAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Submission {
  id: string;
  userId: string;
  fileName: string;
  fileSize: number;
  mimeType: string;
  md5: string;
  sha1: string;
  sha256: string;
  ssdeep: string | null;
  status: SubmissionStatus;
  threatLevel: ThreatLevel | null;
  threatScore: number | null;
  storagePath: string;
  tags: string[];
  submittedAt: string;
  completedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AnalysisJob {
  id: string;
  submissionId: string;
  jobType: JobType;
  status: JobStatus;
  priority: number;
  attempt: number;
  maxAttempts: number;
  result: Record<string, unknown> | null;
  errorMessage: string | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface IOC {
  id: string;
  submissionId: string;
  type: IOCType;
  value: string;
  context: string | null;
  confidence: number;
  source: string;
  firstSeenAt: string;
  createdAt: string;
}

export interface ATTACKTechnique {
  id: string;
  techniqueId: string;
  name: string;
  tactic: string;
  description: string;
  dataSource: string;
  confidence: number;
}

export interface YaraRule {
  id: string;
  name: string;
  description: string;
  category: string;
  source: string;
  ruleContent: string;
  isEnabled: boolean;
  lastMatchedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface SandboxEnvironment {
  id: string;
  name: string;
  os: string;
  osVersion: string;
  architecture: string;
  status: SandboxStatus;
  baseSnapshotId: string;
  internetMode: InternetMode;
  maxExecutionSeconds: number;
  createdAt: string;
  updatedAt: string;
}

export interface DetonationSession {
  id: string;
  submissionId: string;
  sandboxId: string;
  internetMode: InternetMode;
  durationSeconds: number;
  screenshotPaths: string[];
  pcapPath: string | null;
  memoryDumpPath: string | null;
  filesystemDiffPath: string | null;
  registryDiffPath: string | null;
  processTreePath: string | null;
  startedAt: string;
  completedAt: string | null;
  createdAt: string;
}

// ── Analysis Results ─────────────────────────────────────────────────────────

export interface ThreatIntelResult {
  submissionId: string;
  source: string;
  knownMalware: boolean;
  malwareFamily: string | null;
  firstSeenAt: string | null;
  detectionRatio: string | null;
  communityScore: number | null;
  tags: string[];
  rawResponse: Record<string, unknown>;
  queriedAt: string;
  detectionCount?: number | null;
  totalEngines?: number | null;
}

export interface StaticAnalysisResult {
  submissionId: string;
  fileType: string;
  magic: string;
  entropy: number;
  isPacked: boolean;
  packerName: string | null;
  imports: string[];
  exports: string[];
  sections: SectionInfo[];
  strings: ExtractedString[];
  certificates: CertificateInfo[];
  iocs: IOC[];
  attackTechniques: ATTACKTechnique[];
}

export interface SectionInfo {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number;
  md5: string;
}

export interface ExtractedString {
  value: string;
  encoding: 'ascii' | 'utf16';
  offset: number;
  category: string | null;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  serial: string;
  validFrom: string;
  validTo: string;
  isValid: boolean;
}

export interface DynamicAnalysisResult {
  submissionId: string;
  detonationSessionId: string;
  processesCreated: ProcessInfo[];
  networkConnections: NetworkConnection[];
  filesModified: FileModification[];
  registryModifications: RegistryModification[];
  mutexesCreated: string[];
  iocs: IOC[];
  attackTechniques: ATTACKTechnique[];
  behaviorTags: string[];
}

export interface ProcessInfo {
  pid: number;
  parentPid: number;
  name: string;
  commandLine: string;
  createdAt: string;
}

export interface NetworkConnection {
  protocol: 'tcp' | 'udp' | 'dns' | 'http' | 'https' | 'tls';
  sourceAddress: string;
  sourcePort: number;
  destinationAddress: string;
  destinationPort: number;
  domain: string | null;
  bytesSent: number;
  bytesReceived: number;
}

export interface FileModification {
  path: string;
  operation: 'create' | 'modify' | 'delete' | 'rename';
  newPath: string | null;
  sha256: string | null;
}

export interface RegistryModification {
  key: string;
  valueName: string | null;
  operation: 'create' | 'modify' | 'delete';
  valueData: string | null;
}

export interface AnalysisReport {
  id: string;
  submissionId: string;
  submission: Submission;
  threatLevel: ThreatLevel;
  threatScore: number;
  summary: string;
  staticAnalysis: StaticAnalysisResult | null;
  dynamicAnalysis: DynamicAnalysisResult | null;
  threatIntel: ThreatIntelResult[];
  yaraMatches: YaraMatch[];
  iocs: IOC[];
  attackTechniques: ATTACKTechnique[];
  generatedAt: string;
}

export interface YaraMatch {
  ruleId: string;
  ruleName: string;
  category: string;
  matchedStrings: string[];
}

// ── API Types ────────────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

export interface ApiResponse<T> {
  success: boolean;
  data: T | null;
  error: ApiError | null;
  requestId: string;
  timestamp: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}
