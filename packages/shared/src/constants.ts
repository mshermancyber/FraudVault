import { ThreatLevel } from './types/index.js';

/** File types accepted for submission. */
export const SUPPORTED_FILE_TYPES: ReadonlySet<string> = new Set([
  // Executables
  'application/x-dosexec',
  'application/x-executable',
  'application/x-elf',
  'application/x-mach-binary',
  'application/vnd.microsoft.portable-executable',
  // Scripts
  'application/javascript',
  'application/x-python-code',
  'application/x-powershell',
  'application/x-sh',
  'application/x-bat',
  'text/x-python',
  'text/x-shellscript',
  // Documents
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/rtf',
  // Archives
  'application/zip',
  'application/x-rar-compressed',
  'application/x-7z-compressed',
  'application/gzip',
  'application/x-tar',
  // Disk images / installers
  'application/x-iso9660-image',
  'application/x-msi',
  // Other
  'application/java-archive',
  'application/x-java-applet',
  'application/vnd.android.package-archive',
  'application/x-dex',
  'application/octet-stream',
]);

/** File extension allow-list (lowercase, with leading dot). */
export const SUPPORTED_FILE_EXTENSIONS: ReadonlySet<string> = new Set([
  '.exe', '.dll', '.sys', '.scr', '.cpl', '.drv',
  '.elf', '.so', '.dylib', '.mach',
  '.js', '.vbs', '.ps1', '.bat', '.cmd', '.sh', '.py',
  '.pdf', '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm',
  '.ppt', '.pptx', '.pptm', '.rtf',
  '.zip', '.rar', '.7z', '.gz', '.tar', '.bz2',
  '.iso', '.img', '.msi',
  '.jar', '.class', '.apk', '.dex',
  '.lnk', '.hta', '.wsf',
]);

/** Maximum file size in bytes (default 256 MB). */
export const MAX_FILE_SIZE_BYTES = 256 * 1024 * 1024;

/** Maximum file size for free-tier users (50 MB). */
export const MAX_FILE_SIZE_FREE_BYTES = 50 * 1024 * 1024;

/** Threat-score thresholds mapping numeric scores to threat levels. */
export const THREAT_SCORE_THRESHOLDS: ReadonlyArray<{
  readonly min: number;
  readonly max: number;
  readonly level: ThreatLevel;
}> = [
  { min: 0, max: 9, level: ThreatLevel.Informational },
  { min: 10, max: 39, level: ThreatLevel.Low },
  { min: 40, max: 69, level: ThreatLevel.Medium },
  { min: 70, max: 89, level: ThreatLevel.High },
  { min: 90, max: 100, level: ThreatLevel.Critical },
] as const;

/** Default analysis timeout in seconds. */
export const DEFAULT_ANALYSIS_TIMEOUT_SECONDS = 300;

/** Maximum number of concurrent detonation sessions. */
export const DEFAULT_MAX_CONCURRENT_DETONATIONS = 4;

/** Pagination defaults. */
export const DEFAULT_PAGE_SIZE = 25;
export const MAX_PAGE_SIZE = 100;

/** Maximum number of tags per submission. */
export const MAX_TAGS_PER_SUBMISSION = 20;

/** Maximum YARA rule size in bytes. */
export const MAX_YARA_RULE_SIZE_BYTES = 1024 * 1024;

/** Queue names used across the platform. */
export const QUEUE_NAMES = {
  ANALYSIS: 'analysis',
  STATIC_ANALYSIS: 'static-analysis',
  DYNAMIC_ANALYSIS: 'dynamic-analysis',
  THREAT_INTEL: 'threat-intel',
  DETECTION: 'detection',
  REPORTING: 'reporting',
} as const;

/** Redis key prefixes. */
export const REDIS_KEY_PREFIXES = {
  SESSION: 'session:',
  RATE_LIMIT: 'rl:',
  JOB_LOCK: 'lock:job:',
  CACHE_HASH: 'cache:hash:',
  CACHE_INTEL: 'cache:intel:',
} as const;

/**
 * Returns the ThreatLevel for a given numeric score (0-100).
 */
export function threatLevelFromScore(score: number): ThreatLevel {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const match = THREAT_SCORE_THRESHOLDS.find(
    (t) => clamped >= t.min && clamped <= t.max,
  );
  return match?.level ?? ThreatLevel.Informational;
}
