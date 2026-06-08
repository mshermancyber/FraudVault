// ── Execution strategies per file type ───────────────────────────────────────

/**
 * Describes how to execute a specific file type inside a sandbox.
 */
export interface ExecutionStrategy {
  /** Human-readable label for this strategy. */
  readonly label: string;
  /** The command to run inside the guest, with `{FILE}` as a placeholder. */
  readonly command: string;
  /** Working directory inside the guest (null = use file's directory). */
  readonly workingDir: string | null;
  /** Environment variables to set before execution. */
  readonly env: Readonly<Record<string, string>>;
  /** Timeout override in seconds (null = use default detonation duration). */
  readonly timeoutSeconds: number | null;
  /** Whether this strategy requires a GUI display. */
  readonly requiresGui: boolean;
}

// ── File type mapping ───────────────────────────────────────────────────────

type FileCategory =
  | 'windows_exe'
  | 'windows_dll'
  | 'windows_msi'
  | 'powershell'
  | 'python'
  | 'javascript'
  | 'vbscript'
  | 'office_document'
  | 'pdf'
  | 'url'
  | 'bat_cmd'
  | 'elf_binary'
  | 'shell_script'
  | 'jar'
  | 'hta'
  | 'unknown';

/**
 * Map of MIME types to file categories.
 */
const MIME_CATEGORY_MAP: ReadonlyMap<string, FileCategory> = new Map([
  ['application/x-dosexec', 'windows_exe'],
  ['application/x-msdos-program', 'windows_exe'],
  ['application/x-msdownload', 'windows_exe'],
  ['application/vnd.microsoft.portable-executable', 'windows_exe'],
  ['application/x-msi', 'windows_msi'],
  ['application/x-ole-storage', 'office_document'],
  ['application/msword', 'office_document'],
  ['application/vnd.ms-excel', 'office_document'],
  ['application/vnd.ms-powerpoint', 'office_document'],
  ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'office_document'],
  ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'office_document'],
  ['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'office_document'],
  ['application/pdf', 'pdf'],
  ['application/x-python-code', 'python'],
  ['text/x-python', 'python'],
  ['application/javascript', 'javascript'],
  ['text/javascript', 'javascript'],
  ['application/x-executable', 'elf_binary'],
  ['application/x-elf', 'elf_binary'],
  ['application/x-sharedlib', 'elf_binary'],
  ['application/java-archive', 'jar'],
  ['application/x-hta', 'hta'],
]);

/**
 * Map of file extensions to categories (fallback when MIME is ambiguous).
 */
const EXTENSION_CATEGORY_MAP: ReadonlyMap<string, FileCategory> = new Map([
  ['.exe', 'windows_exe'],
  ['.dll', 'windows_dll'],
  ['.msi', 'windows_msi'],
  ['.ps1', 'powershell'],
  ['.psm1', 'powershell'],
  ['.psd1', 'powershell'],
  ['.py', 'python'],
  ['.pyw', 'python'],
  ['.js', 'javascript'],
  ['.jse', 'javascript'],
  ['.vbs', 'vbscript'],
  ['.vbe', 'vbscript'],
  ['.wsf', 'javascript'],
  ['.doc', 'office_document'],
  ['.docx', 'office_document'],
  ['.docm', 'office_document'],
  ['.xls', 'office_document'],
  ['.xlsx', 'office_document'],
  ['.xlsm', 'office_document'],
  ['.ppt', 'office_document'],
  ['.pptx', 'office_document'],
  ['.pptm', 'office_document'],
  ['.pdf', 'pdf'],
  ['.bat', 'bat_cmd'],
  ['.cmd', 'bat_cmd'],
  ['.sh', 'shell_script'],
  ['.jar', 'jar'],
  ['.hta', 'hta'],
  ['.url', 'url'],
  ['.lnk', 'windows_exe'], // Shortcut files treated as executables
]);

// ── Execution strategies per category ───────────────────────────────────────

const STRATEGIES: Readonly<Record<FileCategory, ExecutionStrategy>> = {
  windows_exe: {
    label: 'Windows Executable',
    command: 'cmd.exe /c start /wait "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: null,
    requiresGui: true,
  },
  windows_dll: {
    label: 'Windows DLL (rundll32)',
    command: 'rundll32.exe "{FILE}",DllMain',
    workingDir: null,
    env: {},
    timeoutSeconds: null,
    requiresGui: true,
  },
  windows_msi: {
    label: 'Windows Installer (MSI)',
    command: 'msiexec /i "{FILE}" /qn /norestart',
    workingDir: null,
    env: {},
    timeoutSeconds: null,
    requiresGui: true,
  },
  powershell: {
    label: 'PowerShell Script',
    command: 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: null,
    requiresGui: false,
  },
  python: {
    label: 'Python Script',
    command: 'python "{FILE}"',
    workingDir: null,
    env: { PYTHONDONTWRITEBYTECODE: '1' },
    timeoutSeconds: null,
    requiresGui: false,
  },
  javascript: {
    label: 'JavaScript (Windows Script Host)',
    command: 'cscript.exe //nologo "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: null,
    requiresGui: false,
  },
  vbscript: {
    label: 'VBScript (Windows Script Host)',
    command: 'cscript.exe //nologo "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: null,
    requiresGui: false,
  },
  office_document: {
    label: 'Office Document',
    command: 'cmd.exe /c start /wait "" "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: 180,
    requiresGui: true,
  },
  pdf: {
    label: 'PDF Document',
    command: 'cmd.exe /c start /wait "" "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: 120,
    requiresGui: true,
  },
  url: {
    label: 'URL (Browser)',
    command: 'cmd.exe /c start /wait "" "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: 120,
    requiresGui: true,
  },
  bat_cmd: {
    label: 'Batch/CMD Script',
    command: 'cmd.exe /c "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: null,
    requiresGui: false,
  },
  elf_binary: {
    label: 'Linux ELF Binary',
    command: 'chmod +x "{FILE}" && "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: null,
    requiresGui: false,
  },
  shell_script: {
    label: 'Shell Script',
    command: '/bin/bash "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: null,
    requiresGui: false,
  },
  jar: {
    label: 'Java Archive',
    command: 'java -jar "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: null,
    requiresGui: false,
  },
  hta: {
    label: 'HTML Application',
    command: 'mshta.exe "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: null,
    requiresGui: true,
  },
  unknown: {
    label: 'Unknown File Type',
    command: 'cmd.exe /c start /wait "" "{FILE}"',
    workingDir: null,
    env: {},
    timeoutSeconds: 60,
    requiresGui: true,
  },
};

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Determine the file category from MIME type and file name.
 */
export function classifyFile(mimeType: string, fileName: string): FileCategory {
  // Try MIME type first
  const mimeCategory = MIME_CATEGORY_MAP.get(mimeType);
  if (mimeCategory) return mimeCategory;

  // Fall back to extension
  const dotIndex = fileName.lastIndexOf('.');
  if (dotIndex !== -1) {
    const ext = fileName.slice(dotIndex).toLowerCase();
    const extCategory = EXTENSION_CATEGORY_MAP.get(ext);
    if (extCategory) return extCategory;
  }

  return 'unknown';
}

/**
 * Get the execution strategy for a given file.
 */
export function getExecutionStrategy(
  mimeType: string,
  fileName: string,
): ExecutionStrategy {
  const category = classifyFile(mimeType, fileName);
  return STRATEGIES[category];
}

/**
 * Build the actual command string for executing a sample in the sandbox.
 * Replaces the `{FILE}` placeholder with the actual file path.
 */
export function buildExecutionCommand(
  strategy: ExecutionStrategy,
  remoteSamplePath: string,
): string {
  if (/[`$;&|<>()!"\\\n\r\t]/.test(remoteSamplePath)) {
    throw new Error('Unsafe characters in sample path');
  }
  return strategy.command.replace(/\{FILE\}/g, remoteSamplePath);
}

/**
 * DLL-specific: attempt multiple known entry points.
 */
export function getDllEntryPoints(): readonly string[] {
  return [
    'DllMain',
    'DllRegisterServer',
    'DllUnregisterServer',
    'ServiceMain',
    'Start',
    'Run',
    'Install',
    'Main',
  ];
}

/**
 * Build DLL-specific execution commands for trying multiple entry points.
 */
export function buildDllCommands(dllPath: string): readonly string[] {
  return getDllEntryPoints().map(
    (entry) => `rundll32.exe "${dllPath}",${entry}`,
  );
}
