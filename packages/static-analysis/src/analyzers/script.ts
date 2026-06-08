import * as fs from 'node:fs/promises';

// ── Result types ─────────────────────────────────────────────────────────────

export type ScriptLanguage =
  | 'powershell'
  | 'bash'
  | 'python'
  | 'javascript'
  | 'vbscript'
  | 'batch'
  | 'unknown';

export interface ScriptIndicator {
  pattern: string;
  matchedText: string;
  offset: number;
  reason: string;
  severity: 'info' | 'warning' | 'critical';
  category: 'obfuscation' | 'execution' | 'evasion' | 'network' | 'persistence' | 'encoded_payload' | 'suspicious_import';
}

export interface EncodedPayload {
  encoding: 'base64' | 'hex' | 'xor' | 'gzip_base64' | 'decimal_chars';
  value: string;
  offset: number;
  /** Decoded preview (first 200 chars), or null if decoding fails. */
  decodedPreview: string | null;
}

export interface ScriptAnalysisResult {
  /** Whether the file was identified as a script. */
  isScript: boolean;
  /** Detected script language. */
  language: ScriptLanguage;
  /** Suspicious indicators found. */
  indicators: ScriptIndicator[];
  /** Encoded payloads detected. */
  encodedPayloads: EncodedPayload[];
  /** Overall obfuscation score (0-100). */
  obfuscationScore: number;
  /** Whether the script appears to be obfuscated. */
  isObfuscated: boolean;
  /** Summary of findings by category. */
  categorySummary: Record<string, number>;
}

// ── Language detection ───────────────────────────────────────────────────────

interface LanguageSignature {
  language: ScriptLanguage;
  patterns: RegExp[];
  shebangs: RegExp[];
  extensions: string[];
}

const LANGUAGE_SIGNATURES: readonly LanguageSignature[] = [
  {
    language: 'powershell',
    patterns: [
      /\$[A-Za-z_][A-Za-z0-9_]*\s*=/,
      /\bparam\s*\(/i,
      /\bfunction\s+[A-Za-z\-]+/i,
      /\bGet-[A-Za-z]+\b/i,
      /\bSet-[A-Za-z]+\b/i,
      /\bNew-Object\b/i,
      /\bWrite-Host\b/i,
      /\b\[System\.\w+\]/i,
    ],
    shebangs: [/^#!.*pwsh/m, /^#!.*powershell/mi],
    extensions: ['.ps1', '.psm1', '.psd1'],
  },
  {
    language: 'bash',
    patterns: [
      /^#!/m,
      /\bif\s+\[\s+/m,
      /\bfi\b/m,
      /\bdo\b[\s;]+/m,
      /\bdone\b/m,
      /\besac\b/m,
      /\bfunction\s+\w+\s*\(\)/m,
      /\$\{\w+\}/,
    ],
    shebangs: [/^#!\/bin\/(?:ba)?sh/m, /^#!\/usr\/bin\/env\s+(?:ba)?sh/m, /^#!\/bin\/zsh/m],
    extensions: ['.sh', '.bash', '.zsh'],
  },
  {
    language: 'python',
    patterns: [
      /^import\s+\w+/m,
      /^from\s+\w+\s+import/m,
      /^def\s+\w+\s*\(/m,
      /^class\s+\w+/m,
      /\bprint\s*\(/,
      /\bif\s+__name__\s*==\s*['"]__main__['"]/,
    ],
    shebangs: [/^#!.*python/mi],
    extensions: ['.py', '.pyw'],
  },
  {
    language: 'javascript',
    patterns: [
      /\bfunction\s+\w+\s*\(/,
      /\bvar\s+\w+\s*=/,
      /\blet\s+\w+\s*=/,
      /\bconst\s+\w+\s*=/,
      /=>\s*\{/,
      /\bdocument\.\w+/,
      /\bwindow\.\w+/,
      /\bconsole\.log\b/,
      /\brequire\s*\(/,
    ],
    shebangs: [/^#!.*node/mi],
    extensions: ['.js', '.mjs', '.cjs', '.jsx', '.wsf', '.hta'],
  },
  {
    language: 'vbscript',
    patterns: [
      /\bDim\s+\w+/i,
      /\bSub\s+\w+/i,
      /\bFunction\s+\w+/i,
      /\bWScript\./i,
      /\bCreateObject\s*\(/i,
      /\bMsgBox\b/i,
      /\bEnd\s+Sub\b/i,
      /\bEnd\s+Function\b/i,
    ],
    shebangs: [],
    extensions: ['.vbs', '.vbe', '.wsf'],
  },
  {
    language: 'batch',
    patterns: [
      /^@echo\s+off/mi,
      /^set\s+\w+=/mi,
      /^goto\s+:\w+/mi,
      /^:\w+\s*$/m,
      /\bif\s+exist\b/i,
      /\bfor\s+\/[a-z]\b/i,
      /\%~dp0\b/,
      /\%\w+\%/,
    ],
    shebangs: [],
    extensions: ['.bat', '.cmd'],
  },
];

function detectLanguage(text: string, filePath: string): ScriptLanguage {
  // Check extension first.
  const ext = filePath.toLowerCase().match(/\.[a-z0-9]+$/)?.[0] ?? '';
  for (const sig of LANGUAGE_SIGNATURES) {
    if (sig.extensions.includes(ext)) return sig.language;
  }

  // Check shebangs.
  for (const sig of LANGUAGE_SIGNATURES) {
    for (const shebang of sig.shebangs) {
      if (shebang.test(text)) return sig.language;
    }
  }

  // Score each language based on pattern matches.
  let bestLang: ScriptLanguage = 'unknown';
  let bestScore = 0;

  for (const sig of LANGUAGE_SIGNATURES) {
    let score = 0;
    for (const pat of sig.patterns) {
      if (pat.test(text)) score++;
    }
    if (score > bestScore) {
      bestScore = score;
      bestLang = sig.language;
    }
  }

  return bestScore >= 2 ? bestLang : 'unknown';
}

// ── Pattern type used by all language-specific pattern lists ─────────────────

interface PatternDef {
  pattern: RegExp;
  name: string;
  reason: string;
  severity: 'info' | 'warning' | 'critical';
  category: ScriptIndicator['category'];
}

// ── PowerShell patterns ──────────────────────────────────────────────────────

const PS_PATTERNS: readonly PatternDef[] = [
  // Obfuscation
  { pattern: /\bIEX\b/gi, name: 'IEX', reason: 'Invoke-Expression shorthand (code execution)', severity: 'critical', category: 'obfuscation' },
  { pattern: /\bInvoke-Expression\b/gi, name: 'Invoke-Expression', reason: 'Dynamic code execution', severity: 'critical', category: 'obfuscation' },
  { pattern: /-[Ee]nc(?:oded)?[Cc](?:ommand)?\b/g, name: '-EncodedCommand', reason: 'Base64-encoded PowerShell command', severity: 'critical', category: 'encoded_payload' },
  { pattern: /\[Convert\]::FromBase64String/gi, name: 'FromBase64String', reason: 'Base64 decoding', severity: 'warning', category: 'obfuscation' },
  { pattern: /\[System\.Convert\]::FromBase64String/gi, name: 'System.Convert.FromBase64String', reason: 'Base64 decoding via System', severity: 'warning', category: 'obfuscation' },
  { pattern: /\bInvoke-Obfuscation\b/gi, name: 'Invoke-Obfuscation', reason: 'Known obfuscation tool', severity: 'critical', category: 'obfuscation' },
  { pattern: /-join\s*\(\s*\[char\[\]\]/gi, name: '-join [char[]]', reason: 'Character array join (obfuscation)', severity: 'warning', category: 'obfuscation' },
  { pattern: /\$\w+\s*=\s*\[char\]\d+\s*\+\s*\[char\]\d+/gi, name: 'Char concatenation', reason: 'String building from char codes', severity: 'warning', category: 'obfuscation' },
  { pattern: /\.\s*\(\s*\$\w+\)/g, name: 'Dot-source variable', reason: 'Executing content of a variable', severity: 'warning', category: 'obfuscation' },
  { pattern: /"[`+\$\\]{3,}"/g, name: 'Escaped string', reason: 'Heavily escaped string (obfuscation)', severity: 'warning', category: 'obfuscation' },
  { pattern: /-replace\s*'[^']*',\s*'[^']*'/gi, name: '-replace chain', reason: 'String replacement (potential deobfuscation)', severity: 'info', category: 'obfuscation' },

  // Execution / code injection
  { pattern: /\bNew-Object\s+System\.Net\.WebClient\b/gi, name: 'WebClient', reason: 'Network download capability', severity: 'critical', category: 'network' },
  { pattern: /\bDownloadString\b/gi, name: 'DownloadString', reason: 'Remote code download', severity: 'critical', category: 'network' },
  { pattern: /\bDownloadFile\b/gi, name: 'DownloadFile', reason: 'Remote file download', severity: 'critical', category: 'network' },
  { pattern: /\bDownloadData\b/gi, name: 'DownloadData', reason: 'Remote data download', severity: 'critical', category: 'network' },
  { pattern: /\bInvoke-WebRequest\b/gi, name: 'Invoke-WebRequest', reason: 'HTTP request', severity: 'warning', category: 'network' },
  { pattern: /\bInvoke-RestMethod\b/gi, name: 'Invoke-RestMethod', reason: 'REST API call', severity: 'warning', category: 'network' },
  { pattern: /\bStart-Process\b/gi, name: 'Start-Process', reason: 'Process execution', severity: 'warning', category: 'execution' },
  { pattern: /\bNew-Object\s+System\.Diagnostics\.Process\b/gi, name: 'Diagnostics.Process', reason: 'Process creation via .NET', severity: 'warning', category: 'execution' },
  { pattern: /\bAdd-Type\b/gi, name: 'Add-Type', reason: 'Compile and load .NET code at runtime', severity: 'warning', category: 'execution' },
  { pattern: /\[System\.Reflection\.Assembly\]::Load/gi, name: 'Assembly.Load', reason: 'Dynamic assembly loading', severity: 'critical', category: 'execution' },
  { pattern: /\bInvoke-Mimikatz\b/gi, name: 'Invoke-Mimikatz', reason: 'Credential theft tool', severity: 'critical', category: 'execution' },

  // Evasion
  { pattern: /\bSet-MpPreference\b/gi, name: 'Set-MpPreference', reason: 'Modifying Windows Defender settings', severity: 'critical', category: 'evasion' },
  { pattern: /\bBypass\b/gi, name: 'Bypass', reason: 'Security bypass reference', severity: 'warning', category: 'evasion' },
  { pattern: /-ExecutionPolicy\s+Bypass/gi, name: '-ExecutionPolicy Bypass', reason: 'Bypassing execution policy', severity: 'critical', category: 'evasion' },
  { pattern: /\bAMSI\b/gi, name: 'AMSI', reason: 'AMSI reference (potential bypass)', severity: 'warning', category: 'evasion' },
  { pattern: /\bDisable-WindowsOptionalFeature\b/gi, name: 'Disable-WindowsOptionalFeature', reason: 'Disabling Windows features', severity: 'warning', category: 'evasion' },

  // Persistence
  { pattern: /\bNew-ScheduledTask\b/gi, name: 'New-ScheduledTask', reason: 'Scheduled task creation (persistence)', severity: 'critical', category: 'persistence' },
  { pattern: /\bRegister-ScheduledTask\b/gi, name: 'Register-ScheduledTask', reason: 'Scheduled task registration', severity: 'critical', category: 'persistence' },
  { pattern: /\bNew-ItemProperty\s.*Run\b/gi, name: 'Registry Run key', reason: 'Registry Run key persistence', severity: 'critical', category: 'persistence' },
  { pattern: /\bSet-ItemProperty\s.*Run\b/gi, name: 'Registry Run key set', reason: 'Registry Run key modification', severity: 'critical', category: 'persistence' },
];

// ── Bash patterns ────────────────────────────────────────────────────────────

const BASH_PATTERNS: readonly PatternDef[] = [
  { pattern: /\bcurl\b[^|]*\|\s*(?:ba)?sh\b/gi, name: 'curl|sh', reason: 'Download and execute pattern', severity: 'critical', category: 'execution' },
  { pattern: /\bwget\b[^|]*\|\s*(?:ba)?sh\b/gi, name: 'wget|sh', reason: 'Download and execute pattern', severity: 'critical', category: 'execution' },
  { pattern: /\bcurl\b[^|]*\|\s*bash\b/gi, name: 'curl|bash', reason: 'Download and pipe to bash', severity: 'critical', category: 'execution' },
  { pattern: /\bwget\b[^|]*\|\s*bash\b/gi, name: 'wget|bash', reason: 'Download and pipe to bash', severity: 'critical', category: 'execution' },
  { pattern: /\beval\s+["'`$]/g, name: 'eval', reason: 'Dynamic code evaluation', severity: 'critical', category: 'obfuscation' },
  { pattern: /\/dev\/tcp\/\d/g, name: '/dev/tcp', reason: 'Bash TCP connection (reverse shell)', severity: 'critical', category: 'network' },
  { pattern: /\/dev\/udp\/\d/g, name: '/dev/udp', reason: 'Bash UDP connection', severity: 'critical', category: 'network' },
  { pattern: /\bbase64\s+-d\b/g, name: 'base64 -d', reason: 'Base64 decoding', severity: 'warning', category: 'obfuscation' },
  { pattern: /\bbase64\s+--decode\b/g, name: 'base64 --decode', reason: 'Base64 decoding', severity: 'warning', category: 'obfuscation' },
  { pattern: /\b\$\(echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\b/g, name: 'echo|base64', reason: 'Encoded command execution', severity: 'critical', category: 'encoded_payload' },
  { pattern: /\bnc\s+-[a-z]*l/gi, name: 'nc -l (netcat listen)', reason: 'Netcat listener (backdoor)', severity: 'critical', category: 'network' },
  { pattern: /\bncat\b/gi, name: 'ncat', reason: 'Ncat network tool', severity: 'warning', category: 'network' },
  { pattern: /\bsocat\b/gi, name: 'socat', reason: 'Socat network relay', severity: 'warning', category: 'network' },
  { pattern: /\bchmod\s+[0-7]*[75][0-7]*\s/g, name: 'chmod executable', reason: 'Making files executable', severity: 'warning', category: 'execution' },
  { pattern: /\bcrontab\b/gi, name: 'crontab', reason: 'Cron job manipulation (persistence)', severity: 'warning', category: 'persistence' },
  { pattern: /\/etc\/cron/g, name: '/etc/cron', reason: 'Direct cron directory access', severity: 'warning', category: 'persistence' },
  { pattern: /\biptables\s+-[A-Z]/g, name: 'iptables', reason: 'Firewall rule manipulation', severity: 'warning', category: 'evasion' },
  { pattern: /\bhistory\s+-[cd]/g, name: 'history clear', reason: 'Clearing command history (anti-forensics)', severity: 'critical', category: 'evasion' },
  { pattern: /\brm\s+-[rf]+\s+\/(?:var\/log|tmp)/g, name: 'rm logs', reason: 'Log deletion (anti-forensics)', severity: 'critical', category: 'evasion' },
  { pattern: /\bnohup\b/g, name: 'nohup', reason: 'Background process persistence', severity: 'info', category: 'persistence' },
  { pattern: /\bdisown\b/g, name: 'disown', reason: 'Detaching process from shell', severity: 'info', category: 'persistence' },
  { pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}/g, name: 'hex escape sequence', reason: 'Hex-encoded content', severity: 'warning', category: 'encoded_payload' },
];

// ── Python patterns ──────────────────────────────────────────────────────────

const PYTHON_PATTERNS: readonly PatternDef[] = [
  { pattern: /\bimport\s+socket\b/g, name: 'import socket', reason: 'Network socket library', severity: 'warning', category: 'suspicious_import' },
  { pattern: /\bimport\s+subprocess\b/g, name: 'import subprocess', reason: 'Process execution library', severity: 'warning', category: 'suspicious_import' },
  { pattern: /\bimport\s+ctypes\b/g, name: 'import ctypes', reason: 'C type library (native code execution)', severity: 'warning', category: 'suspicious_import' },
  { pattern: /\bos\.system\s*\(/g, name: 'os.system()', reason: 'Shell command execution', severity: 'critical', category: 'execution' },
  { pattern: /\bos\.popen\s*\(/g, name: 'os.popen()', reason: 'Shell command with pipe', severity: 'critical', category: 'execution' },
  { pattern: /\bos\.exec\w*\s*\(/g, name: 'os.exec*()', reason: 'Process replacement', severity: 'critical', category: 'execution' },
  { pattern: /\bsubprocess\.\w+\s*\(/g, name: 'subprocess call', reason: 'Process execution', severity: 'warning', category: 'execution' },
  { pattern: /\bexec\s*\(/g, name: 'exec()', reason: 'Dynamic code execution', severity: 'critical', category: 'obfuscation' },
  { pattern: /\beval\s*\(/g, name: 'eval()', reason: 'Dynamic expression evaluation', severity: 'critical', category: 'obfuscation' },
  { pattern: /\bcompile\s*\(/g, name: 'compile()', reason: 'Dynamic code compilation', severity: 'warning', category: 'obfuscation' },
  { pattern: /\b__import__\s*\(/g, name: '__import__()', reason: 'Dynamic import', severity: 'warning', category: 'obfuscation' },
  { pattern: /\bbase64\.b64decode\b/g, name: 'base64.b64decode', reason: 'Base64 decoding', severity: 'warning', category: 'encoded_payload' },
  { pattern: /\bbase64\.b32decode\b/g, name: 'base64.b32decode', reason: 'Base32 decoding', severity: 'warning', category: 'encoded_payload' },
  { pattern: /\bcodecs\.decode\b/g, name: 'codecs.decode', reason: 'Encoding/decoding operation', severity: 'info', category: 'obfuscation' },
  { pattern: /\bzlib\.decompress\b/g, name: 'zlib.decompress', reason: 'Compressed data decompression', severity: 'info', category: 'encoded_payload' },
  { pattern: /\bimport\s+paramiko\b/g, name: 'import paramiko', reason: 'SSH library (remote access)', severity: 'warning', category: 'suspicious_import' },
  { pattern: /\bimport\s+scapy\b/g, name: 'import scapy', reason: 'Packet manipulation library', severity: 'warning', category: 'suspicious_import' },
  { pattern: /\bimport\s+pynput\b/g, name: 'import pynput', reason: 'Input monitoring (keylogger)', severity: 'critical', category: 'suspicious_import' },
  { pattern: /\bimport\s+pyautogui\b/g, name: 'import pyautogui', reason: 'GUI automation', severity: 'info', category: 'suspicious_import' },
  { pattern: /\bimport\s+mss\b/g, name: 'import mss', reason: 'Screenshot library', severity: 'warning', category: 'suspicious_import' },
  { pattern: /\bimport\s+pycryptodome\b|\bfrom\s+Crypto\b/g, name: 'pycryptodome/Crypto', reason: 'Cryptography library', severity: 'info', category: 'suspicious_import' },
  { pattern: /\bimport\s+win32api\b/g, name: 'import win32api', reason: 'Windows API access', severity: 'warning', category: 'suspicious_import' },
  { pattern: /\bimport\s+winreg\b/g, name: 'import winreg', reason: 'Windows registry access', severity: 'warning', category: 'suspicious_import' },
  { pattern: /\bctypes\.windll\b/g, name: 'ctypes.windll', reason: 'Windows DLL access via ctypes', severity: 'critical', category: 'execution' },
  { pattern: /\bctypes\.cdll\b/g, name: 'ctypes.cdll', reason: 'Native library access via ctypes', severity: 'warning', category: 'execution' },
];

// ── JavaScript patterns ──────────────────────────────────────────────────────

const JS_PATTERNS: readonly PatternDef[] = [
  { pattern: /\beval\s*\(/g, name: 'eval()', reason: 'Dynamic code execution', severity: 'critical', category: 'obfuscation' },
  { pattern: /\bdocument\.write\s*\(/g, name: 'document.write()', reason: 'DOM manipulation (potential injection)', severity: 'warning', category: 'execution' },
  { pattern: /\bActiveXObject\s*\(/g, name: 'ActiveXObject', reason: 'ActiveX object creation (Windows-specific)', severity: 'critical', category: 'execution' },
  { pattern: /\bnew\s+Function\s*\(/g, name: 'new Function()', reason: 'Dynamic function creation', severity: 'critical', category: 'obfuscation' },
  { pattern: /\bWScript\.Shell\b/gi, name: 'WScript.Shell', reason: 'Windows Script Host shell', severity: 'critical', category: 'execution' },
  { pattern: /\bWScript\.CreateObject\b/gi, name: 'WScript.CreateObject', reason: 'COM object creation', severity: 'critical', category: 'execution' },
  { pattern: /\bShell\.Application\b/gi, name: 'Shell.Application', reason: 'Shell automation', severity: 'critical', category: 'execution' },
  { pattern: /\bScripting\.FileSystemObject\b/gi, name: 'Scripting.FileSystemObject', reason: 'File system access', severity: 'warning', category: 'execution' },
  { pattern: /\bMSXML2\.XMLHTTP\b/gi, name: 'MSXML2.XMLHTTP', reason: 'HTTP request via ActiveX', severity: 'critical', category: 'network' },
  { pattern: /\bADODB\.Stream\b/gi, name: 'ADODB.Stream', reason: 'Binary stream (file write)', severity: 'critical', category: 'execution' },
  { pattern: /\bsetTimeout\s*\(\s*["'].*["']/g, name: 'setTimeout(string)', reason: 'Delayed string execution', severity: 'warning', category: 'obfuscation' },
  { pattern: /\bsetInterval\s*\(\s*["'].*["']/g, name: 'setInterval(string)', reason: 'Repeated string execution', severity: 'warning', category: 'obfuscation' },
  { pattern: /\bunescape\s*\(/g, name: 'unescape()', reason: 'String unescaping (obfuscation)', severity: 'warning', category: 'obfuscation' },
  { pattern: /\batob\s*\(/g, name: 'atob()', reason: 'Base64 decoding', severity: 'warning', category: 'encoded_payload' },
  { pattern: /\bString\.fromCharCode\s*\(/g, name: 'String.fromCharCode()', reason: 'Building strings from char codes', severity: 'warning', category: 'obfuscation' },
  { pattern: /\bcharCodeAt\s*\(/g, name: 'charCodeAt()', reason: 'Character code extraction', severity: 'info', category: 'obfuscation' },
  { pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}/g, name: 'hex escape sequence', reason: 'Hex-encoded content', severity: 'warning', category: 'encoded_payload' },
  { pattern: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}/g, name: 'unicode escape sequence', reason: 'Unicode-encoded content', severity: 'warning', category: 'encoded_payload' },
  { pattern: /\bwindow\s*\[\s*["'][a-z]+["']\s*\]/gi, name: 'window[string]', reason: 'Bracket notation access (evasion)', severity: 'warning', category: 'evasion' },
  { pattern: /\[["']constructor["']\]\s*\[/g, name: 'constructor chain', reason: 'Constructor-based code execution', severity: 'critical', category: 'obfuscation' },
];

// ── VBScript patterns ────────────────────────────────────────────────────────

const VBS_PATTERNS: readonly PatternDef[] = [
  { pattern: /\bCreateObject\s*\(\s*"WScript\.Shell"/gi, name: 'CreateObject WScript.Shell', reason: 'Shell execution', severity: 'critical', category: 'execution' },
  { pattern: /\bCreateObject\s*\(\s*"Scripting\.FileSystemObject"/gi, name: 'CreateObject FSO', reason: 'File system access', severity: 'warning', category: 'execution' },
  { pattern: /\bCreateObject\s*\(\s*"MSXML2/gi, name: 'CreateObject MSXML2', reason: 'HTTP request capability', severity: 'critical', category: 'network' },
  { pattern: /\bCreateObject\s*\(\s*"ADODB\.Stream"/gi, name: 'CreateObject ADODB.Stream', reason: 'Binary file operations', severity: 'critical', category: 'execution' },
  { pattern: /\bExecute\s*\(/gi, name: 'Execute()', reason: 'Dynamic code execution', severity: 'critical', category: 'obfuscation' },
  { pattern: /\bExecuteGlobal\s*\(/gi, name: 'ExecuteGlobal()', reason: 'Global scope code execution', severity: 'critical', category: 'obfuscation' },
  { pattern: /\bChrW?\s*\(\s*\d+\s*\)/gi, name: 'Chr()/ChrW()', reason: 'Character code conversion (obfuscation)', severity: 'warning', category: 'obfuscation' },
  { pattern: /\bShell\.Run\b/gi, name: 'Shell.Run', reason: 'Process execution', severity: 'critical', category: 'execution' },
  { pattern: /\b\.ShellExecute\b/gi, name: 'ShellExecute', reason: 'Process execution via shell', severity: 'critical', category: 'execution' },
  { pattern: /\bRegWrite\b/gi, name: 'RegWrite', reason: 'Registry modification', severity: 'warning', category: 'persistence' },
];

// ── Batch patterns ───────────────────────────────────────────────────────────

const BATCH_PATTERNS: readonly PatternDef[] = [
  { pattern: /\bpowershell\b[^"\n]*-[Ee]nc/gi, name: 'powershell -enc', reason: 'Encoded PowerShell from batch', severity: 'critical', category: 'encoded_payload' },
  { pattern: /\bcertutil\s+-decode\b/gi, name: 'certutil -decode', reason: 'Base64 decoding via certutil', severity: 'critical', category: 'encoded_payload' },
  { pattern: /\bcertutil\s+-urlcache\b/gi, name: 'certutil -urlcache', reason: 'File download via certutil', severity: 'critical', category: 'network' },
  { pattern: /\bbitsadmin\b/gi, name: 'bitsadmin', reason: 'Background file transfer', severity: 'warning', category: 'network' },
  { pattern: /\breg\s+add\b/gi, name: 'reg add', reason: 'Registry modification', severity: 'warning', category: 'persistence' },
  { pattern: /\bschtasks\s+\/create\b/gi, name: 'schtasks /create', reason: 'Scheduled task creation', severity: 'critical', category: 'persistence' },
  { pattern: /\bnet\s+user\b/gi, name: 'net user', reason: 'User account manipulation', severity: 'warning', category: 'execution' },
  { pattern: /\bnet\s+localgroup\s+administrators\b/gi, name: 'net localgroup administrators', reason: 'Adding user to administrators', severity: 'critical', category: 'execution' },
  { pattern: /\bsc\s+create\b/gi, name: 'sc create', reason: 'Service creation', severity: 'critical', category: 'persistence' },
  { pattern: /\bwmic\b/gi, name: 'wmic', reason: 'WMI command-line', severity: 'warning', category: 'execution' },
  { pattern: /\battrib\s+\+h/gi, name: 'attrib +h', reason: 'Hiding files', severity: 'warning', category: 'evasion' },
  { pattern: /\bdel\s+\/[fqs]\b/gi, name: 'del /f', reason: 'Force file deletion', severity: 'info', category: 'evasion' },
];

// ── Encoded payload detection ────────────────────────────────────────────────

function detectEncodedPayloads(text: string): EncodedPayload[] {
  const payloads: EncodedPayload[] = [];

  // Base64 strings (min 40 chars to reduce false positives from scripts).
  const b64Re = /[A-Za-z0-9+/]{40,}={0,2}/g;
  let match: RegExpExecArray | null;
  b64Re.lastIndex = 0;
  while ((match = b64Re.exec(text)) !== null) {
    try {
      const decoded = Buffer.from(match[0], 'base64');
      // Validate: round-trip must match and decoded should have some printable chars.
      if (decoded.toString('base64') === match[0]) {
        const preview = decoded.toString('utf-8').substring(0, 200);
        // Only report if decoded content has at least some printable chars.
        const printableCount = preview.split('').filter((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126).length;
        if (printableCount / Math.max(preview.length, 1) > 0.4) {
          payloads.push({
            encoding: 'base64',
            value: match[0].substring(0, 200),
            offset: match.index,
            decodedPreview: preview,
          });
        }
      }
    } catch {
      // Not valid base64.
    }
    if (payloads.length > 50) break;
  }

  // Hex-encoded strings (long sequences of hex pairs).
  const hexRe = /(?:\\x[0-9a-fA-F]{2}){10,}/g;
  hexRe.lastIndex = 0;
  while ((match = hexRe.exec(text)) !== null) {
    const hexStr = match[0].replace(/\\x/g, '');
    try {
      const decoded = Buffer.from(hexStr, 'hex');
      payloads.push({
        encoding: 'hex',
        value: match[0].substring(0, 200),
        offset: match.index,
        decodedPreview: decoded.toString('utf-8').substring(0, 200),
      });
    } catch {
      // Not valid hex.
    }
    if (payloads.length > 50) break;
  }

  // Decimal char code sequences: Chr(104)+Chr(116)+...
  const chrRe = /(?:Chr[W]?\s*\(\s*\d+\s*\)\s*[&+]\s*){4,}/gi;
  chrRe.lastIndex = 0;
  while ((match = chrRe.exec(text)) !== null) {
    const nums = [...match[0].matchAll(/\d+/g)].map((m) => parseInt(m[0], 10));
    const decoded = nums.map((n) => String.fromCharCode(n)).join('');
    payloads.push({
      encoding: 'decimal_chars',
      value: match[0].substring(0, 200),
      offset: match.index,
      decodedPreview: decoded.substring(0, 200),
    });
    if (payloads.length > 50) break;
  }

  return payloads;
}

// ── Obfuscation scoring ─────────────────────────────────────────────────────

function computeObfuscationScore(text: string, indicators: ScriptIndicator[], encodedPayloads: EncodedPayload[]): number {
  let score = 0;

  // Points from indicators.
  for (const ind of indicators) {
    if (ind.category === 'obfuscation') {
      score += ind.severity === 'critical' ? 15 : ind.severity === 'warning' ? 8 : 3;
    }
    if (ind.category === 'encoded_payload') {
      score += ind.severity === 'critical' ? 12 : 8;
    }
  }

  // Points from encoded payloads.
  score += encodedPayloads.length * 5;

  // Check for high ratio of non-printable or special characters.
  const specialCharCount = text.split('').filter((c) => {
    const code = c.charCodeAt(0);
    return code > 127 || (code < 32 && code !== 10 && code !== 13 && code !== 9);
  }).length;
  const specialRatio = specialCharCount / Math.max(text.length, 1);
  if (specialRatio > 0.1) score += 15;
  if (specialRatio > 0.3) score += 20;

  // Check average line length (obfuscated scripts often have very long lines).
  const lines = text.split('\n').filter((l) => l.trim().length > 0);
  if (lines.length > 0) {
    const avgLineLength = lines.reduce((sum, l) => sum + l.length, 0) / lines.length;
    if (avgLineLength > 500) score += 10;
    if (avgLineLength > 2000) score += 15;
  }

  // Single very long line (minified/obfuscated).
  const maxLineLength = lines.reduce((max, l) => Math.max(max, l.length), 0);
  if (maxLineLength > 5000 && lines.length < 10) score += 15;

  return Math.min(100, score);
}

// ── Main analysis function ───────────────────────────────────────────────────

export async function analyzeScript(filePath: string): Promise<ScriptAnalysisResult> {
  const buf = await fs.readFile(filePath);
  const text = buf.toString('utf-8');

  const language = detectLanguage(text, filePath);

  if (language === 'unknown') {
    // Try to see if it's at least partially text.
    const printableCount = text.split('').filter((c) => {
      const code = c.charCodeAt(0);
      return (code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9;
    }).length;
    const textRatio = printableCount / Math.max(text.length, 1);

    if (textRatio < 0.7) {
      return {
        isScript: false,
        language: 'unknown',
        indicators: [],
        encodedPayloads: [],
        obfuscationScore: 0,
        isObfuscated: false,
        categorySummary: {},
      };
    }
  }

  // Select patterns based on detected language.
  let patterns: readonly PatternDef[] = [];

  switch (language) {
    case 'powershell': patterns = PS_PATTERNS; break;
    case 'bash': patterns = BASH_PATTERNS; break;
    case 'python': patterns = PYTHON_PATTERNS; break;
    case 'javascript': patterns = JS_PATTERNS; break;
    case 'vbscript': patterns = VBS_PATTERNS; break;
    case 'batch': patterns = BATCH_PATTERNS; break;
    default:
      // Apply a subset of all patterns for unknown language.
      patterns = [
        ...PS_PATTERNS.filter((p) => p.severity === 'critical'),
        ...BASH_PATTERNS.filter((p) => p.severity === 'critical'),
        ...JS_PATTERNS.filter((p) => p.severity === 'critical'),
      ];
      break;
  }

  // Run pattern matching.
  const indicators: ScriptIndicator[] = [];

  for (const pat of patterns) {
    pat.pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    let matchCount = 0;
    while ((m = pat.pattern.exec(text)) !== null) {
      indicators.push({
        pattern: pat.name,
        matchedText: m[0].substring(0, 200),
        offset: m.index,
        reason: pat.reason,
        severity: pat.severity,
        category: pat.category,
      });
      matchCount++;
      if (matchCount >= 10) break; // Cap per-pattern matches
    }
    pat.pattern.lastIndex = 0;
  }

  // Detect encoded payloads.
  const encodedPayloads = detectEncodedPayloads(text);

  // Compute obfuscation score.
  const obfuscationScore = computeObfuscationScore(text, indicators, encodedPayloads);

  // Build category summary.
  const categorySummary: Record<string, number> = {};
  for (const ind of indicators) {
    categorySummary[ind.category] = (categorySummary[ind.category] ?? 0) + 1;
  }

  return {
    isScript: true,
    language,
    indicators,
    encodedPayloads,
    obfuscationScore,
    isObfuscated: obfuscationScore >= 40,
    categorySummary,
  };
}
