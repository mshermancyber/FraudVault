// ── Deobfuscation, Decompilation & Rule Generation ─────────────────────────
// Provides layer-by-layer deobfuscation for PowerShell, JavaScript, Office macros,
// .NET assemblies, and auto-generates YARA + Snort/Suricata rules from analysis results.

// ── Interfaces ─────────────────────────────────────────────────────────────────

export interface DeobfuscationLayer {
  readonly layer: number;
  readonly content: string;
  readonly technique: string;
}

export interface IOC {
  readonly type: string;
  readonly value: string;
}

export interface DeobfuscationResult {
  readonly originalScript: string;
  readonly layers: DeobfuscationLayer[];
  readonly finalPayload: string;
  readonly iocs: IOC[];
  readonly indicators: string[];
}

export interface GeneratedYaraRule {
  readonly name: string;
  readonly description: string;
  readonly rule: string;
  readonly confidence: number;
}

export interface SectionInfo {
  readonly name: string;
  readonly entropy: number;
}

export interface DnsQueryEntry {
  readonly domain: string;
}

export interface HttpRequestEntry {
  readonly host: string;
  readonly uri: string;
  readonly method: string;
  readonly userAgent?: string;
}

export interface ConnectionEntry {
  readonly ip: string;
  readonly port: number;
  readonly protocol: string;
}

export interface NetworkRules {
  readonly suricata: string[];
  readonly snort: string[];
}

// ── 1. PowerShell Deobfuscation ────────────────────────────────────────────────

/**
 * Returns a Python script that performs layer-by-layer PowerShell deobfuscation.
 * The script identifies encoding techniques (base64, gzip, XOR, char substitution),
 * recursively decodes each layer, extracts the final payload, and pulls IOCs.
 */
export function getPowerShellDeobfuscationScript(scriptContent: string): string {
  const jsonContent = JSON.stringify(scriptContent);
  const b64Content = Buffer.from(jsonContent, 'utf-8').toString('base64');

  return `#!/usr/bin/env python3
"""
FraudVault PowerShell Deobfuscation Engine
Performs recursive layer-by-layer deobfuscation of obfuscated PowerShell scripts.
"""

import base64
import re
import zlib
import json
import sys
from typing import List, Dict, Tuple

SCRIPT_CONTENT = json.loads(base64.b64decode('${b64Content}').decode('utf-8'))

class PowerShellDeobfuscator:
    def __init__(self, script: str):
        self.original = script
        self.layers: List[Dict[str, object]] = []
        self.iocs: List[Dict[str, str]] = []
        self.indicators: List[str] = []
        self.current_layer = 0

    def decode_base64_command(self, content: str) -> Tuple[str, bool]:
        """Decode -EncodedCommand or [Convert]::FromBase64String patterns."""
        # Match -EncodedCommand or -enc or -e followed by base64
        patterns = [
            r'-[Ee](?:nc(?:oded)?[Cc](?:ommand)?)?\\s+([A-Za-z0-9+/=]+)',
            r'\\[Convert\\]::FromBase64String\\(["\\'](.*?)["\\'\\)]',
            r'\\[System\\.Convert\\]::FromBase64String\\(["\\'](.*?)["\\'\\)]',
            r'FromBase64String\\(["\\'](.*?)["\\'\\)]',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                try:
                    decoded_bytes = base64.b64decode(match)
                    # Try UTF-16LE first (common for PowerShell encoded commands)
                    try:
                        decoded = decoded_bytes.decode('utf-16-le')
                    except (UnicodeDecodeError, ValueError):
                        decoded = decoded_bytes.decode('utf-8', errors='replace')
                    if len(decoded) > 5 and any(c.isalpha() for c in decoded):
                        return decoded, True
                except Exception:
                    continue
        return content, False

    def decode_char_codes(self, content: str) -> Tuple[str, bool]:
        """Decode [char]72+[char]101... style obfuscation."""
        # Pattern: [char]N or [Char]N or ([char]N+[char]M+...)
        char_pattern = r'\\[(?:[Cc]har|CHAR)\\]\\s*(\\d+)'
        matches = re.findall(char_pattern, content)
        if len(matches) >= 3:
            decoded_chars = ''.join(chr(int(m)) for m in matches if 0 < int(m) < 65536)
            if decoded_chars:
                # Replace the char array expression in context
                full_pattern = r'(?:\\[(?:[Cc]har|CHAR)\\]\\s*\\d+\\s*\\+?\\s*)+'
                result = re.sub(full_pattern, decoded_chars, content)
                return result, True

        # Also handle $([char]0x4D+[char]0x5A) hex style
        hex_char_pattern = r'\\[(?:[Cc]har|CHAR)\\]\\s*0x([0-9A-Fa-f]+)'
        hex_matches = re.findall(hex_char_pattern, content)
        if len(hex_matches) >= 3:
            decoded_chars = ''.join(chr(int(m, 16)) for m in hex_matches if 0 < int(m, 16) < 65536)
            if decoded_chars:
                full_pattern = r'(?:\\[(?:[Cc]har|CHAR)\\]\\s*0x[0-9A-Fa-f]+\\s*\\+?\\s*)+'
                result = re.sub(full_pattern, decoded_chars, content)
                return result, True

        return content, False

    def decode_string_reversal(self, content: str) -> Tuple[str, bool]:
        """Detect and reverse reversed strings."""
        # Pattern: reversed string with indicators
        patterns = [
            r"\\-join\\s*\\(\\s*'([^']+)'\\s*\\[\\s*\\d+\\.\\.0\\s*\\]\\s*\\)",
            r"\\('([^']+)'\\[\\((\\d+)\\.\\.0\\)\\]\\s*-join\\s*''\\)",
            r'\\.Reverse\\(\\).*?["\\'](.*?)["\\'\\]',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                reversed_str = match[::-1] if isinstance(match, str) else match[0][::-1]
                if len(reversed_str) > 5:
                    return content.replace(match if isinstance(match, str) else match[0], reversed_str), True
        return content, False

    def decode_replacement_chains(self, content: str) -> Tuple[str, bool]:
        """Apply .replace() or -replace chains."""
        replace_pattern = r"-replace\\s*['\"]([^'\"]*)['\"]\\s*,\\s*['\"]([^'\"]*)['\"]"
        matches = re.findall(replace_pattern, content)
        if matches:
            result = content
            for old, new in matches:
                result = result.replace(old, new)
            # Remove the replace directives themselves
            result = re.sub(replace_pattern, '', result)
            if result != content:
                return result, True
        return content, False

    def decode_gzip_deflate(self, content: str) -> Tuple[str, bool]:
        """Decompress GZip/Deflate compressed payloads."""
        # Look for patterns indicating compressed content
        patterns = [
            r'\\[IO\\.Compression\\.GZipStream\\]',
            r'\\[IO\\.Compression\\.DeflateStream\\]',
            r'New-Object\\s+IO\\.Compression\\.',
            r'Decompress',
        ]
        has_compression = any(re.search(p, content) for p in patterns)
        if not has_compression:
            return content, False

        # Try to find and decompress base64 within
        b64_pattern = r'[A-Za-z0-9+/=]{50,}'
        b64_matches = re.findall(b64_pattern, content)
        for b64 in b64_matches:
            try:
                raw = base64.b64decode(b64)
                # Try gzip
                try:
                    decompressed = zlib.decompress(raw, 16 + zlib.MAX_WBITS)
                    decoded = decompressed.decode('utf-8', errors='replace')
                    if len(decoded) > 10:
                        return decoded, True
                except Exception:
                    pass
                # Try deflate
                try:
                    decompressed = zlib.decompress(raw, -zlib.MAX_WBITS)
                    decoded = decompressed.decode('utf-8', errors='replace')
                    if len(decoded) > 10:
                        return decoded, True
                except Exception:
                    pass
                # Try raw zlib
                try:
                    decompressed = zlib.decompress(raw)
                    decoded = decompressed.decode('utf-8', errors='replace')
                    if len(decoded) > 10:
                        return decoded, True
                except Exception:
                    pass
            except Exception:
                continue
        return content, False

    def decode_xor(self, content: str) -> Tuple[str, bool]:
        """Decode XOR-encoded content."""
        # Look for XOR loop patterns
        xor_patterns = [
            r'-bxor\\s*(\\d+)',
            r'\\^\\s*(\\d+)',
            r'xor.*?(\\d{1,3})',
        ]
        for pattern in xor_patterns:
            matches = re.findall(pattern, content)
            if matches:
                key = int(matches[0])
                if 1 <= key <= 255:
                    # Find byte arrays to XOR
                    byte_pattern = r'(?:\\d{1,3}\\s*,\\s*){5,}'
                    byte_matches = re.findall(byte_pattern, content)
                    for byte_str in byte_matches:
                        try:
                            byte_vals = [int(b.strip()) for b in byte_str.split(',') if b.strip()]
                            decoded = ''.join(chr(b ^ key) for b in byte_vals if 0 <= (b ^ key) < 65536)
                            if len(decoded) > 5 and any(c.isalpha() for c in decoded):
                                self.indicators.append(f'XOR key: {key}')
                                return decoded, True
                        except (ValueError, TypeError):
                            continue
        return content, False

    def decode_iex_capture(self, content: str) -> Tuple[str, bool]:
        """Capture what Invoke-Expression (IEX) would execute."""
        # Strip IEX/Invoke-Expression wrappers to reveal inner content
        iex_patterns = [
            r'(?:IEX|Invoke-Expression)\\s*\\((.+)\\)',
            r'(?:IEX|Invoke-Expression)\\s*(.+)',
            r'\\|\\s*(?:IEX|Invoke-Expression)',
        ]
        for pattern in iex_patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if match:
                if match.groups():
                    inner = match.group(1).strip()
                    if inner != content and len(inner) > 10:
                        self.indicators.append('Invoke-Expression (IEX) detected — dynamic code execution')
                        return inner, True
        return content, False

    def extract_iocs(self, content: str) -> None:
        """Extract indicators of compromise from content."""
        # URLs
        urls = re.findall(r'https?://[^\\s\\'\\";,\\)\\]>]+', content)
        for url in urls:
            self.iocs.append({'type': 'url', 'value': url})

        # IP addresses
        ips = re.findall(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', content)
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                # Skip private/loopback
                if not (ip.startswith('127.') or ip.startswith('10.') or
                        ip.startswith('192.168.') or ip.startswith('0.')):
                    self.iocs.append({'type': 'ip', 'value': ip})

        # Domains
        domains = re.findall(r'\\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.(?:[a-zA-Z]{2,}))\\b', content)
        for domain in domains:
            if '.' in domain and not domain.endswith('.dll') and not domain.endswith('.exe'):
                self.iocs.append({'type': 'domain', 'value': domain})

        # File paths
        paths = re.findall(r'[A-Z]:\\\\[\\\\a-zA-Z0-9_.\\-\\s]+', content)
        for path in paths:
            self.iocs.append({'type': 'filepath', 'value': path})

        # Registry keys
        reg_keys = re.findall(r'(?:HKLM|HKCU|HKCR|HKU|HKCC)\\\\[\\\\a-zA-Z0-9_.\\-\\s]+', content)
        for key in reg_keys:
            self.iocs.append({'type': 'registry', 'value': key})

        # Email addresses
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', content)
        for email in emails:
            self.iocs.append({'type': 'email', 'value': email})

    def detect_indicators(self, content: str) -> None:
        """Detect suspicious behavioral indicators."""
        indicator_patterns = [
            (r'Net\\.WebClient|WebRequest|Invoke-WebRequest|wget|curl', 'Network download capability'),
            (r'Start-Process|Invoke-Item|cmd\\.exe|powershell\\.exe', 'Process execution'),
            (r'\\$env:TEMP|\\$env:APPDATA|%TEMP%|%APPDATA%', 'References temp/appdata directories'),
            (r'Set-ItemProperty.*Run|New-ItemProperty.*Run', 'Registry persistence (Run key)'),
            (r'schtasks|Register-ScheduledTask', 'Scheduled task persistence'),
            (r'Add-MpPreference.*ExclusionPath', 'Defender exclusion (evasion)'),
            (r'\\[Reflection\\.Assembly\\]|LoadWithPartialName', 'Reflective assembly loading'),
            (r'VirtualAlloc|NtAllocateVirtualMemory|VirtualProtect', 'Memory manipulation (shellcode injection)'),
            (r'CreateThread|CreateRemoteThread|QueueUserAPC', 'Thread injection'),
            (r'Wmi|Get-WmiObject|Invoke-WmiMethod', 'WMI usage'),
            (r'AES|RijndaelManaged|DESCryptoServiceProvider', 'Cryptographic operations'),
            (r'Credentials|SecureString|NetworkCredential', 'Credential access'),
        ]
        for pattern, description in indicator_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if description not in self.indicators:
                    self.indicators.append(description)

    def deobfuscate(self) -> Dict[str, object]:
        """Run all deobfuscation layers recursively."""
        content = self.original
        max_layers = 20

        while self.current_layer < max_layers:
            decoded = False
            technique = ''

            # Try each deobfuscation technique in order
            result, success = self.decode_base64_command(content)
            if success:
                technique = 'Base64 decoding'
                content = result
                decoded = True
            else:
                result, success = self.decode_gzip_deflate(content)
                if success:
                    technique = 'GZip/Deflate decompression'
                    content = result
                    decoded = True
                else:
                    result, success = self.decode_xor(content)
                    if success:
                        technique = 'XOR decoding'
                        content = result
                        decoded = True
                    else:
                        result, success = self.decode_char_codes(content)
                        if success:
                            technique = 'Character code reconstruction'
                            content = result
                            decoded = True
                        else:
                            result, success = self.decode_string_reversal(content)
                            if success:
                                technique = 'String reversal'
                                content = result
                                decoded = True
                            else:
                                result, success = self.decode_replacement_chains(content)
                                if success:
                                    technique = 'String replacement chain'
                                    content = result
                                    decoded = True
                                else:
                                    result, success = self.decode_iex_capture(content)
                                    if success:
                                        technique = 'IEX unwrap'
                                        content = result
                                        decoded = True

            if decoded:
                self.current_layer += 1
                self.layers.append({
                    'layer': self.current_layer,
                    'content': content[:5000],
                    'technique': technique,
                })
                # Extract IOCs at each layer
                self.extract_iocs(content)
                self.detect_indicators(content)
            else:
                break

        # Final IOC extraction on the last content
        self.extract_iocs(content)
        self.detect_indicators(content)

        # Deduplicate IOCs
        seen = set()
        unique_iocs = []
        for ioc in self.iocs:
            key = f"{ioc['type']}:{ioc['value']}"
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return {
            'originalScript': self.original[:2000],
            'layers': self.layers,
            'finalPayload': content[:10000],
            'iocs': unique_iocs,
            'indicators': list(set(self.indicators)),
        }


if __name__ == '__main__':
    deobfuscator = PowerShellDeobfuscator(SCRIPT_CONTENT)
    result = deobfuscator.deobfuscate()
    print(json.dumps(result, indent=2, default=str))
`;
}

// ── 2. JavaScript Deobfuscation ────────────────────────────────────────────────

/**
 * Returns a Node.js script that deobfuscates JavaScript by hooking eval(),
 * Function(), document.write() etc., executing the JS in a sandboxed context,
 * and capturing all deobfuscated outputs.
 */
export function getJavaScriptDeobfuscationScript(jsContent: string): string {
  const serializedContent = JSON.stringify(jsContent);

  return `#!/usr/bin/env node
"use strict";

const vm = require('vm');

const SCRIPT_CONTENT = ${serializedContent};

const captured = [];
const urls = [];
const ips = [];
const indicators = [];
let executionError = null;

// Build a fake DOM/browser environment
const fakeDocument = {
  write: function(content) {
    captured.push({ source: 'document.write', content: String(content) });
  },
  writeln: function(content) {
    captured.push({ source: 'document.writeln', content: String(content) });
  },
  createElement: function(tag) {
    return {
      tagName: tag,
      src: '',
      href: '',
      setAttribute: function(name, value) {
        if (name === 'src' || name === 'href') {
          urls.push(value);
        }
      },
      appendChild: function() {},
      style: {},
    };
  },
  getElementById: function() { return null; },
  getElementsByTagName: function() { return []; },
  body: { appendChild: function() {}, innerHTML: '' },
  head: { appendChild: function() {} },
  location: { href: 'about:blank', hostname: 'localhost' },
  cookie: '',
};

const fakeWindow = {
  location: { href: 'about:blank', hostname: 'localhost' },
  navigator: { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
  document: fakeDocument,
};

// Hooked eval
function hookedEval(code) {
  const codeStr = String(code);
  captured.push({ source: 'eval', content: codeStr.substring(0, 50000) });
  extractIOCs(codeStr);
  // Recursively evaluate to catch nested layers
  try {
    return vm.runInContext(codeStr, sandbox, { timeout: 3000 });
  } catch (e) {
    return undefined;
  }
}

// Hooked Function constructor
function hookedFunction() {
  const args = Array.from(arguments);
  const body = args.length > 0 ? String(args[args.length - 1]) : '';
  captured.push({ source: 'Function', content: body.substring(0, 50000) });
  extractIOCs(body);
  return function() {
    try {
      return vm.runInContext(body, sandbox, { timeout: 3000 });
    } catch (e) {
      return undefined;
    }
  };
}

// Hooked setTimeout/setInterval with string argument
function hookedSetTimeout(handler, delay) {
  if (typeof handler === 'string') {
    captured.push({ source: 'setTimeout', content: handler.substring(0, 50000) });
    extractIOCs(handler);
    try {
      vm.runInContext(handler, sandbox, { timeout: 3000 });
    } catch (e) {}
  }
}

function hookedSetInterval(handler, delay) {
  if (typeof handler === 'string') {
    captured.push({ source: 'setInterval', content: handler.substring(0, 50000) });
    extractIOCs(handler);
  }
}

// Hooked XMLHttpRequest
function FakeXHR() {
  this.url = '';
  this.method = '';
}
FakeXHR.prototype.open = function(method, url) {
  this.method = method;
  this.url = url;
  urls.push(url);
  indicators.push('XMLHttpRequest detected: ' + method + ' ' + url);
};
FakeXHR.prototype.send = function() {};
FakeXHR.prototype.setRequestHeader = function() {};

// IOC extraction
function extractIOCs(content) {
  // URLs
  const urlMatches = content.match(/https?:\\/\\/[^\\s'";\`,)\\]>]+/g);
  if (urlMatches) {
    urlMatches.forEach(function(u) { urls.push(u); });
  }
  // IPs
  const ipMatches = content.match(/\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b/g);
  if (ipMatches) {
    ipMatches.forEach(function(ip) {
      const parts = ip.split('.');
      if (parts.every(function(p) { return parseInt(p) >= 0 && parseInt(p) <= 255; })) {
        if (!ip.startsWith('127.') && !ip.startsWith('10.') &&
            !ip.startsWith('192.168.') && !ip.startsWith('0.')) {
          ips.push(ip);
        }
      }
    });
  }
  // Suspicious patterns
  if (/ActiveXObject|WScript\\.Shell|Scripting\\.FileSystemObject/i.test(content)) {
    indicators.push('ActiveX/WSH object creation');
  }
  if (/cmd\\.exe|powershell|wscript|cscript/i.test(content)) {
    indicators.push('Shell command execution reference');
  }
  if (/\\\\x[0-9a-f]{2}/i.test(content) && content.match(/\\\\x[0-9a-f]{2}/gi).length > 20) {
    indicators.push('Heavy hex encoding detected');
  }
}

// Create sandboxed context
const sandbox = vm.createContext({
  eval: hookedEval,
  Function: hookedFunction,
  setTimeout: hookedSetTimeout,
  setInterval: hookedSetInterval,
  clearTimeout: function() {},
  clearInterval: function() {},
  document: fakeDocument,
  window: fakeWindow,
  self: fakeWindow,
  navigator: fakeWindow.navigator,
  location: fakeWindow.location,
  XMLHttpRequest: FakeXHR,
  ActiveXObject: function(name) {
    indicators.push('ActiveXObject created: ' + name);
    return {
      Open: function(m, u) { urls.push(u); },
      Send: function() {},
      ResponseBody: '',
      ResponseText: '',
      Status: 200,
      Run: function(cmd) { indicators.push('WScript.Shell.Run: ' + cmd); },
      Exec: function(cmd) { indicators.push('WScript.Shell.Exec: ' + cmd); },
    };
  },
  WScript: {
    CreateObject: function(name) {
      indicators.push('WScript.CreateObject: ' + name);
      return {};
    },
    Echo: function(msg) { captured.push({ source: 'WScript.Echo', content: String(msg) }); },
    Sleep: function() {},
  },
  console: {
    log: function() {
      const msg = Array.from(arguments).join(' ');
      captured.push({ source: 'console.log', content: msg });
    },
    warn: function() {},
    error: function() {},
  },
  atob: function(str) {
    return Buffer.from(str, 'base64').toString('binary');
  },
  btoa: function(str) {
    return Buffer.from(str, 'binary').toString('base64');
  },
  unescape: unescape,
  decodeURIComponent: decodeURIComponent,
  decodeURI: decodeURI,
  encodeURIComponent: encodeURIComponent,
  parseInt: parseInt,
  parseFloat: parseFloat,
  String: String,
  Number: Number,
  Array: Array,
  Object: Object,
  Math: Math,
  Date: Date,
  RegExp: RegExp,
  JSON: JSON,
  isNaN: isNaN,
  isFinite: isFinite,
  undefined: undefined,
  NaN: NaN,
  Infinity: Infinity,
});

// Execute the script in sandbox
try {
  vm.runInContext(SCRIPT_CONTENT, sandbox, {
    timeout: 10000,
    filename: 'malware_sample.js',
  });
} catch (e) {
  executionError = e.message;
}

// Extract IOCs from original script as well
extractIOCs(SCRIPT_CONTENT);

// Deduplicate
const uniqueUrls = [...new Set(urls)];
const uniqueIPs = [...new Set(ips)];
const uniqueIndicators = [...new Set(indicators)];

// Build IOC list
const iocs = [];
uniqueUrls.forEach(function(u) { iocs.push({ type: 'url', value: u }); });
uniqueIPs.forEach(function(ip) { iocs.push({ type: 'ip', value: ip }); });

// Build layers from captured
const layers = captured.map(function(c, i) {
  return {
    layer: i + 1,
    content: c.content.substring(0, 5000),
    technique: c.source,
  };
});

const result = {
  originalScript: SCRIPT_CONTENT.substring(0, 2000),
  layers: layers,
  finalPayload: captured.length > 0 ? captured[captured.length - 1].content.substring(0, 10000) : SCRIPT_CONTENT.substring(0, 10000),
  iocs: iocs,
  indicators: uniqueIndicators,
  executionError: executionError,
};

process.stdout.write(JSON.stringify(result, null, 2));
`;
}

// ── 3. Office Macro Extraction ─────────────────────────────────────────────────

/**
 * Returns a Python script that extracts and analyzes VBA macros from
 * OLE/OOXML documents (similar to oletools/olevba functionality).
 */
export function getMacroExtractionScript(): string {
  return `#!/usr/bin/env python3
"""
FraudVault Office Macro Extraction Engine
Extracts VBA macros from OLE2/OOXML documents, identifies auto-execution
triggers, deobfuscates basic patterns, and extracts IOCs.
"""

import struct
import zipfile
import re
import json
import sys
import os
from typing import List, Dict, Optional, Tuple

# Auto-execution trigger keywords
AUTO_EXEC_TRIGGERS = [
    'AutoOpen', 'AutoClose', 'AutoNew', 'AutoExec', 'AutoExit',
    'Document_Open', 'Document_Close', 'Document_New',
    'Workbook_Open', 'Workbook_Close', 'Workbook_Activate',
    'Worksheet_Change', 'Worksheet_Activate',
    'Auto_Open', 'Auto_Close',
    'DocumentOpen', 'NewDocument',
    'ThisDocument',
]

# Suspicious VBA functions/patterns
SUSPICIOUS_PATTERNS = [
    (r'Shell\\b', 'Shell command execution'),
    (r'WScript\\.Shell', 'Windows Script Host Shell'),
    (r'Scripting\\.FileSystemObject', 'File system access'),
    (r'MSXML2\\.XMLHTTP|WinHttp', 'HTTP request (download)'),
    (r'ADODB\\.Stream', 'Binary stream (file write)'),
    (r'PowerShell|pwsh', 'PowerShell execution'),
    (r'cmd\\.exe|cmd\\s*/c', 'Command prompt execution'),
    (r'CreateObject', 'COM object creation'),
    (r'GetObject', 'COM object binding'),
    (r'CallByName', 'Dynamic method invocation'),
    (r'Environ\\(', 'Environment variable access'),
    (r'Kill\\s', 'File deletion'),
    (r'FileCopy', 'File copy operation'),
    (r'Open\\s.*For\\s+(?:Output|Binary)', 'File write operation'),
    (r'URLDownloadToFile', 'Direct file download'),
    (r'Lib\\s+"kernel32|Lib\\s+"user32|Lib\\s+"ntdll', 'Windows API call'),
    (r'VirtualAlloc|RtlMoveMemory|CreateThread', 'Shellcode injection pattern'),
    (r'RegWrite|RegRead|RegDelete', 'Registry manipulation'),
]


class OLEParser:
    """Minimal OLE2 Compound File parser for VBA extraction."""

    def __init__(self, data: bytes):
        self.data = data
        self.sector_size = 512
        self.mini_sector_size = 64
        self.fat: List[int] = []
        self.directory: List[Dict[str, object]] = []
        self.mini_fat: List[int] = []
        self.mini_stream = b''

    def parse(self) -> bool:
        """Parse OLE2 header and structures."""
        if len(self.data) < 512:
            return False
        # Check magic number
        magic = self.data[:8]
        if magic != b'\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1':
            return False

        # Parse header
        self.sector_size = 1 << struct.unpack_from('<H', self.data, 30)[0]
        self.mini_sector_size = 1 << struct.unpack_from('<H', self.data, 32)[0]
        fat_sectors_count = struct.unpack_from('<I', self.data, 44)[0]
        first_dir_sector = struct.unpack_from('<I', self.data, 48)[0]
        first_mini_fat_sector = struct.unpack_from('<I', self.data, 60)[0]
        first_difat_sector = struct.unpack_from('<I', self.data, 68)[0]

        # Read DIFAT (first 109 entries are in header)
        difat = []
        for i in range(109):
            sect = struct.unpack_from('<I', self.data, 76 + i * 4)[0]
            if sect < 0xFFFFFFFE:
                difat.append(sect)

        # Build FAT
        for sect in difat:
            offset = (sect + 1) * self.sector_size
            for i in range(self.sector_size // 4):
                if offset + i * 4 + 4 <= len(self.data):
                    val = struct.unpack_from('<I', self.data, offset + i * 4)[0]
                    self.fat.append(val)

        # Read directory
        self._read_directory_chain(first_dir_sector)

        # Read mini FAT
        self._read_mini_fat(first_mini_fat_sector)

        # Get mini stream from root entry
        if self.directory:
            root = self.directory[0]
            start_sect = root.get('start_sector', 0xFFFFFFFE)
            if isinstance(start_sect, int) and start_sect < 0xFFFFFFFE:
                self.mini_stream = self._read_chain(start_sect)

        return True

    def _get_sector_data(self, sector: int) -> bytes:
        """Get data for a given sector."""
        offset = (sector + 1) * self.sector_size
        end = offset + self.sector_size
        if end <= len(self.data):
            return self.data[offset:end]
        return b''

    def _read_chain(self, start_sector: int) -> bytes:
        """Read a chain of sectors following the FAT."""
        result = b''
        current = start_sector
        visited = set()
        while current < 0xFFFFFFFE and current not in visited and len(result) < 10 * 1024 * 1024:
            visited.add(current)
            result += self._get_sector_data(current)
            if current < len(self.fat):
                current = self.fat[current]
            else:
                break
        return result

    def _read_mini_chain(self, start_sector: int, size: int) -> bytes:
        """Read a chain from the mini stream."""
        result = b''
        current = start_sector
        visited = set()
        while current < 0xFFFFFFFE and current not in visited and len(result) < size:
            visited.add(current)
            offset = current * self.mini_sector_size
            end = offset + self.mini_sector_size
            if end <= len(self.mini_stream):
                result += self.mini_stream[offset:end]
            if current < len(self.mini_fat):
                current = self.mini_fat[current]
            else:
                break
        return result[:size]

    def _read_directory_chain(self, start_sector: int) -> None:
        """Read directory entries from sector chain."""
        dir_data = self._read_chain(start_sector)
        entry_size = 128
        for i in range(len(dir_data) // entry_size):
            entry_bytes = dir_data[i * entry_size:(i + 1) * entry_size]
            if len(entry_bytes) < entry_size:
                break
            name_len = struct.unpack_from('<H', entry_bytes, 64)[0]
            if name_len == 0:
                continue
            name = entry_bytes[:name_len].decode('utf-16-le', errors='replace').rstrip('\\x00')
            obj_type = entry_bytes[66]
            start_sector = struct.unpack_from('<I', entry_bytes, 116)[0]
            size = struct.unpack_from('<I', entry_bytes, 120)[0]
            self.directory.append({
                'name': name,
                'type': obj_type,
                'start_sector': start_sector,
                'size': size,
                'index': i,
            })

    def _read_mini_fat(self, start_sector: int) -> None:
        """Read the mini FAT."""
        if start_sector >= 0xFFFFFFFE:
            return
        mini_fat_data = self._read_chain(start_sector)
        for i in range(len(mini_fat_data) // 4):
            val = struct.unpack_from('<I', mini_fat_data, i * 4)[0]
            self.mini_fat.append(val)

    def get_stream(self, entry: Dict[str, object]) -> bytes:
        """Get the data for a directory entry."""
        start = entry.get('start_sector', 0xFFFFFFFE)
        size = entry.get('size', 0)
        if not isinstance(start, int) or not isinstance(size, int):
            return b''
        if start >= 0xFFFFFFFE:
            return b''
        # Mini stream for entries < 4096 bytes
        if size < 4096:
            return self._read_mini_chain(start, size)
        else:
            data = self._read_chain(start)
            return data[:size]

    def find_vba_streams(self) -> List[Tuple[str, bytes]]:
        """Find and return all VBA-related streams."""
        vba_streams = []
        vba_keywords = ['vba', 'macro', 'module', 'thisworkbook', 'thisdocument', 'sheet']
        for entry in self.directory:
            name = str(entry.get('name', ''))
            name_lower = name.lower()
            if any(kw in name_lower for kw in vba_keywords) or entry.get('type') == 2:
                data = self.get_stream(entry)
                if data and len(data) > 0:
                    vba_streams.append((name, data))
        return vba_streams


def extract_vba_from_compressed(data: bytes) -> str:
    """
    Attempt to decompress VBA p-code / compressed source.
    VBA uses a custom compression (MS-OVBA 2.4.1).
    Fallback: extract printable strings.
    """
    # Try to find the VBA source by looking for readable code patterns
    # The compressed format starts with 0x01 signature byte
    if not data:
        return ''

    # Simple approach: extract all printable ASCII sequences
    result = []
    current = []
    for byte in data:
        if 32 <= byte <= 126 or byte in (10, 13, 9):
            current.append(chr(byte))
        else:
            if len(current) > 3:
                result.append(''.join(current))
            current = []
    if len(current) > 3:
        result.append(''.join(current))

    # Filter for VBA-like content
    vba_keywords = ['Sub ', 'Function ', 'Dim ', 'Set ', 'If ', 'End Sub',
                    'End Function', 'Call ', 'For ', 'Next ', 'Do ', 'Loop',
                    'While ', 'Wend', 'Private ', 'Public ', 'Const ']
    code_lines = []
    for segment in result:
        if any(kw in segment for kw in vba_keywords) or len(segment) > 20:
            code_lines.append(segment)

    return '\\n'.join(code_lines)


def extract_macros_from_ooxml(filepath: str) -> List[Dict[str, str]]:
    """Extract VBA macros from OOXML (.docm, .xlsm, .pptm) files."""
    macros = []
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            # Look for vbaProject.bin
            vba_files = [n for n in zf.namelist() if 'vbaproject' in n.lower() or 'vba' in n.lower()]
            for vba_file in vba_files:
                data = zf.read(vba_file)
                # Parse embedded OLE
                ole = OLEParser(data)
                if ole.parse():
                    for name, stream_data in ole.find_vba_streams():
                        code = extract_vba_from_compressed(stream_data)
                        if code.strip():
                            macros.append({'name': name, 'code': code})
    except (zipfile.BadZipFile, Exception) as e:
        pass
    return macros


def extract_macros_from_ole(filepath: str) -> List[Dict[str, str]]:
    """Extract VBA macros from OLE2 (.doc, .xls, .ppt) files."""
    macros = []
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        ole = OLEParser(data)
        if ole.parse():
            for name, stream_data in ole.find_vba_streams():
                code = extract_vba_from_compressed(stream_data)
                if code.strip():
                    macros.append({'name': name, 'code': code})
    except Exception as e:
        pass
    return macros


def deobfuscate_chr_concat(code: str) -> str:
    """Deobfuscate Chr() concatenation patterns."""
    # Pattern: Chr(72) & Chr(101) & Chr(108)...
    chr_pattern = r'Chr\\w?\\((\\d+)\\)'
    matches = re.findall(chr_pattern, code)
    if matches:
        decoded = ''.join(chr(int(m)) for m in matches if 0 < int(m) < 65536)
        # Replace the entire Chr chain
        full_pattern = r'(?:Chr\\w?\\(\\d+\\)\\s*&?\\s*)+'
        code = re.sub(full_pattern, f'"{decoded}"', code)
    return code


def deobfuscate_strreverse(code: str) -> str:
    """Deobfuscate StrReverse() calls."""
    pattern = r'StrReverse\\("([^"]*)"\\)'
    matches = re.findall(pattern, code)
    for match in matches:
        code = code.replace(f'StrReverse("{match}")', f'"{match[::-1]}"')
    return code


def extract_iocs_from_macro(code: str) -> List[Dict[str, str]]:
    """Extract IOCs from macro code."""
    iocs = []
    # URLs
    urls = re.findall(r'https?://[^\\s"&\\']+', code)
    for url in urls:
        iocs.append({'type': 'url', 'value': url})
    # IPs
    ips = re.findall(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', code)
    for ip in ips:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            if not ip.startswith('127.') and not ip.startswith('10.') and not ip.startswith('192.168.'):
                iocs.append({'type': 'ip', 'value': ip})
    # File paths
    paths = re.findall(r'[A-Z]:\\\\[\\\\a-zA-Z0-9_. -]+', code)
    for path in paths:
        iocs.append({'type': 'filepath', 'value': path})
    # Shell commands
    shell_cmds = re.findall(r'Shell\\s*\\(?\\s*"([^"]+)"', code)
    for cmd in shell_cmds:
        iocs.append({'type': 'command', 'value': cmd})
    return iocs


def analyze_macro(code: str) -> Dict[str, object]:
    """Analyze a single macro for threats."""
    # Check auto-execution
    auto_exec = []
    for trigger in AUTO_EXEC_TRIGGERS:
        if trigger.lower() in code.lower():
            auto_exec.append(trigger)

    # Check suspicious patterns
    suspicious = []
    for pattern, description in SUSPICIOUS_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            suspicious.append(description)

    # Deobfuscate
    deobfuscated = deobfuscate_chr_concat(code)
    deobfuscated = deobfuscate_strreverse(deobfuscated)

    # Extract IOCs from both original and deobfuscated
    iocs = extract_iocs_from_macro(code)
    if deobfuscated != code:
        iocs.extend(extract_iocs_from_macro(deobfuscated))

    # Deduplicate IOCs
    seen = set()
    unique_iocs = []
    for ioc in iocs:
        key = f"{ioc['type']}:{ioc['value']}"
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)

    return {
        'autoExecTriggers': auto_exec,
        'suspiciousPatterns': suspicious,
        'deobfuscatedCode': deobfuscated if deobfuscated != code else None,
        'iocs': unique_iocs,
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'Usage: macro_extract.py <filepath>'}))
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(json.dumps({'error': f'File not found: {filepath}'}))
        sys.exit(1)

    # Determine file type
    with open(filepath, 'rb') as f:
        header = f.read(8)

    macros: List[Dict[str, str]] = []

    if header[:4] == b'PK\\x03\\x04':
        # OOXML (ZIP-based)
        macros = extract_macros_from_ooxml(filepath)
    elif header[:8] == b'\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1':
        # OLE2
        macros = extract_macros_from_ole(filepath)
    else:
        print(json.dumps({'error': 'Unknown file format (not OLE2 or OOXML)'}))
        sys.exit(1)

    # Analyze each macro
    results = []
    all_iocs: List[Dict[str, str]] = []
    all_indicators: List[str] = []

    for macro in macros:
        analysis = analyze_macro(macro['code'])
        results.append({
            'moduleName': macro['name'],
            'code': macro['code'][:5000],
            'analysis': analysis,
        })
        all_iocs.extend(analysis.get('iocs', []))
        all_indicators.extend(analysis.get('suspiciousPatterns', []))
        if analysis.get('autoExecTriggers'):
            all_indicators.append(f"Auto-execution: {', '.join(analysis['autoExecTriggers'])}")

    # Deduplicate
    seen_iocs = set()
    unique_iocs = []
    for ioc in all_iocs:
        key = f"{ioc['type']}:{ioc['value']}"
        if key not in seen_iocs:
            seen_iocs.add(key)
            unique_iocs.append(ioc)

    output = {
        'macrosFound': len(macros),
        'macros': results,
        'iocs': unique_iocs,
        'indicators': list(set(all_indicators)),
        'riskLevel': 'high' if all_indicators else ('medium' if macros else 'low'),
    }

    print(json.dumps(output, indent=2, default=str))


if __name__ == '__main__':
    main()
`;
}

// ── 4. .NET Decompilation ──────────────────────────────────────────────────────

/**
 * Returns a bash script that decompiles .NET assemblies using monodis,
 * extracts method names, string literals, embedded resources, and
 * identifies suspicious patterns.
 */
export function getDotNetDecompilationScript(filePath: string): string {
  const escapedPath = filePath.replace(/'/g, "'\\''");

  return `#!/usr/bin/env bash
set -euo pipefail

# FraudVault .NET Decompilation Engine
# Checks for .NET assembly, disassembles with monodis, and extracts indicators.

FILE_PATH='${escapedPath}'
OUTPUT_JSON=""

# Check if file exists
if [ ! -f "$FILE_PATH" ]; then
  echo '{"error": "File not found: '"$FILE_PATH"'"}'
  exit 1
fi

# Check if it's a PE file with CLI header (.NET)
MAGIC=$(xxd -l 2 -p "$FILE_PATH" 2>/dev/null || echo "")
if [ "$MAGIC" != "4d5a" ]; then
  echo '{"error": "Not a PE file (missing MZ header)", "isDotNet": false}'
  exit 0
fi

# Check for .NET CLI header marker
# The PE optional header data directory entry 14 (CLI Header) should be non-zero
IS_DOTNET=false
if command -v monodis &>/dev/null; then
  # Try monodis - if it succeeds, it's .NET
  if monodis --help &>/dev/null 2>&1 || true; then
    MONO_OUTPUT=$(monodis "$FILE_PATH" 2>/dev/null) && IS_DOTNET=true || IS_DOTNET=false
  fi
elif command -v ilspycmd &>/dev/null; then
  MONO_OUTPUT=$(ilspycmd "$FILE_PATH" 2>/dev/null) && IS_DOTNET=true || IS_DOTNET=false
fi

# Fallback: use strings + pattern matching
if [ "$IS_DOTNET" = false ]; then
  # Check for .NET metadata signatures in file
  if grep -q "mscoree.dll\\|_CorExeMain\\|System.Runtime\\|mscorlib" "$FILE_PATH" 2>/dev/null; then
    IS_DOTNET=true
    MONO_OUTPUT=""
  else
    echo '{"error": "Not a .NET assembly or decompiler not available", "isDotNet": false}'
    exit 0
  fi
fi

# Create temp directory for output
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Extract strings
strings -n 6 "$FILE_PATH" > "$TMPDIR/all_strings.txt" 2>/dev/null || true

# Extract method names (from monodis IL or strings)
METHOD_NAMES="[]"
if [ -n "$MONO_OUTPUT" ]; then
  echo "$MONO_OUTPUT" > "$TMPDIR/il_output.txt"
  # Extract .method directives
  METHOD_NAMES=$(grep -oP '\.method\s+.*?\s+(\w+)\s*\(' "$TMPDIR/il_output.txt" 2>/dev/null | \
    awk -F'(' '{print $1}' | awk '{print $NF}' | sort -u | head -100 | \
    python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")
fi

# Extract string literals (quoted strings from IL or binary)
STRING_LITERALS=$(grep -oP '"[^"]{4,200}"' "$TMPDIR/all_strings.txt" 2>/dev/null | \
  sort -u | head -50 | \
  python3 -c "import sys,json; print(json.dumps([l.strip().strip('\"') for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")

# Extract interesting strings
URLS=$(grep -oP 'https?://[^\s"'"'"';<>]+' "$TMPDIR/all_strings.txt" 2>/dev/null | sort -u | head -20 | \
  python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")

IPS=$(grep -oP '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' "$TMPDIR/all_strings.txt" 2>/dev/null | \
  grep -v '^127\.\|^10\.\|^192\.168\.\|^0\.' | sort -u | head -20 | \
  python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")

# Identify suspicious .NET patterns
SUSPICIOUS_PATTERNS="[]"
SUSPICIOUS_FOUND=""

check_pattern() {
  local pattern="$1"
  local desc="$2"
  if grep -qi "$pattern" "$TMPDIR/all_strings.txt" 2>/dev/null; then
    SUSPICIOUS_FOUND="$SUSPICIOUS_FOUND|$desc"
  fi
}

check_pattern "Process.Start\|ProcessStartInfo" "Process execution"
check_pattern "WebClient\|HttpClient\|WebRequest" "Network download capability"
check_pattern "Reflection.Assembly\|Assembly.Load" "Reflective loading"
check_pattern "VirtualAlloc\|VirtualProtect\|Marshal.Copy" "Memory manipulation"
check_pattern "CreateThread\|Thread.Start" "Thread creation"
check_pattern "Registry\|RegistryKey" "Registry access"
check_pattern "Cryptography\|AesCryptoServiceProvider\|RijndaelManaged" "Cryptographic operations"
check_pattern "Socket\|TcpClient\|UdpClient" "Raw network socket usage"
check_pattern "Invoke\|DynamicInvoke\|MethodInfo" "Reflection/dynamic invocation"
check_pattern "GetProcAddress\|LoadLibrary\|DllImport" "Native interop (P/Invoke)"
check_pattern "Credentials\|NetworkCredential\|CredentialCache" "Credential access"
check_pattern "ServiceBase\|InstallUtil" "Service installation"
check_pattern "RunPE\|Hollowing\|NtUnmapViewOfSection" "Process hollowing"

if [ -n "$SUSPICIOUS_FOUND" ]; then
  SUSPICIOUS_PATTERNS=$(echo "$SUSPICIOUS_FOUND" | tr '|' '\n' | grep -v '^$' | sort -u | \
    python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")
fi

# Extract embedded resource names
RESOURCES="[]"
if [ -n "$MONO_OUTPUT" ]; then
  RESOURCES=$(grep -oP '\.mresource\s+.*?\s+(\S+)' "$TMPDIR/il_output.txt" 2>/dev/null | \
    awk '{print $NF}' | sort -u | head -20 | \
    python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")
fi

# Extract referenced assemblies
REFERENCES="[]"
if [ -n "$MONO_OUTPUT" ]; then
  REFERENCES=$(grep -oP '\.assembly\s+extern\s+\S+' "$TMPDIR/il_output.txt" 2>/dev/null | \
    awk '{print $NF}' | sort -u | head -30 | \
    python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")
fi

# Build JSON output — write data to files to avoid shell variable injection
echo "$METHOD_NAMES" > "$TMPDIR/method_names.json"
echo "$STRING_LITERALS" > "$TMPDIR/string_literals.json"
echo "$URLS" > "$TMPDIR/urls.json"
echo "$IPS" > "$TMPDIR/ips.json"
echo "$SUSPICIOUS_PATTERNS" > "$TMPDIR/suspicious_patterns.json"
echo "$RESOURCES" > "$TMPDIR/resources.json"
echo "$REFERENCES" > "$TMPDIR/references.json"

export SCANBOY_TMPDIR="$TMPDIR"
export SCANBOY_FILEPATH="$FILE_PATH"
python3 << 'PYEOF'
import json, os
tmpdir = os.environ['SCANBOY_TMPDIR']
file_path = os.environ['SCANBOY_FILEPATH']

def load(name):
    try:
        with open(os.path.join(tmpdir, name)) as f:
            return json.loads(f.read().strip())
    except:
        return []

il_text = ""
il_path = os.path.join(tmpdir, "il_output.txt")
if os.path.exists(il_path):
    with open(il_path) as f:
        il_text = f.read()[:20000]

result = {
    "isDotNet": True,
    "filePath": file_path,
    "methodNames": load("method_names.json"),
    "stringLiterals": load("string_literals.json"),
    "urls": load("urls.json"),
    "ips": load("ips.json"),
    "suspiciousPatterns": load("suspicious_patterns.json"),
    "embeddedResources": load("resources.json"),
    "referencedAssemblies": load("references.json"),
    "ilDisassembly": il_text,
}
print(json.dumps(result, indent=2))
PYEOF
`;
}

// ── 5. Auto YARA Rule Generation ───────────────────────────────────────────────

/**
 * Generates a YARA rule from sample analysis results that uniquely identifies
 * the given sample based on strings, imports, sections, and file characteristics.
 */
export function generateYaraRuleFromSample(
  filename: string,
  sha256: string,
  uniqueStrings: string[],
  imports: string[],
  sections: SectionInfo[],
  fileSize: number,
): GeneratedYaraRule {
  // Sanitize the filename for use as a YARA rule name
  const ruleName = filename
    .replace(/[^a-zA-Z0-9_]/g, '_')
    .replace(/^[0-9]/, '_$&')
    .replace(/__+/g, '_')
    .substring(0, 50);

  const today = new Date().toISOString().split('T')[0];

  // Select the best 3-5 unique strings (prioritize longer, more specific strings)
  const selectedStrings = selectUniqueStrings(uniqueStrings, 5);

  // Select suspicious imports (not common runtime imports)
  const suspiciousImports = filterSuspiciousImports(imports);
  const selectedImports = suspiciousImports.slice(0, 3);

  // Determine file size condition (allow +/- 20% variance)
  const _minSize = Math.max(0, Math.floor(fileSize * 0.8)); void _minSize;
  const maxSize = Math.ceil(fileSize * 1.2);
  const fileSizeCondition = formatFileSize(maxSize);

  // Identify high-entropy sections (possibly packed). >7.7 discriminates from normal PEs.
  const highEntropySections = sections.filter((s) => s.entropy > 7.7);
  const hasPacking = highEntropySections.length > 0;

  // Build meta section
  const metaLines: string[] = [
    `        author = "FraudVault Auto-Generated"`,
    `        date = "${today}"`,
    `        sha256 = "${sha256}"`,
    `        description = "Auto-generated rule for ${sanitizeYaraString(filename)}"`,
  ];

  if (hasPacking) {
    metaLines.push(`        packed = "true"`);
  }

  // Build strings section
  const stringLines: string[] = [];
  selectedStrings.forEach((str, idx) => {
    const escaped = sanitizeYaraString(str);
    if (isHexPattern(str)) {
      stringLines.push(`        $s${idx + 1} = { ${toYaraHex(str)} }`);
    } else {
      stringLines.push(`        $s${idx + 1} = "${escaped}" ascii wide`);
    }
  });

  selectedImports.forEach((imp, idx) => {
    stringLines.push(`        $import${idx + 1} = "${sanitizeYaraString(imp)}" ascii`);
  });

  // Build condition
  const conditions: string[] = [];

  // PE header check
  conditions.push('uint16(0) == 0x5A4D');

  // File size constraint
  conditions.push(`filesize < ${fileSizeCondition}`);

  // String matching (require majority)
  const totalStrings = selectedStrings.length;
  if (totalStrings > 0) {
    const requiredCount = Math.max(2, Math.ceil(totalStrings * 0.6));
    conditions.push(`${requiredCount} of ($s*)`);
  }

  // Import matching
  if (selectedImports.length > 0) {
    if (selectedImports.length === 1) {
      conditions.push('$import1');
    } else {
      conditions.push(`${Math.min(2, selectedImports.length)} of ($import*)`);
    }
  }

  // Section-based conditions for packed samples
  if (hasPacking) {
    const packedSection = highEntropySections[0];
    if (packedSection!.name === 'UPX0' || packedSection!.name === 'UPX1') {
      stringLines.push(`        $upx = "UPX" ascii`);
      conditions.push('$upx');
    }
  }

  // Assemble the rule
  const rule = [
    `rule ${ruleName}_Gen {`,
    `    meta:`,
    ...metaLines,
    `    strings:`,
    ...stringLines,
    `    condition:`,
    `        ${conditions.join(' and\n        ')}`,
    `}`,
  ].join('\n');

  // Calculate confidence based on quality of indicators
  const confidence = calculateConfidence(selectedStrings, selectedImports, sections, fileSize);

  return {
    name: `${ruleName}_Gen`,
    description: `Auto-generated YARA rule for ${filename} (SHA256: ${sha256.substring(0, 16)}...)`,
    rule,
    confidence,
  };
}

// ── 6. Auto Snort/Suricata Rule Generation ─────────────────────────────────────

/**
 * Generates IDS rules (Suricata and Snort format) from observed network
 * activity including DNS queries, HTTP requests, and connections.
 */
export function generateNetworkRules(
  dnsQueries: DnsQueryEntry[],
  httpRequests: HttpRequestEntry[],
  connections: ConnectionEntry[],
): NetworkRules {
  const suricataRules: string[] = [];
  const snortRules: string[] = [];
  let sidCounter = 9000001;

  // Generate DNS rules
  for (const query of dnsQueries) {
    const domain = sanitizeRuleContent(query.domain);
    if (!domain || isCommonDomain(domain)) {
      continue;
    }

    const suricataRule = [
      'alert dns $HOME_NET any -> any any',
      `(msg:"FraudVault - Malicious DNS Query [${domain}]";`,
      `dns.query; content:"${domain}"; nocase;`,
      `sid:${sidCounter}; rev:1;)`,
    ].join(' ');
    suricataRules.push(suricataRule);

    const snortRule = [
      'alert udp $HOME_NET any -> any 53',
      `(msg:"FraudVault - Malicious DNS Query [${domain}]";`,
      `content:"|01 00 00 01|"; depth:4; offset:2;`,
      `content:"${domain}"; nocase;`,
      `sid:${sidCounter}; rev:1;)`,
    ].join(' ');
    snortRules.push(snortRule);

    sidCounter++;
  }

  // Generate HTTP rules
  for (const req of httpRequests) {
    const host = sanitizeRuleContent(req.host);
    const uri = sanitizeRuleContent(req.uri);
    const method = req.method.toUpperCase();

    if (!host || isCommonDomain(host)) {
      continue;
    }

    // Suricata HTTP rule
    const suricataParts: string[] = [
      'alert http $HOME_NET any -> $EXTERNAL_NET any',
      `(msg:"FraudVault - Malicious HTTP ${method} [${host}${uri}]";`,
    ];

    suricataParts.push(`content:"${method}"; http_method;`);

    if (host) {
      suricataParts.push(`content:"${host}"; http_host;`);
    }

    if (uri && uri !== '/') {
      suricataParts.push(`content:"${uri}"; http_uri;`);
    }

    if (req.userAgent) {
      const ua = sanitizeRuleContent(req.userAgent);
      if (ua && !isCommonUserAgent(ua)) {
        suricataParts.push(`content:"${ua}"; http_user_agent;`);
      }
    }

    suricataParts.push(`sid:${sidCounter}; rev:1;)`);
    suricataRules.push(suricataParts.join(' '));

    // Snort HTTP rule
    const snortParts: string[] = [
      'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS',
      `(msg:"FraudVault - Malicious HTTP ${method} [${host}${uri}]";`,
      `content:"${method}"; http_method;`,
    ];

    if (host) {
      snortParts.push(`content:"${host}"; http_header;`);
    }

    if (uri && uri !== '/') {
      snortParts.push(`content:"${uri}"; http_uri;`);
    }

    snortParts.push(`sid:${sidCounter}; rev:1;)`);
    snortRules.push(snortParts.join(' '));

    sidCounter++;
  }

  // Generate connection-based rules (for non-HTTP, non-DNS traffic)
  for (const conn of connections) {
    const ip = conn.ip;
    const port = conn.port;
    const protocol = conn.protocol.toLowerCase();

    // Skip common ports and private IPs
    if (isPrivateIP(ip) || isCommonPort(port)) {
      continue;
    }

    const protoKeyword = protocol === 'udp' ? 'udp' : 'tcp';

    const suricataRule = [
      `alert ${protoKeyword} $HOME_NET any -> ${ip} ${port}`,
      `(msg:"FraudVault - Suspicious Outbound Connection [${ip}:${port}]";`,
      `flow:to_server,established;`,
      `sid:${sidCounter}; rev:1;)`,
    ].join(' ');
    suricataRules.push(suricataRule);

    const snortRule = [
      `alert ${protoKeyword} $HOME_NET any -> ${ip} ${port}`,
      `(msg:"FraudVault - Suspicious Outbound Connection [${ip}:${port}]";`,
      `flags:S;`,
      `sid:${sidCounter}; rev:1;)`,
    ].join(' ');
    snortRules.push(snortRule);

    sidCounter++;
  }

  return {
    suricata: suricataRules,
    snort: snortRules,
  };
}

// ── Helper Functions ───────────────────────────────────────────────────────────

/** Common library strings to exclude from YARA rules */
const COMMON_STRINGS = new Set([
  'kernel32.dll',
  'ntdll.dll',
  'user32.dll',
  'advapi32.dll',
  'msvcrt.dll',
  'GetProcAddress',
  'LoadLibraryA',
  'VirtualAlloc',
  'ExitProcess',
  'GetModuleHandle',
  'This program cannot be run in DOS mode',
  'Rich',
  '.text',
  '.data',
  '.rdata',
  '.rsrc',
  '.reloc',
]);

/** Common imports that are too generic for YARA rules */
const COMMON_IMPORTS = new Set([
  'kernel32.dll',
  'ntdll.dll',
  'user32.dll',
  'gdi32.dll',
  'advapi32.dll',
  'msvcrt.dll',
  'ole32.dll',
  'oleaut32.dll',
  'shell32.dll',
  'comctl32.dll',
  'comdlg32.dll',
  'ws2_32.dll',
  'msvcp140.dll',
  'vcruntime140.dll',
  'ucrtbase.dll',
  'api-ms-win-crt-runtime-l1-1-0.dll',
]);

/** Domains that should not trigger IDS rules */
const COMMON_DOMAINS = new Set([
  'google.com',
  'microsoft.com',
  'windows.com',
  'windowsupdate.com',
  'office.com',
  'live.com',
  'bing.com',
  'msn.com',
  'akamai.net',
  'cloudflare.com',
  'amazonaws.com',
  'github.com',
  'apple.com',
  'mozilla.org',
  'w3.org',
]);

function selectUniqueStrings(strings: string[], maxCount: number): string[] {
  // Filter out common strings and sort by uniqueness (length, specificity)
  const filtered = strings.filter((s) => {
    const lower = s.toLowerCase();
    if (COMMON_STRINGS.has(s) || COMMON_STRINGS.has(lower)) return false;
    if (s.length < 4) return false;
    if (s.length > 200) return false;
    // Skip strings that are all whitespace or all dots
    if (/^[\s.]+$/.test(s)) return false;
    return true;
  });

  // Score strings by uniqueness
  const scored = filtered.map((s) => ({
    value: s,
    score: calculateStringScore(s),
  }));

  // Sort by score descending and take top N
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, maxCount).map((s) => s.value);
}

function calculateStringScore(s: string): number {
  let score = 0;
  // Longer strings are more specific
  score += Math.min(s.length, 50) * 2;
  // Strings with mixed case
  if (/[A-Z]/.test(s) && /[a-z]/.test(s)) score += 10;
  // Strings with special characters (more unique)
  if (/[{}()\[\]@#$%^&]/.test(s)) score += 15;
  // Strings that look like URLs or paths
  if (/https?:\/\//.test(s)) score += 20;
  if (/[A-Z]:\\/.test(s)) score += 15;
  // Ransom notes, C2 markers
  if (/encrypt|ransom|bitcoin|wallet|victim|decrypt/i.test(s)) score += 30;
  // Avoid purely numeric strings
  if (/^\d+$/.test(s)) score -= 20;
  return score;
}

function filterSuspiciousImports(imports: string[]): string[] {
  return imports.filter((imp) => {
    const lower = imp.toLowerCase();
    if (COMMON_IMPORTS.has(lower)) return false;
    // Keep DLLs that are unusual/suspicious
    return true;
  });
}

function formatFileSize(bytes: number): string {
  if (bytes >= 1024 * 1024) {
    return `${Math.ceil(bytes / (1024 * 1024))}MB`;
  }
  if (bytes >= 1024) {
    return `${Math.ceil(bytes / 1024)}KB`;
  }
  return `${bytes}`;
}

function sanitizeYaraString(s: string): string {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
}

function isHexPattern(s: string): boolean {
  // Check if the string is primarily non-printable bytes
  const nonPrintable = [...s].filter(
    (c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) > 126,
  ).length;
  return nonPrintable > s.length * 0.5;
}

function toYaraHex(s: string): string {
  return [...s]
    .map((c) => c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

function calculateConfidence(
  strings: string[],
  imports: string[],
  sections: SectionInfo[],
  fileSize: number,
): number {
  let confidence = 0.3; // Base confidence

  // More unique strings = higher confidence
  if (strings.length >= 3) confidence += 0.2;
  if (strings.length >= 5) confidence += 0.1;

  // Suspicious imports boost confidence
  if (imports.length >= 1) confidence += 0.1;
  if (imports.length >= 2) confidence += 0.1;

  // Non-standard sections
  const standardSections = new Set(['.text', '.data', '.rdata', '.rsrc', '.reloc', '.bss']);
  const unusualSections = sections.filter((s) => !standardSections.has(s.name));
  if (unusualSections.length > 0) confidence += 0.1;

  // Very small or very large files are more distinctive
  if (fileSize < 10240 || fileSize > 10 * 1024 * 1024) confidence += 0.05;

  // High entropy sections (packed) are distinctive. >7.7 avoids FPs on normal PEs.
  const packed = sections.filter((s) => s.entropy > 7.7);
  if (packed.length > 0) confidence += 0.05;

  return Math.min(confidence, 1.0);
}

function sanitizeRuleContent(s: string): string {
  return s
    .replace(/"/g, '')
    .replace(/;/g, '')
    .replace(/\(/g, '')
    .replace(/\)/g, '')
    .replace(/\\/g, '/')
    .replace(/\|/g, '')
    .replace(/[\r\n]/g, '')
    .trim();
}

function isCommonDomain(domain: string): boolean {
  const lower = domain.toLowerCase();
  for (const common of COMMON_DOMAINS) {
    if (lower === common || lower.endsWith(`.${common}`)) {
      return true;
    }
  }
  return false;
}

function isCommonUserAgent(ua: string): boolean {
  // Very common user agents that would cause too many false positives
  const common = [
    'Mozilla/5.0',
    'Chrome/',
    'Firefox/',
    'Safari/',
    'Edge/',
    'MSIE',
  ];
  return common.some((c) => ua.includes(c)) && ua.length > 50;
}

function isPrivateIP(ip: string): boolean {
  if (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('127.') ||
    ip.startsWith('0.') ||
    ip === '255.255.255.255'
  ) {
    return true;
  }
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1] ?? '', 10);
    return second >= 16 && second <= 31;
  }
  return false;
}

function isCommonPort(port: number): boolean {
  const common = new Set([80, 443, 53, 8080, 8443]);
  return common.has(port);
}
