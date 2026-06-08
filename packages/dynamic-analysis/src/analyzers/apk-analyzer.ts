// ── Mobile APK Analysis ─────────────────────────────────────────────────────
//
// Static analysis of Android APK packages: extracts manifest data, permissions,
// components, certificates, and scans for suspicious indicators and IOCs.

// ── Result Types ────────────────────────────────────────────────────────────

export interface ApkAnalysisResult {
  packageName: string;
  versionName: string;
  versionCode: number;
  minSdkVersion: number;
  targetSdkVersion: number;
  permissions: string[];
  dangerousPermissions: string[];
  activities: string[];
  services: string[];
  receivers: string[];
  providers: string[];
  nativeLibraries: string[];
  certificates: Array<{ issuer: string; subject: string; sha256: string }>;
  suspiciousIndicators: Array<{ category: string; description: string; severity: SeverityLevel }>;
  urls: string[];
  ips: string[];
  hardcodedSecrets: string[];
}

export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

// ── Dangerous Permission Patterns ───────────────────────────────────────────

interface DangerousPermissionPattern {
  permission: string;
  category: string;
  description: string;
  severity: SeverityLevel;
}

const DANGEROUS_PERMISSION_PATTERNS: readonly DangerousPermissionPattern[] = [
  // Banking Trojan indicators
  { permission: 'android.permission.READ_SMS', category: 'banking_trojan', description: 'Can read SMS messages (OTP interception)', severity: 'high' },
  { permission: 'android.permission.SEND_SMS', category: 'banking_trojan', description: 'Can send SMS messages (premium SMS fraud)', severity: 'high' },
  { permission: 'android.permission.RECEIVE_SMS', category: 'banking_trojan', description: 'Can intercept incoming SMS (OTP theft)', severity: 'high' },
  // Spyware indicators
  { permission: 'android.permission.RECORD_AUDIO', category: 'spyware', description: 'Can record audio from microphone', severity: 'high' },
  { permission: 'android.permission.CAMERA', category: 'spyware', description: 'Can access device camera', severity: 'high' },
  { permission: 'android.permission.ACCESS_FINE_LOCATION', category: 'spyware', description: 'Can track precise GPS location', severity: 'medium' },
  { permission: 'android.permission.READ_CONTACTS', category: 'spyware', description: 'Can read contact list', severity: 'medium' },
  { permission: 'android.permission.READ_CALL_LOG', category: 'spyware', description: 'Can read call history', severity: 'high' },
  // Overlay attacks
  { permission: 'android.permission.BIND_ACCESSIBILITY_SERVICE', category: 'overlay_attack', description: 'Accessibility service abuse for credential theft', severity: 'critical' },
  { permission: 'android.permission.SYSTEM_ALERT_WINDOW', category: 'overlay_attack', description: 'Can draw overlays on other apps (phishing)', severity: 'high' },
  // Device admin / lockout
  { permission: 'android.permission.BIND_DEVICE_ADMIN', category: 'device_admin', description: 'Device admin access (device lockout/wipe)', severity: 'critical' },
  // Dropper
  { permission: 'android.permission.INSTALL_PACKAGES', category: 'dropper', description: 'Can install additional packages (second-stage dropper)', severity: 'critical' },
  { permission: 'android.permission.REQUEST_INSTALL_PACKAGES', category: 'dropper', description: 'Can request package installation', severity: 'high' },
  { permission: 'android.permission.DELETE_PACKAGES', category: 'dropper', description: 'Can delete packages (uninstall security apps)', severity: 'high' },
  // Persistence
  { permission: 'android.permission.RECEIVE_BOOT_COMPLETED', category: 'persistence', description: 'Auto-starts on device boot', severity: 'medium' },
  { permission: 'android.permission.WAKE_LOCK', category: 'persistence', description: 'Prevents device from sleeping', severity: 'low' },
  // Network
  { permission: 'android.permission.READ_PHONE_STATE', category: 'fingerprinting', description: 'Can read IMEI, phone number, carrier info', severity: 'medium' },
  { permission: 'android.permission.CHANGE_WIFI_STATE', category: 'network_manipulation', description: 'Can modify WiFi connections', severity: 'medium' },
] as const;

// ── Secret Detection Patterns ───────────────────────────────────────────────

/** Regex patterns used to detect hardcoded secrets in APK files. Exported for testing. */
export const _SECRET_PATTERNS: readonly RegExp[] = [
  /AIza[0-9A-Za-z_-]{35}/,                    // Google API Key
  /AKIA[0-9A-Z]{16}/,                          // AWS Access Key ID
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i,  // UUID-style tokens
  /sk_live_[0-9a-zA-Z]{24,}/,                  // Stripe Secret Key
  /ghp_[0-9a-zA-Z]{36}/,                       // GitHub Personal Access Token
  /-----BEGIN (?:RSA )?PRIVATE KEY-----/,       // Private Keys
  /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\./,   // JWT Tokens
  /firebase[A-Za-z0-9.:/\-_]{20,}/i,           // Firebase URLs
  /[a-zA-Z0-9_]+:\/\/[^:]+:[^@]+@/,            // Connection strings with credentials
];

// ── Python Analysis Script ──────────────────────────────────────────────────

/**
 * Returns a Python script that performs comprehensive APK analysis.
 * The script uses only standard library modules (zipfile, struct, xml.etree)
 * plus basic binary XML parsing for AndroidManifest.xml.
 */
export function getApkAnalysisScript(): string {
  return `#!/usr/bin/env python3
"""
FraudVault APK Analyzer
Extracts metadata, permissions, components, and scans for IOCs in Android APK files.
Uses only standard library modules for portability.
"""

import json
import os
import re
import struct
import sys
import hashlib
import zipfile
from xml.etree import ElementTree

# ── Binary XML Parser (Android's AXML format) ────────────────────────────────

# Android binary XML chunk types
CHUNK_AXML_FILE = 0x00080003
CHUNK_STRING_POOL = 0x001C0001
CHUNK_RESOURCE_MAP = 0x00080180
CHUNK_START_NAMESPACE = 0x00100100
CHUNK_END_NAMESPACE = 0x00100101
CHUNK_START_TAG = 0x00100102
CHUNK_END_TAG = 0x00100103
CHUNK_TEXT = 0x00100104

# Attribute value types
TYPE_NULL = 0
TYPE_REFERENCE = 1
TYPE_ATTRIBUTE = 2
TYPE_STRING = 3
TYPE_FLOAT = 4
TYPE_DIMENSION = 5
TYPE_FRACTION = 6
TYPE_INT_DEC = 16
TYPE_INT_HEX = 17
TYPE_INT_BOOLEAN = 18

def parse_binary_xml(data):
    """Parse Android binary XML format and extract manifest information."""
    result = {
        'package': '',
        'version_name': '',
        'version_code': 0,
        'min_sdk': 0,
        'target_sdk': 0,
        'permissions': [],
        'activities': [],
        'services': [],
        'receivers': [],
        'providers': [],
    }

    if len(data) < 8:
        return result

    # Parse string pool
    strings = []
    offset = 0

    magic, file_size = struct.unpack_from('<HH', data, 0)
    offset = 8  # Skip file header

    # Find and parse string pool
    if offset + 8 <= len(data):
        chunk_type, chunk_size = struct.unpack_from('<I I', data, offset)
        if chunk_type == CHUNK_STRING_POOL:
            strings = parse_string_pool(data, offset, chunk_size)
            offset += chunk_size

    # Skip resource map if present
    if offset + 8 <= len(data):
        chunk_type, chunk_size = struct.unpack_from('<I I', data, offset)
        if chunk_type == CHUNK_RESOURCE_MAP:
            offset += chunk_size

    # Parse XML nodes
    current_tag = ''
    in_manifest = False

    while offset + 8 <= len(data):
        chunk_type, chunk_size = struct.unpack_from('<I I', data, offset)

        if chunk_size < 8 or offset + chunk_size > len(data):
            break

        if chunk_type == CHUNK_START_TAG:
            if offset + 28 <= len(data):
                ns_idx, name_idx = struct.unpack_from('<i i', data, offset + 8 + 8)
                attr_count = struct.unpack_from('<H', data, offset + 8 + 20)[0]

                tag_name = get_string(strings, name_idx)
                current_tag = tag_name

                if tag_name == 'manifest':
                    in_manifest = True
                    attrs = parse_attributes(data, offset + 36, attr_count, strings)
                    result['package'] = attrs.get('package', '')
                    vc = attrs.get('versionCode', '0')
                    result['version_code'] = int(vc) if vc.isdigit() else 0
                    result['version_name'] = attrs.get('versionName', '')

                elif tag_name == 'uses-sdk':
                    attrs = parse_attributes(data, offset + 36, attr_count, strings)
                    ms = attrs.get('minSdkVersion', '0')
                    ts = attrs.get('targetSdkVersion', '0')
                    result['min_sdk'] = int(ms) if ms.isdigit() else 0
                    result['target_sdk'] = int(ts) if ts.isdigit() else 0

                elif tag_name == 'uses-permission':
                    attrs = parse_attributes(data, offset + 36, attr_count, strings)
                    perm = attrs.get('name', '')
                    if perm:
                        result['permissions'].append(perm)

                elif tag_name == 'activity':
                    attrs = parse_attributes(data, offset + 36, attr_count, strings)
                    name = attrs.get('name', '')
                    if name:
                        result['activities'].append(name)

                elif tag_name == 'service':
                    attrs = parse_attributes(data, offset + 36, attr_count, strings)
                    name = attrs.get('name', '')
                    if name:
                        result['services'].append(name)

                elif tag_name == 'receiver':
                    attrs = parse_attributes(data, offset + 36, attr_count, strings)
                    name = attrs.get('name', '')
                    if name:
                        result['receivers'].append(name)

                elif tag_name == 'provider':
                    attrs = parse_attributes(data, offset + 36, attr_count, strings)
                    name = attrs.get('name', '')
                    if name:
                        result['providers'].append(name)

        offset += chunk_size

    return result


def parse_string_pool(data, pool_offset, pool_size):
    """Parse AXML string pool and return list of strings."""
    strings = []
    if pool_offset + 28 > len(data):
        return strings

    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        '<I I I I I', data, pool_offset + 8
    )

    is_utf8 = (flags & (1 << 8)) != 0
    offsets_start = pool_offset + 28

    for i in range(min(string_count, 10000)):
        if offsets_start + i * 4 + 4 > len(data):
            break
        str_offset = struct.unpack_from('<I', data, offsets_start + i * 4)[0]
        abs_offset = pool_offset + strings_start + str_offset

        if abs_offset >= len(data):
            strings.append('')
            continue

        try:
            if is_utf8:
                # UTF-8: skip char count byte(s), read byte count, then string bytes
                char_len = data[abs_offset]
                abs_offset += 2 if char_len & 0x80 else 1
                byte_len = data[abs_offset]
                abs_offset += 2 if byte_len & 0x80 else 1
                end = abs_offset + byte_len
                if end <= len(data):
                    strings.append(data[abs_offset:end].decode('utf-8', errors='replace'))
                else:
                    strings.append('')
            else:
                # UTF-16: 2-byte length, then UTF-16LE string
                if abs_offset + 2 > len(data):
                    strings.append('')
                    continue
                str_len = struct.unpack_from('<H', data, abs_offset)[0]
                abs_offset += 2
                end = abs_offset + str_len * 2
                if end <= len(data):
                    strings.append(data[abs_offset:end].decode('utf-16-le', errors='replace'))
                else:
                    strings.append('')
        except (IndexError, struct.error, UnicodeDecodeError):
            strings.append('')

    return strings


def parse_attributes(data, offset, count, strings):
    """Parse tag attributes and return dict of name->value."""
    attrs = {}
    for i in range(min(count, 50)):
        attr_offset = offset + i * 20
        if attr_offset + 20 > len(data):
            break
        ns_idx, name_idx, raw_value_idx, typed_value_size, typed_value_type, typed_value_data = struct.unpack_from(
            '<i i i H B x I', data, attr_offset
        )

        attr_name = get_string(strings, name_idx)

        if typed_value_type == TYPE_STRING:
            attr_value = get_string(strings, typed_value_data)
        elif typed_value_type in (TYPE_INT_DEC, TYPE_INT_HEX):
            attr_value = str(typed_value_data)
        elif typed_value_type == TYPE_INT_BOOLEAN:
            attr_value = 'true' if typed_value_data != 0 else 'false'
        elif typed_value_type == TYPE_REFERENCE:
            attr_value = f'@0x{typed_value_data:08x}'
        else:
            attr_value = get_string(strings, raw_value_idx) if raw_value_idx >= 0 else str(typed_value_data)

        if attr_name:
            attrs[attr_name] = attr_value

    return attrs


def get_string(strings, idx):
    """Safely get a string from the pool by index."""
    if 0 <= idx < len(strings):
        return strings[idx]
    return ''


# ── Certificate Analysis ─────────────────────────────────────────────────────

def analyze_certificates(apk_path):
    """Extract certificate information from APK signing block."""
    certs = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                if name.startswith('META-INF/') and (name.endswith('.RSA') or name.endswith('.DSA') or name.endswith('.EC')):
                    cert_data = zf.read(name)
                    sha256 = hashlib.sha256(cert_data).hexdigest()
                    # Basic extraction - full X.509 parsing requires cryptography lib
                    certs.append({
                        'issuer': f'META-INF/{os.path.basename(name)}',
                        'subject': f'signing-cert-{len(certs)}',
                        'sha256': sha256,
                    })
    except Exception:
        pass
    return certs


# ── IOC Extraction ───────────────────────────────────────────────────────────

URL_PATTERN = re.compile(r'https?://[\\w\\-._~:/?#\\[\\]@!$&\\'()*+,;=%]+', re.IGNORECASE)
IP_PATTERN = re.compile(r'\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b')

SECRET_PATTERNS_PY = [
    re.compile(r'AIza[0-9A-Za-z_\\-]{35}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    re.compile(r'ghp_[0-9a-zA-Z]{36}'),
    re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
    re.compile(r'firebase[A-Za-z0-9.:/\\-_]{20,}', re.IGNORECASE),
]


def scan_for_iocs(apk_path):
    """Scan APK contents for URLs, IPs, and hardcoded secrets."""
    urls = set()
    ips = set()
    secrets = set()

    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                # Skip binary resource files and large files
                if name.endswith(('.png', '.jpg', '.gif', '.webp', '.mp3', '.ogg')):
                    continue

                info = zf.getinfo(name)
                if info.file_size > 5 * 1024 * 1024:  # Skip files > 5MB
                    continue

                try:
                    content = zf.read(name)
                    # Try to decode as text
                    try:
                        text = content.decode('utf-8', errors='ignore')
                    except Exception:
                        text = content.decode('latin-1', errors='ignore')

                    # Find URLs
                    for match in URL_PATTERN.finditer(text):
                        url = match.group(0)
                        if len(url) < 500:
                            urls.add(url)

                    # Find IPs
                    for match in IP_PATTERN.finditer(text):
                        ip = match.group(0)
                        # Filter out common non-routable
                        if not ip.startswith(('10.', '127.', '0.', '192.168.', '255.')):
                            ips.add(ip)

                    # Find secrets
                    for pattern in SECRET_PATTERNS_PY:
                        for match in pattern.finditer(text):
                            secrets.add(match.group(0)[:100])

                except Exception:
                    continue
    except Exception:
        pass

    return list(urls)[:100], list(ips)[:50], list(secrets)[:20]


# ── Native Library Detection ─────────────────────────────────────────────────

def find_native_libraries(apk_path):
    """Find native .so libraries in APK."""
    libs = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                if name.startswith('lib/') and name.endswith('.so'):
                    libs.append(name)
    except Exception:
        pass
    return libs


# ── Main Analysis ────────────────────────────────────────────────────────────

def analyze_apk(apk_path):
    """Perform full APK analysis and return JSON result."""
    result = {
        'packageName': '',
        'versionName': '',
        'versionCode': 0,
        'minSdkVersion': 0,
        'targetSdkVersion': 0,
        'permissions': [],
        'dangerousPermissions': [],
        'activities': [],
        'services': [],
        'receivers': [],
        'providers': [],
        'nativeLibraries': [],
        'certificates': [],
        'suspiciousIndicators': [],
        'urls': [],
        'ips': [],
        'hardcodedSecrets': [],
    }

    if not os.path.isfile(apk_path):
        return result

    # Parse AndroidManifest.xml
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            if 'AndroidManifest.xml' in zf.namelist():
                manifest_data = zf.read('AndroidManifest.xml')
                manifest = parse_binary_xml(manifest_data)

                result['packageName'] = manifest['package']
                result['versionName'] = manifest['version_name']
                result['versionCode'] = manifest['version_code']
                result['minSdkVersion'] = manifest['min_sdk']
                result['targetSdkVersion'] = manifest['target_sdk']
                result['permissions'] = manifest['permissions']
                result['activities'] = manifest['activities']
                result['services'] = manifest['services']
                result['receivers'] = manifest['receivers']
                result['providers'] = manifest['providers']
    except Exception as e:
        result['suspiciousIndicators'].append({
            'category': 'parse_error',
            'description': f'Failed to parse AndroidManifest.xml: {str(e)}',
            'severity': 'medium',
        })

    # Identify dangerous permissions
    dangerous_perms = ${JSON.stringify(DANGEROUS_PERMISSION_PATTERNS.map(p => p.permission))}
    result['dangerousPermissions'] = [p for p in result['permissions'] if p in dangerous_perms]

    # Analyze certificates
    result['certificates'] = analyze_certificates(apk_path)

    # Find native libraries
    result['nativeLibraries'] = find_native_libraries(apk_path)

    # Scan for IOCs
    urls, ips, secrets = scan_for_iocs(apk_path)
    result['urls'] = urls
    result['ips'] = ips
    result['hardcodedSecrets'] = secrets

    # Generate suspicious indicators
    indicators = []

    # Permission-based indicators
    perm_set = set(result['permissions'])
    if 'android.permission.READ_SMS' in perm_set and 'android.permission.SEND_SMS' in perm_set:
        indicators.append({
            'category': 'banking_trojan',
            'description': 'App has SMS read+send permissions (common in banking trojans for OTP interception)',
            'severity': 'critical',
        })

    if 'android.permission.RECORD_AUDIO' in perm_set and 'android.permission.CAMERA' in perm_set:
        indicators.append({
            'category': 'spyware',
            'description': 'App has audio recording and camera access (surveillance capability)',
            'severity': 'high',
        })

    if 'android.permission.BIND_ACCESSIBILITY_SERVICE' in perm_set:
        indicators.append({
            'category': 'overlay_attack',
            'description': 'App uses accessibility service (commonly abused for credential overlay attacks)',
            'severity': 'critical',
        })

    if 'android.permission.BIND_DEVICE_ADMIN' in perm_set:
        indicators.append({
            'category': 'ransomware',
            'description': 'App requests device admin (can lock device, wipe data)',
            'severity': 'critical',
        })

    if 'android.permission.INSTALL_PACKAGES' in perm_set:
        indicators.append({
            'category': 'dropper',
            'description': 'App can install additional packages (dropper behavior)',
            'severity': 'critical',
        })

    # Target SDK check
    if result['targetSdkVersion'] > 0 and result['targetSdkVersion'] < 26:
        indicators.append({
            'category': 'evasion',
            'description': f'Targets old SDK {result["targetSdkVersion"]} to bypass modern permission system',
            'severity': 'high',
        })

    # Native code
    if result['nativeLibraries']:
        indicators.append({
            'category': 'native_code',
            'description': f'Contains {len(result["nativeLibraries"])} native libraries (potential for obfuscated native payloads)',
            'severity': 'medium',
        })

    # No certificates
    if not result['certificates']:
        indicators.append({
            'category': 'unsigned',
            'description': 'APK has no signing certificates (likely tampered or test build)',
            'severity': 'high',
        })

    # Hardcoded secrets
    if result['hardcodedSecrets']:
        indicators.append({
            'category': 'hardcoded_secrets',
            'description': f'Found {len(result["hardcodedSecrets"])} hardcoded secrets/API keys',
            'severity': 'high',
        })

    # Excessive permissions
    if len(result['dangerousPermissions']) > 5:
        indicators.append({
            'category': 'excessive_permissions',
            'description': f'Requests {len(result["dangerousPermissions"])} dangerous permissions (over-privileged)',
            'severity': 'high',
        })

    result['suspiciousIndicators'] = indicators

    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'Usage: apk_analyzer.py <path_to_apk>'}))
        sys.exit(1)

    apk_path = sys.argv[1]
    result = analyze_apk(apk_path)
    print(json.dumps(result, indent=2))
`;
}

// ── Permission Classification ───────────────────────────────────────────────

/**
 * Classify permissions and return details about dangerous ones.
 */
export function classifyPermissions(permissions: string[]): DangerousPermissionPattern[] {
  const dangerous: DangerousPermissionPattern[] = [];
  for (const perm of permissions) {
    const match = DANGEROUS_PERMISSION_PATTERNS.find(p => p.permission === perm);
    if (match) {
      dangerous.push(match);
    }
  }
  return dangerous;
}

/**
 * Calculate a risk score (0-100) for an APK based on analysis results.
 */
export function computeApkRiskScore(result: ApkAnalysisResult): number {
  let score = 0;

  // Dangerous permissions scoring
  const permCategories = new Set<string>();
  for (const perm of result.dangerousPermissions) {
    const pattern = DANGEROUS_PERMISSION_PATTERNS.find(p => p.permission === perm);
    if (pattern) {
      permCategories.add(pattern.category);
      if (pattern.severity === 'critical') score += 15;
      else if (pattern.severity === 'high') score += 8;
      else if (pattern.severity === 'medium') score += 4;
      else score += 2;
    }
  }

  // Multiple dangerous categories compound the risk
  if (permCategories.size >= 3) score += 15;
  else if (permCategories.size >= 2) score += 8;

  // Suspicious indicators
  for (const indicator of result.suspiciousIndicators) {
    if (indicator.severity === 'critical') score += 20;
    else if (indicator.severity === 'high') score += 12;
    else if (indicator.severity === 'medium') score += 6;
    else score += 3;
  }

  // IOC indicators
  if (result.urls.length > 10) score += 5;
  if (result.ips.length > 5) score += 5;
  if (result.hardcodedSecrets.length > 0) score += 10;

  // Old target SDK
  if (result.targetSdkVersion > 0 && result.targetSdkVersion < 26) score += 10;

  // No certificates
  if (result.certificates.length === 0) score += 10;

  return Math.min(100, Math.max(0, score));
}

/**
 * Parse the JSON output from the Python APK analysis script.
 */
export function parseApkAnalysisOutput(jsonOutput: string): ApkAnalysisResult | null {
  try {
    const parsed = JSON.parse(jsonOutput) as Record<string, unknown>;
    if ('error' in parsed) return null;

    return {
      packageName: String(parsed['packageName'] ?? ''),
      versionName: String(parsed['versionName'] ?? ''),
      versionCode: Number(parsed['versionCode'] ?? 0),
      minSdkVersion: Number(parsed['minSdkVersion'] ?? 0),
      targetSdkVersion: Number(parsed['targetSdkVersion'] ?? 0),
      permissions: (parsed['permissions'] as string[]) ?? [],
      dangerousPermissions: (parsed['dangerousPermissions'] as string[]) ?? [],
      activities: (parsed['activities'] as string[]) ?? [],
      services: (parsed['services'] as string[]) ?? [],
      receivers: (parsed['receivers'] as string[]) ?? [],
      providers: (parsed['providers'] as string[]) ?? [],
      nativeLibraries: (parsed['nativeLibraries'] as string[]) ?? [],
      certificates: (parsed['certificates'] as Array<{ issuer: string; subject: string; sha256: string }>) ?? [],
      suspiciousIndicators: (parsed['suspiciousIndicators'] as Array<{ category: string; description: string; severity: SeverityLevel }>) ?? [],
      urls: (parsed['urls'] as string[]) ?? [],
      ips: (parsed['ips'] as string[]) ?? [],
      hardcodedSecrets: (parsed['hardcodedSecrets'] as string[]) ?? [],
    };
  } catch {
    return null;
  }
}
