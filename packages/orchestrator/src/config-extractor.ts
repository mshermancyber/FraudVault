// ── Real Config Extraction for Known Malware Families ─────────────────────────
//
// When a family is identified (via VT, YARA match, or string patterns), attempts
// to parse the binary for configuration data. Extraction is performed via a
// Python script that runs inside the sandbox jail. Results are stored in
// threat_intel_results with provider='config-extraction'.
//
// Supported families:
//   - Cobalt Strike: XOR-decoded config at known offsets
//   - Emotet: RSA key + C2 IP:port list
//   - Agent Tesla: SMTP/FTP credentials from .NET resources
//   - Remcos RAT: RC4-encrypted config between markers
//   - AsyncRAT: AES-encrypted config in resources
//   - QakBot: RC4-encrypted config blob with C2 list

import type pg from 'pg';
import type { Logger } from 'pino';

// ── Types ──────────────────────────────────────────────────────────────────────

export interface ExtractedConfig {
  family: string;
  confidence: number;
  c2Servers: string[];
  encryptionKeys: string[];
  mutexes: string[];
  campaignId: string | null;
  botId: string | null;
  raw: Record<string, unknown>;
}

export interface ConfigExtractionResult {
  success: boolean;
  config: ExtractedConfig | null;
  error: string | null;
}

// ── Python Extraction Script ──────────────────────────────────────────────────

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

let _extractorsLibrary: string | null = null;
function getExtractorsLibrary(): string {
  if (!_extractorsLibrary) {
    const paths = [
      join(__dirname, 'extractors-library.py'),
      join(__dirname, '..', 'src', 'extractors-library.py'),
      join(process.cwd(), 'packages', 'orchestrator', 'src', 'extractors-library.py'),
    ];
    for (const p of paths) {
      try { _extractorsLibrary = readFileSync(p, 'utf-8'); break; } catch { /* next */ }
    }
    if (!_extractorsLibrary) _extractorsLibrary = '';
  }
  return _extractorsLibrary;
}

/**
 * Returns the Python script that performs real config extraction for known
 * malware families. This script is injected into the sandbox container and
 * executed after family identification from YARA/VT results.
 */
export function getConfigExtractorScript(family: string): string {
  return `
import json, os, sys, struct, re, hashlib, base64, binascii

# ═══════════════════════════════════════════════════════════════════════════════
# Malware Config Extraction Engine
# ═══════════════════════════════════════════════════════════════════════════════

FAMILY = ${JSON.stringify(family.toLowerCase().replace(/[^a-z0-9 _\-./]/g, ''))}
SAMPLE_PATH = "/opt/scanboy/sample"


def xor_decrypt(data, key):
    """XOR decrypt data with a single-byte or multi-byte key."""
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def rc4_decrypt(data, key):
    """RC4 stream cipher decryption."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


def extract_ipv4_addresses(data):
    """Extract valid IPv4 addresses from binary data."""
    ips = set()
    # Look for IP:port patterns in ASCII text
    text = data.decode('ascii', errors='ignore')
    for match in re.finditer(r'(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(:\\d{1,5})?', text):
        ip = match.group(1)
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            # Skip loopback, link-local, multicast
            first_octet = int(parts[0])
            if first_octet not in (0, 127, 169, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 255):
                port = match.group(2)
                if port:
                    ips.add(f"{ip}{port}")
                else:
                    ips.add(ip)
    return list(ips)


def extract_urls(data):
    """Extract URLs from binary data."""
    text = data.decode('ascii', errors='ignore')
    urls = set()
    for match in re.finditer(r'https?://[a-zA-Z0-9._/\\-:@]+', text):
        url = match.group(0)
        if len(url) > 10 and '.' in url:
            urls.add(url)
    return list(urls)


def extract_domains(data):
    """Extract domain names from binary data."""
    text = data.decode('ascii', errors='ignore')
    domains = set()
    for match in re.finditer(r'([a-zA-Z0-9\\-]+\\.)+[a-zA-Z]{2,}', text):
        domain = match.group(0).lower()
        # Filter out common false positives
        if domain.endswith(('.dll', '.exe', '.sys', '.com.dll')):
            continue
        if len(domain) > 5 and domain.count('.') >= 1:
            domains.add(domain)
    return list(domains)


# ═══════════════════════════════════════════════════════════════════════════════
# Cobalt Strike Config Extraction
# ═══════════════════════════════════════════════════════════════════════════════

def extract_cobalt_strike_config(data):
    """
    Cobalt Strike beacon config extraction.
    The config is XOR encoded (common keys: 0x69, 0x2e) and starts with
    marker bytes 0x00 0x01 0x00 0x01 0x00 0x02 after decoding.
    Config fields are TLV-encoded: 2-byte type, 2-byte length, then value.
    """
    result = {
        'family': 'Cobalt Strike',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {},
    }

    # Known XOR keys used by Cobalt Strike
    xor_keys = [0x69, 0x2e, 0x00]
    config_marker = b'\\x00\\x01\\x00\\x01\\x00\\x02'
    decoded_config = None

    for key in xor_keys:
        if key == 0x00:
            # Try unencoded
            idx = data.find(config_marker)
            if idx >= 0:
                decoded_config = data[idx:]
                break
        else:
            decrypted = xor_decrypt(data, key)
            idx = decrypted.find(config_marker)
            if idx >= 0:
                decoded_config = decrypted[idx:]
                break

    if not decoded_config:
        # Try scanning with sliding window
        for offset in range(0, min(len(data) - 6, 1024 * 1024), 4):
            for key in [0x69, 0x2e]:
                chunk = xor_decrypt(data[offset:offset+6], key)
                if chunk == config_marker:
                    decoded_config = xor_decrypt(data[offset:offset+4096], key)
                    break
            if decoded_config:
                break

    if not decoded_config or len(decoded_config) < 20:
        # Fallback: extract any C2 indicators from strings
        urls = extract_urls(data)
        ips = extract_ipv4_addresses(data)
        if urls or ips:
            result['c2Servers'] = (urls + ips)[:20]
            result['confidence'] = 40
        return result if result['c2Servers'] else None

    # Parse TLV config fields
    CS_FIELDS = {
        1: 'BeaconType',
        2: 'Port',
        3: 'SleepTime',
        4: 'MaxGetSize',
        5: 'Jitter',
        7: 'PublicKey',
        8: 'C2Server',
        9: 'UserAgent',
        10: 'HttpPostUri',
        26: 'SpawnTo_x86',
        27: 'SpawnTo_x64',
        28: 'CryptoScheme',
        29: 'Proxy_Config',
        37: 'Watermark',
        38: 'StageCleanup',
        39: 'CFGCaution',
    }

    pos = 0
    parsed_fields = {}
    try:
        while pos < len(decoded_config) - 4:
            field_type = struct.unpack('>H', decoded_config[pos:pos+2])[0]
            field_len = struct.unpack('>H', decoded_config[pos+2:pos+4])[0]
            pos += 4

            if field_len > 4096 or pos + field_len > len(decoded_config):
                break

            field_data = decoded_config[pos:pos+field_len]
            pos += field_len

            field_name = CS_FIELDS.get(field_type, f'field_{field_type}')

            if field_type == 8:  # C2Server
                c2 = field_data.decode('ascii', errors='ignore').strip('\\x00')
                if c2:
                    for server in c2.split(','):
                        server = server.strip()
                        if server:
                            result['c2Servers'].append(server)
            elif field_type == 7:  # PublicKey
                result['encryptionKeys'].append(binascii.hexlify(field_data[:32]).decode())
            elif field_type == 37:  # Watermark
                if field_len == 4:
                    watermark = struct.unpack('>I', field_data)[0]
                    result['raw']['watermark'] = watermark
                    result['campaignId'] = str(watermark)
            elif field_type in (1, 2, 3, 4, 5):
                if field_len == 2:
                    parsed_fields[field_name] = struct.unpack('>H', field_data)[0]
                elif field_len == 4:
                    parsed_fields[field_name] = struct.unpack('>I', field_data)[0]
            else:
                text_val = field_data.decode('ascii', errors='ignore').strip('\\x00')
                if text_val:
                    parsed_fields[field_name] = text_val

    except (struct.error, IndexError):
        pass

    result['raw'].update(parsed_fields)
    result['confidence'] = 90 if result['c2Servers'] else 60

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Emotet Config Extraction
# ═══════════════════════════════════════════════════════════════════════════════

def extract_emotet_config(data):
    """
    Emotet config: RSA public key + C2 IP:port list.
    C2 list is usually at end of .data section or XOR encoded.
    IP:port stored as 4-byte IP + 2-byte port (big-endian).
    """
    result = {
        'family': 'Emotet',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {},
    }

    # Look for RSA public key
    rsa_markers = [b'-----BEGIN PUBLIC KEY-----', b'RSA1', b'PUBLICKEYBLOB']
    for marker in rsa_markers:
        idx = data.find(marker)
        if idx >= 0:
            if marker == b'-----BEGIN PUBLIC KEY-----':
                end_marker = b'-----END PUBLIC KEY-----'
                end_idx = data.find(end_marker, idx)
                if end_idx > idx:
                    key_data = data[idx:end_idx + len(end_marker)]
                    result['encryptionKeys'].append(key_data.decode('ascii', errors='ignore'))
            else:
                result['encryptionKeys'].append(f"RSA key at offset 0x{idx:x}")
            break

    # Look for packed IP:port structures (4 bytes IP + 2 bytes port)
    # Emotet often stores C2s as binary IP + port structures
    c2_candidates = []

    # Method 1: Look for binary IP:port sequences
    for offset in range(0, len(data) - 6, 1):
        if offset + 6 > len(data):
            break
        # Check if this looks like a valid IP:port
        ip_bytes = data[offset:offset+4]
        port_bytes = data[offset+4:offset+6]

        first_octet = ip_bytes[0]
        if first_octet in (0, 127, 169, 224, 255):
            continue

        port = struct.unpack('>H', port_bytes)[0]
        if port < 80 or port > 65000:
            continue

        ip_str = '.'.join(str(b) for b in ip_bytes)
        # Validate all octets
        if all(0 < b < 255 for b in ip_bytes[:1]) and all(0 <= b <= 255 for b in ip_bytes[1:]):
            # Check the next entry is also valid (C2 lists are sequential)
            if offset + 12 <= len(data):
                next_ip = data[offset+6:offset+10]
                next_port = struct.unpack('>H', data[offset+10:offset+12])[0]
                if (next_ip[0] not in (0, 127, 169, 224, 255) and
                    80 <= next_port <= 65000):
                    c2_candidates.append(f"{ip_str}:{port}")
                    # Found a sequence, extract more
                    seq_offset = offset + 6
                    while seq_offset + 6 <= len(data) and len(c2_candidates) < 50:
                        ip_b = data[seq_offset:seq_offset+4]
                        p_b = data[seq_offset+4:seq_offset+6]
                        if ip_b[0] in (0, 127, 169, 224, 255):
                            break
                        p = struct.unpack('>H', p_b)[0]
                        if p < 80 or p > 65000:
                            break
                        c2_candidates.append(f"{'.'.join(str(b) for b in ip_b)}:{p}")
                        seq_offset += 6
                    break

    # Method 2: XOR with common keys and look for IP patterns
    if not c2_candidates:
        for xor_key in [0x45, 0x54, 0x69, 0x7a, 0xaa, 0xbb, 0xcc]:
            decrypted = xor_decrypt(data[-8192:], xor_key)
            ips = extract_ipv4_addresses(decrypted)
            if len(ips) >= 3:
                c2_candidates = ips[:30]
                result['raw']['xor_key'] = hex(xor_key)
                break

    # Method 3: Fallback to string extraction
    if not c2_candidates:
        c2_candidates = extract_ipv4_addresses(data)

    result['c2Servers'] = c2_candidates[:30]
    result['confidence'] = 80 if len(c2_candidates) >= 3 else (50 if c2_candidates else 0)

    return result if result['c2Servers'] or result['encryptionKeys'] else None


# ═══════════════════════════════════════════════════════════════════════════════
# Agent Tesla Config Extraction
# ═══════════════════════════════════════════════════════════════════════════════

def extract_agenttesla_config(data):
    """
    Agent Tesla: SMTP/FTP credentials embedded in .NET resources or base64 strings.
    Often uses base64-encoded config strings with SMTP server, port, user, password.
    """
    result = {
        'family': 'Agent Tesla',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {},
    }

    text = data.decode('ascii', errors='ignore')

    # Look for SMTP server configurations
    smtp_servers = set()
    smtp_patterns = [
        r'smtp\\.[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',
        r'mail\\.[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',
    ]
    for pattern in smtp_patterns:
        for match in re.finditer(pattern, text):
            smtp_servers.add(match.group(0))

    # Look for FTP servers
    ftp_patterns = [
        r'ftp://[a-zA-Z0-9._/\\-:@]+',
        r'ftp\\.[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',
    ]
    for pattern in ftp_patterns:
        for match in re.finditer(pattern, text):
            result['c2Servers'].append(match.group(0))

    # Look for Telegram bot tokens
    telegram_pattern = r'\\d{8,10}:[A-Za-z0-9_-]{35}'
    for match in re.finditer(telegram_pattern, text):
        result['raw']['telegram_bot_token'] = match.group(0)

    # Look for base64 encoded strings that might be credentials
    b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    for match in re.finditer(b64_pattern, text):
        try:
            decoded = base64.b64decode(match.group(0)).decode('utf-8', errors='ignore')
            if '@' in decoded and '.' in decoded:
                result['raw']['decoded_email'] = decoded
            elif 'smtp' in decoded.lower() or 'mail' in decoded.lower():
                result['raw']['decoded_config'] = decoded
        except Exception:
            pass

    # Look for port numbers commonly used by Agent Tesla
    port_pattern = r'(?:587|465|25|21|143|993)\\b'
    ports = re.findall(port_pattern, text)
    if ports:
        result['raw']['ports'] = list(set(ports))

    # SMTP servers are C2 for Agent Tesla
    result['c2Servers'].extend(list(smtp_servers))

    # Look for credentials patterns
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, text)
    if emails:
        result['raw']['emails'] = emails[:10]

    result['confidence'] = 85 if result['c2Servers'] else (50 if result['raw'] else 0)

    return result if result['c2Servers'] or result['raw'] else None


# ═══════════════════════════════════════════════════════════════════════════════
# Remcos RAT Config Extraction
# ═══════════════════════════════════════════════════════════════════════════════

def extract_remcos_config(data):
    """
    Remcos RAT: Config between markers "SETTINGS" and "END", RC4 encrypted
    with a hardcoded key. Also check for config in resources section.
    """
    result = {
        'family': 'Remcos RAT',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {},
    }

    # Look for SETTINGS/END markers
    settings_marker = b'SETTINGS'
    end_marker = b'\\x00END'

    settings_idx = data.find(settings_marker)
    if settings_idx >= 0:
        end_idx = data.find(end_marker, settings_idx)
        if end_idx < 0:
            end_idx = settings_idx + 4096  # Reasonable max

        config_data = data[settings_idx + len(settings_marker):end_idx]

        # Try RC4 decryption with key found near the config
        # Remcos stores the RC4 key length as first byte, then key, then encrypted config
        if len(config_data) > 2:
            key_len = config_data[0]
            if 1 <= key_len <= 32 and key_len + 1 < len(config_data):
                rc4_key = config_data[1:1+key_len]
                encrypted = config_data[1+key_len:]
                decrypted = rc4_decrypt(encrypted, rc4_key)
                result['encryptionKeys'].append(binascii.hexlify(rc4_key).decode())

                # Parse decrypted config (pipe-delimited or null-delimited)
                config_text = decrypted.decode('ascii', errors='ignore')
                # Remcos uses '|' as field separator
                fields = [f for f in re.split(r'[|\\x00\\x01]', config_text) if f.strip()]

                for field in fields:
                    field = field.strip()
                    # Check for IP:port pattern
                    if re.match(r'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?', field):
                        result['c2Servers'].append(field)
                    elif re.match(r'[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(:\\d+)?', field) and len(field) > 4:
                        result['c2Servers'].append(field)

                if fields:
                    result['raw']['config_fields'] = fields[:20]

    # Fallback: look for Remcos-specific patterns
    if not result['c2Servers']:
        # Remcos often has the mutex name and C2 in cleartext nearby
        remcos_idx = data.find(b'Remcos')
        if remcos_idx >= 0:
            nearby = data[max(0, remcos_idx-512):remcos_idx+1024]
            ips = extract_ipv4_addresses(nearby)
            domains = extract_domains(nearby)
            result['c2Servers'] = (ips + domains)[:10]

    # Look for mutex
    mutex_pattern = r'Remcos[_-]?[A-Za-z0-9]+'
    text = data.decode('ascii', errors='ignore')
    for match in re.finditer(mutex_pattern, text):
        result['mutexes'].append(match.group(0))

    result['confidence'] = 85 if result['c2Servers'] else (60 if result['encryptionKeys'] else 0)

    return result if result['c2Servers'] or result['encryptionKeys'] else None


# ═══════════════════════════════════════════════════════════════════════════════
# AsyncRAT Config Extraction
# ═══════════════════════════════════════════════════════════════════════════════

def extract_asyncrat_config(data):
    """
    AsyncRAT: Config in .NET resources, AES encrypted.
    Key derivable from mutex/assembly name. Config contains host, port, mutex, etc.
    """
    result = {
        'family': 'AsyncRAT',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {},
    }

    text = data.decode('ascii', errors='ignore')

    # AsyncRAT stores config as base64 encoded strings in .NET resources
    # Look for typical config field names
    config_markers = ['Ports', 'Hosts', 'Version', 'Install', 'MTX', 'Pastebin',
                      'Anti', 'BDOS', 'Group', 'Hwid']

    found_markers = []
    for marker in config_markers:
        if marker.encode() in data:
            found_markers.append(marker)

    # Try to extract host:port from nearby base64 strings
    hosts = []
    ports = []

    # Look for base64 encoded values near config markers
    for marker in ['Hosts', 'Host']:
        idx = data.find(marker.encode())
        if idx >= 0:
            # Look for base64 content after the marker
            nearby = data[idx:idx+512].decode('ascii', errors='ignore')
            for b64match in re.finditer(r'[A-Za-z0-9+/]{8,}={0,2}', nearby):
                try:
                    decoded = base64.b64decode(b64match.group(0)).decode('utf-8', errors='ignore')
                    if re.match(r'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}', decoded):
                        hosts.append(decoded)
                    elif re.match(r'[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', decoded):
                        hosts.append(decoded)
                except Exception:
                    pass

    for marker in ['Ports', 'Port']:
        idx = data.find(marker.encode())
        if idx >= 0:
            nearby = data[idx:idx+256].decode('ascii', errors='ignore')
            for b64match in re.finditer(r'[A-Za-z0-9+/]{4,}={0,2}', nearby):
                try:
                    decoded = base64.b64decode(b64match.group(0)).decode('utf-8', errors='ignore')
                    if decoded.isdigit() and 1 <= int(decoded) <= 65535:
                        ports.append(decoded)
                except Exception:
                    pass

    # Combine hosts and ports
    if hosts and ports:
        for host in hosts:
            for port in ports:
                result['c2Servers'].append(f"{host}:{port}")
    elif hosts:
        result['c2Servers'] = hosts

    # Fallback: extract IPs and domains from the binary
    if not result['c2Servers']:
        ips = extract_ipv4_addresses(data)
        result['c2Servers'] = ips[:10]

    # Look for mutex
    mtx_idx = data.find(b'MTX')
    if mtx_idx >= 0:
        nearby = data[mtx_idx:mtx_idx+256].decode('ascii', errors='ignore')
        for b64match in re.finditer(r'[A-Za-z0-9+/]{4,}={0,2}', nearby):
            try:
                decoded = base64.b64decode(b64match.group(0)).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 3:
                    result['mutexes'].append(decoded)
            except Exception:
                pass

    # Look for AES key material
    for marker in [b'\\x00\\x20', b'\\x00\\x10']:  # 32-byte or 16-byte key indicators
        idx = data.find(marker)
        if idx >= 0 and idx + 34 < len(data):
            potential_key = data[idx+2:idx+34]
            if all(32 <= b < 127 for b in potential_key):
                result['encryptionKeys'].append(potential_key.decode('ascii'))

    result['raw']['found_markers'] = found_markers
    result['confidence'] = 80 if result['c2Servers'] else (50 if found_markers else 0)

    return result if result['c2Servers'] or found_markers else None


# ═══════════════════════════════════════════════════════════════════════════════
# QakBot Config Extraction
# ═══════════════════════════════════════════════════════════════════════════════

def extract_qakbot_config(data):
    """
    QakBot/Qbot: RC4 encrypted config blob with C2 list.
    Config often stored in resources, encrypted with SHA1-derived RC4 key.
    C2 entries: 1-byte flag + 4-byte IP + 2-byte port.
    """
    result = {
        'family': 'QakBot',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {},
    }

    # Look for QakBot campaign ID pattern (e.g., "obama", "biden", "bb", "tok")
    campaign_patterns = [
        r'(?:campaign|camp|grp|id)[=:]\\s*([a-zA-Z0-9]+)',
        r'\\b(obama\\d*|biden\\d*|tok\\d*|bb\\d*|aa\\d*|tr\\d*|azd\\d*)\\b',
    ]
    text = data.decode('ascii', errors='ignore')
    for pattern in campaign_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            result['campaignId'] = match.group(1) if match.lastindex else match.group(0)
            break
        if result['campaignId']:
            break

    # Try RC4 decryption with known QakBot key derivation
    # QakBot uses SHA1 of a hardcoded string as RC4 key
    known_seeds = [b'\\x61\\x62\\x63\\x64\\x65', b'Qbot', b'qbot', b'\\x00\\x00\\x00\\x00']
    c2_list = []

    # Look for resource sections that might contain encrypted C2
    # QakBot resource names are often numeric IDs
    for seed in known_seeds:
        rc4_key = hashlib.sha1(seed).digest()
        # Try decrypting various offsets
        for offset in range(0, min(len(data), 512 * 1024), 4096):
            chunk = data[offset:offset+2048]
            if len(chunk) < 7:
                continue
            decrypted = rc4_decrypt(chunk, rc4_key)

            # Check for C2 structure: flag(1) + IP(4) + port(2) = 7 bytes each
            temp_c2 = []
            for i in range(0, len(decrypted) - 6, 7):
                flag = decrypted[i]
                if flag not in (0x01, 0x02):
                    if temp_c2:
                        break
                    continue
                ip_bytes = decrypted[i+1:i+5]
                port = struct.unpack('>H', decrypted[i+5:i+7])[0]
                if ip_bytes[0] in (0, 127, 169, 224, 255):
                    if temp_c2:
                        break
                    continue
                if port < 80 or port > 65535:
                    if temp_c2:
                        break
                    continue
                ip_str = '.'.join(str(b) for b in ip_bytes)
                temp_c2.append(f"{ip_str}:{port}")

            if len(temp_c2) >= 3:
                c2_list = temp_c2
                result['encryptionKeys'].append(binascii.hexlify(rc4_key).decode())
                result['raw']['rc4_seed'] = seed.decode('ascii', errors='ignore')
                break
        if c2_list:
            break

    # Fallback: extract IPs from the binary
    if not c2_list:
        c2_list = extract_ipv4_addresses(data)

    result['c2Servers'] = c2_list[:50]
    result['confidence'] = 85 if len(c2_list) >= 3 else (50 if c2_list else 0)

    # Look for bot ID
    bot_id_pattern = r'[A-Z]{2,4}_[a-z0-9]{6,12}'
    for match in re.finditer(bot_id_pattern, text):
        result['botId'] = match.group(0)
        break

    return result if result['c2Servers'] else None


# ═══════════════════════════════════════════════════════════════════════════════
# Main Extraction Logic
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# Extended Malware Family Extractors (loaded from library)
# ═══════════════════════════════════════════════════════════════════════════════
${getExtractorsLibrary().replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$')}

def main():
    if not os.path.isfile(SAMPLE_PATH):
        print(json.dumps({"success": False, "config": None, "error": "Sample file not found"}))
        return

    try:
        with open(SAMPLE_PATH, "rb") as f:
            data = f.read(50 * 1024 * 1024)  # Max 50MB
    except Exception as e:
        print(json.dumps({"success": False, "config": None, "error": str(e)}))
        return

    extractors = {
        'cobalt strike': extract_cobalt_strike_config,
        'cobaltstrike': extract_cobalt_strike_config,
        'beacon': extract_cobalt_strike_config,
        'emotet': extract_emotet_config,
        'agent tesla': extract_agenttesla_config,
        'agenttesla': extract_agenttesla_config,
        'remcos': extract_remcos_config,
        'asyncrat': extract_asyncrat_config,
        'async rat': extract_asyncrat_config,
        'qakbot': extract_qakbot_config,
        'qbot': extract_qakbot_config,
        'lockbit': extract_lockbit_config,
        'blackcat': extract_blackcat_config,
        'alphv': extract_blackcat_config,
        'conti': extract_conti_config,
        'trickbot': extract_trickbot_config,
        'icedid': extract_icedid_config,
        'bokbot': extract_icedid_config,
        'bumblebee': extract_bumblebee_config,
        'raccoon': extract_raccoon_config,
        'redline': extract_redline_config,
        'vidar': extract_vidar_config,
        'formbook': extract_formbook_config,
        'xloader': extract_formbook_config,
        'lokibot': extract_lokibot_config,
        'njrat': extract_njrat_config,
        'darkcomet': extract_darkcomet_config,
        'ursnif': extract_ursnif_config,
        'gozi': extract_ursnif_config,
        'dridex': extract_dridex_config,
        'bazarloader': extract_bazarloader_config,
        'bazar': extract_bazarloader_config,
        'systembc': extract_systembc_config,
        'smokeloader': extract_smokeloader_config,
        'amadey': extract_amadey_config,
        'stealc': extract_stealc_config,
        'lumma': extract_lumma_config,
        'pikabot': extract_pikabot_config,
        'darkgate': extract_darkgate_config,
        'latrodectus': extract_latrodectus_config,
        'rhadamanthys': extract_rhadamanthys_config,
        'plugx': extract_plugx_config,
        'korplug': extract_plugx_config,
        'shadowpad': extract_shadowpad_config,
        'gh0st': extract_gh0strat_config,
        'gh0strat': extract_gh0strat_config,
        'poison ivy': extract_poisonivy_config,
        'poisonivy': extract_poisonivy_config,
        'netwire': extract_netwire_config,
        'warzone': extract_warzoneRAT_config,
        'ave maria': extract_warzoneRAT_config,
        'havoc': extract_havoc_config,
        'sliver': extract_sliver_config,
        'brute ratel': extract_bruteratel_config,
        'bruteratel': extract_bruteratel_config,
        'brc4': extract_bruteratel_config,
        'mythic': extract_mythic_config,
        'meterpreter': extract_meterpreter_config,
        'metasploit': extract_meterpreter_config,
        'wannacry': extract_wannacry_config,
        'revil': extract_revil_config,
        'sodinokibi': extract_revil_config,
        'ryuk': extract_ryuk_config,
        'hive': extract_hive_config,
        'royal': extract_royal_config,
        'black basta': extract_blackbasta_config,
        'blackbasta': extract_blackbasta_config,
        'akira': extract_akira_config,
        'play': extract_play_config,
        'clop': extract_clop_config,
        'cl0p': extract_clop_config,
        'maze': extract_maze_config,
        'medusa': extract_medusa_config,
        'phobos': extract_phobos_config,
        'dharma': extract_dharma_config,
        'crysis': extract_dharma_config,
    }

    family_lower = FAMILY.lower()
    extractor = None
    for key, func in extractors.items():
        if key in family_lower or family_lower in key:
            extractor = func
            break

    if not extractor:
        # Try all extractors and return the best result
        best_result = None
        best_confidence = 0
        for func in set(extractors.values()):
            try:
                res = func(data)
                if res and res.get('confidence', 0) > best_confidence:
                    best_result = res
                    best_confidence = res['confidence']
            except Exception:
                continue

        if best_result:
            print(json.dumps({"success": True, "config": best_result, "error": None}))
        else:
            print(json.dumps({"success": False, "config": None, "error": f"No extractor for family: {FAMILY}"}))
        return

    try:
        config = extractor(data)
        if config:
            print(json.dumps({"success": True, "config": config, "error": None}))
        else:
            print(json.dumps({"success": False, "config": None, "error": "Config extraction yielded no results"}))
    except Exception as e:
        print(json.dumps({"success": False, "config": None, "error": f"Extraction error: {str(e)}"}))


if __name__ == "__main__":
    main()
`;
}

// ── Config Extraction Orchestration ───────────────────────────────────────────

/**
 * Attempt to extract malware config from a file buffer.
 * This function is called from the submission workflow after family identification.
 * The actual extraction happens via Python script in the sandbox.
 *
 * @param fileData - The raw binary data of the sample
 * @param family - The identified malware family name
 * @param suspiciousStrings - Strings extracted during static analysis
 * @returns ExtractedConfig if extraction succeeded, null otherwise
 */
export async function extractMalwareConfig(
  _fileData: Buffer,
  family: string,
  suspiciousStrings: string[],
): Promise<ExtractedConfig | null> {
  // This function parses the config extraction output from the Python script.
  // The actual extraction is done in-container by getConfigExtractorScript().
  // This is a host-side parser for the JSON output.

  // Quick pre-check: verify we support this family
  const supportedFamilies = [
    'cobalt strike', 'cobaltstrike', 'beacon', 'emotet',
    'agent tesla', 'agenttesla', 'remcos', 'asyncrat', 'async rat',
    'qakbot', 'qbot', 'lockbit', 'blackcat', 'alphv', 'conti',
    'trickbot', 'icedid', 'bokbot', 'bumblebee', 'raccoon',
    'redline', 'vidar', 'formbook', 'xloader', 'lokibot',
    'njrat', 'darkcomet', 'ursnif', 'gozi', 'dridex',
    'bazarloader', 'bazar', 'systembc', 'smokeloader', 'amadey',
    'stealc', 'lumma', 'pikabot', 'darkgate', 'latrodectus',
    'rhadamanthys', 'plugx', 'korplug', 'shadowpad', 'gh0st',
    'poison ivy', 'poisonivy', 'netwire', 'warzone', 'ave maria',
    'havoc', 'sliver', 'brute ratel', 'bruteratel', 'brc4',
    'mythic', 'meterpreter', 'metasploit',
    'wannacry', 'revil', 'sodinokibi', 'ryuk', 'hive', 'royal',
    'black basta', 'blackbasta', 'akira', 'play', 'clop', 'cl0p',
    'maze', 'medusa', 'phobos', 'dharma', 'crysis',
  ];

  const familyLower = family.toLowerCase();
  const isSupported = supportedFamilies.some(f => familyLower.includes(f) || f.includes(familyLower));

  if (!isSupported) {
    return null;
  }

  // For host-side fallback extraction (when sandbox is not available),
  // we can still look for basic indicators in the suspicious strings
  const c2Indicators: string[] = [];
  const ipPattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?/;
  const urlPattern = /https?:\/\/[a-zA-Z0-9._/\-:@]+/;
  const domainPattern = /[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/;

  for (const str of suspiciousStrings) {
    const ipMatch = ipPattern.exec(str);
    if (ipMatch) {
      c2Indicators.push(ipMatch[0]);
    }
    const urlMatch = urlPattern.exec(str);
    if (urlMatch) {
      c2Indicators.push(urlMatch[0]);
    }
    const domainMatch = domainPattern.exec(str);
    if (domainMatch && !domainMatch[0].endsWith('.dll') && !domainMatch[0].endsWith('.exe')) {
      c2Indicators.push(domainMatch[0]);
    }
  }

  if (c2Indicators.length === 0) {
    return null;
  }

  return {
    family,
    confidence: 50, // Lower confidence for string-only extraction
    c2Servers: [...new Set(c2Indicators)].slice(0, 20),
    encryptionKeys: [],
    mutexes: [],
    campaignId: null,
    botId: null,
    raw: { source: 'string-analysis', stringCount: suspiciousStrings.length },
  };
}

// ── Parse Python Script Output ────────────────────────────────────────────────

/**
 * Parse the JSON output from the config extraction Python script.
 */
export function parseConfigExtractionOutput(jsonOutput: string): ConfigExtractionResult {
  try {
    const parsed = JSON.parse(jsonOutput.trim()) as ConfigExtractionResult;
    return {
      success: parsed.success ?? false,
      config: parsed.config ?? null,
      error: parsed.error ?? null,
    };
  } catch {
    return { success: false, config: null, error: 'Failed to parse extraction output' };
  }
}

// ── Database Storage ──────────────────────────────────────────────────────────

/**
 * Store extracted config in threat_intel_results and IOCs tables.
 */
export async function storeExtractedConfig(
  pool: pg.Pool,
  submissionId: string,
  config: ExtractedConfig,
  logger: Logger,
): Promise<void> {
  try {
    // Store in threat_intel_results
    await pool.query(
      `INSERT INTO threat_intel_results (submission_id, provider, verdict, detection_count, total_engines, malware_family, raw_response)
       VALUES ($1, 'config-extraction', 'malicious', $2, $3, $4, $5)
       ON CONFLICT DO NOTHING`,
      [
        submissionId,
        config.c2Servers.length,
        config.c2Servers.length,
        config.family,
        JSON.stringify({
          c2Servers: config.c2Servers,
          encryptionKeys: config.encryptionKeys,
          mutexes: config.mutexes,
          campaignId: config.campaignId,
          botId: config.botId,
          confidence: config.confidence,
          ...config.raw,
        }),
      ],
    );

    // Store C2 servers as IOCs
    for (const c2 of config.c2Servers.slice(0, 50)) {
      const iocType = c2.includes('://') ? 'url'
        : /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(c2) ? 'ip'
        : 'domain';

      await pool.query(
        `INSERT INTO iocs (submission_id, type, value, context, confidence, source)
         VALUES ($1, $2, $3, $4, $5, 'config-extraction')
         ON CONFLICT DO NOTHING`,
        [
          submissionId,
          iocType,
          c2,
          `Extracted from ${config.family} config`,
          config.confidence,
        ],
      );
    }

    // Store mutexes as IOCs
    for (const mutex of config.mutexes.slice(0, 10)) {
      await pool.query(
        `INSERT INTO iocs (submission_id, type, value, context, confidence, source)
         VALUES ($1, $2, $3, $4, $5, 'config-extraction')
         ON CONFLICT DO NOTHING`,
        [submissionId, 'mutex', mutex, `${config.family} mutex`, config.confidence],
      );
    }

    logger.info(
      {
        submissionId,
        family: config.family,
        c2Count: config.c2Servers.length,
        confidence: config.confidence,
      },
      'Stored extracted malware config',
    );
  } catch (err) {
    logger.warn({ err, submissionId, family: config.family }, 'Failed to store extracted config');
  }
}
