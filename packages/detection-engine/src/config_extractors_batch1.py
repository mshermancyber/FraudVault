import re
import struct
import base64
import hashlib
from typing import Optional


# ---------------------------------------------------------------------------
# Helpers (assumed already defined in the surrounding module; repeated here
# so this file is self-contained for unit testing)
# ---------------------------------------------------------------------------

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))


def rc4_decrypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


def extract_ipv4_addresses(data: bytes) -> list:
    text = data.decode('latin-1', errors='replace')
    pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    candidates = re.findall(pattern, text)
    return [ip for ip in candidates if not ip.startswith(('0.', '127.', '255.'))]


# ---------------------------------------------------------------------------
# 1. LockBit
# ---------------------------------------------------------------------------

def extract_lockbit_config(data: bytes):
    """Extract LockBit configuration from binary data."""
    result = {
        'family': 'LockBit',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # Magic marker used in LockBit 2.0 / 3.0 configs
    MAGIC = b'LockBit'
    LB3_MARKER = b'\x4c\x42\x33\x00'  # "LB3\x00"

    if MAGIC in data:
        result['confidence'] += 30
    if LB3_MARKER in data:
        result['confidence'] += 20
        result['raw']['variant'] = 'LockBit3'

    # Onion URLs — LockBit uses .onion C2 for victim communication
    onions = re.findall(rb'[a-z2-7]{16,56}\.onion(?::\d+)?', data)
    for o in onions:
        result['c2Servers'].append(o.decode('ascii', errors='replace'))
    if onions:
        result['confidence'] += 25

    # RSA public key blob (starts with 30 82 or 30 81)
    rsa_markers = [m.start() for m in re.finditer(rb'\x30\x82', data)]
    for off in rsa_markers[:3]:
        blob = data[off:off + 294]  # 2048-bit public key DER
        if len(blob) == 294:
            result['encryptionKeys'].append(blob.hex()[:64])
            result['confidence'] += 10
            break

    # Campaign / affiliate ID stored as 8-byte little-endian value near magic
    for match in re.finditer(rb'(?:affiliate|campaign)[\x00-\x1f]{0,4}', data, re.IGNORECASE):
        off = match.end()
        if off + 8 <= len(data):
            val = struct.unpack_from('<Q', data, off)[0]
            result['campaignId'] = hex(val)
            result['confidence'] += 10
            break

    # Mutex pattern
    mutex_m = re.search(rb'Global\\[0-9A-Fa-f\-]{32,40}', data)
    if mutex_m:
        result['mutexes'].append(mutex_m.group().decode('latin-1'))
        result['confidence'] += 5

    result['raw']['onion_count'] = len(onions)
    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 2. BlackCat / ALPHV
# ---------------------------------------------------------------------------

def extract_blackcat_config(data: bytes):
    """Extract BlackCat/ALPHV configuration from binary data."""
    result = {
        'family': 'BlackCat',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # ALPHV embeds a JSON config block in the Rust binary
    json_start = data.find(b'{"config"')
    if json_start == -1:
        json_start = data.find(b'{"credentials"')
    if json_start == -1:
        json_start = data.find(b'{"public_key"')

    if json_start != -1:
        # Scan for matching closing brace
        depth = 0
        end = json_start
        for i in range(json_start, min(json_start + 65536, len(data))):
            b = data[i:i+1]
            if b == b'{':
                depth += 1
            elif b == b'}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        blob = data[json_start:end]
        result['confidence'] += 40
        result['raw']['json_blob'] = blob[:512].decode('utf-8', errors='replace')

        # Extract onion C2 from JSON blob
        onions = re.findall(rb'[a-z2-7]{16,56}\.onion(?::\d+)?', blob)
        for o in onions:
            result['c2Servers'].append(o.decode('ascii'))
        if onions:
            result['confidence'] += 20

        # Public key field
        pk_m = re.search(rb'"public_key"\s*:\s*"([A-Fa-f0-9]{64,128})"', blob)
        if pk_m:
            result['encryptionKeys'].append(pk_m.group(1).decode())
            result['confidence'] += 10

        # Access token / campaign
        tok_m = re.search(rb'"access_token"\s*:\s*"([^"]{8,64})"', blob)
        if tok_m:
            result['campaignId'] = tok_m.group(1).decode('utf-8', errors='replace')
            result['confidence'] += 10

    # Rust binary marker
    if b'panicked at' in data or b'rust_begin_unwind' in data:
        result['confidence'] += 10
        result['raw']['language'] = 'Rust'

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 3. Conti
# ---------------------------------------------------------------------------

def extract_conti_config(data: bytes):
    """Extract Conti configuration from binary data."""
    result = {
        'family': 'Conti',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # Conti uses single-byte XOR to obfuscate its C2 list; try keys 0x01-0xFF
    CONTI_MARKER = b'CONTI'
    ip_re = re.compile(
        rb'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?):\d{2,5}'
    )

    # Check plaintext first
    if CONTI_MARKER in data or b'conti' in data.lower():
        result['confidence'] += 20

    found_key = None
    best_ips = []
    for key in range(1, 256):
        decrypted = xor_decrypt(data[:65536], bytes([key]))
        ips = ip_re.findall(decrypted)
        if len(ips) > len(best_ips):
            best_ips = ips
            found_key = key

    if best_ips:
        result['confidence'] += 35
        result['encryptionKeys'].append(hex(found_key))
        result['raw']['xor_key'] = hex(found_key)
        for ip in best_ips[:20]:
            result['c2Servers'].append(ip.decode('ascii', errors='replace'))

    # Campaign / gtag marker (Conti shares infrastructure with TrickBot)
    gtag_m = re.search(rb'(?:camp|gtag)[\x00]{0,2}([A-Za-z0-9_\-]{3,16})', data)
    if gtag_m:
        result['campaignId'] = gtag_m.group(1).decode('ascii', errors='replace')
        result['confidence'] += 15

    # Mutex pattern
    mutex_m = re.search(rb'[\x00]{1,4}(Global\\[A-Za-z0-9]{8,40})\x00', data)
    if mutex_m:
        result['mutexes'].append(mutex_m.group(1).decode('ascii', errors='replace'))
        result['confidence'] += 5

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 4. TrickBot
# ---------------------------------------------------------------------------

def extract_trickbot_config(data: bytes):
    """Extract TrickBot configuration from binary data."""
    result = {
        'family': 'TrickBot',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # TrickBot embeds an XML config blob
    xml_start = data.find(b'<mcconf>')
    if xml_start == -1:
        xml_start = data.find(b'<?xml')
    if xml_start != -1:
        xml_end = data.find(b'</mcconf>', xml_start)
        if xml_end == -1:
            xml_end = xml_start + 8192
        xml_blob = data[xml_start:xml_end + 9]
        result['confidence'] += 40
        result['raw']['xml_snippet'] = xml_blob[:256].decode('utf-8', errors='replace')

        # Extract gtag (group/campaign tag)
        gtag_m = re.search(rb'<gtag>([^<]{1,32})</gtag>', xml_blob)
        if gtag_m:
            result['campaignId'] = gtag_m.group(1).decode('utf-8', errors='replace')
            result['confidence'] += 15

        # Extract C2 servers from <srv> or <server> tags
        for srv in re.findall(rb'<srv>([^<]+)</srv>', xml_blob):
            result['c2Servers'].append(srv.decode('utf-8', errors='replace').strip())
        for srv in re.findall(rb'<server>([^<]+)</server>', xml_blob):
            result['c2Servers'].append(srv.decode('utf-8', errors='replace').strip())
        if result['c2Servers']:
            result['confidence'] += 20

        # Bot version
        ver_m = re.search(rb'<ver>([^<]{1,16})</ver>', xml_blob)
        if ver_m:
            result['botId'] = ver_m.group(1).decode('utf-8', errors='replace')
            result['confidence'] += 5

    # Fallback: binary C2 list with port numbers packed as uint16
    if not result['c2Servers']:
        ips = extract_ipv4_addresses(data)
        if ips:
            result['c2Servers'] = ips[:10]
            result['confidence'] += 10

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 5. IcedID
# ---------------------------------------------------------------------------

def extract_icedid_config(data: bytes):
    """Extract IcedID configuration from binary data."""
    result = {
        'family': 'IcedID',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # IcedID loader carries a 24-byte header: magic(4) + campaign_id(4) + padding(16)
    ICEDID_MAGIC = b'\xBA\xBE\xFE\xCA'  # common loader magic variant
    ALT_MAGIC = b'\x4f\x49\x44\x00'     # "OID\x00"

    for magic in (ICEDID_MAGIC, ALT_MAGIC):
        off = data.find(magic)
        if off != -1 and off + 8 <= len(data):
            campaign_id = struct.unpack_from('<I', data, off + 4)[0]
            result['campaignId'] = hex(campaign_id)
            result['confidence'] += 35
            result['raw']['header_offset'] = off
            break

    # Domains encoded as XOR with campaign_id low byte
    if result['campaignId']:
        key = int(result['campaignId'], 16) & 0xFF
        decrypted = xor_decrypt(data, bytes([key]))
        domains = re.findall(
            rb'(?:[a-z0-9\-]{3,63}\.)+(?:com|net|org|ru|cc|pw|top|xyz|io)\b',
            decrypted, re.IGNORECASE
        )
        for d in domains[:10]:
            host = d.decode('ascii', errors='replace')
            if host not in result['c2Servers']:
                result['c2Servers'].append(host)
        if domains:
            result['confidence'] += 25

    # Plaintext domain scan fallback
    if not result['c2Servers']:
        domains = re.findall(
            rb'https?://([a-z0-9\-]{3,63}\.(?:com|net|org|ru|cc|pw|top))[/\x00]',
            data, re.IGNORECASE
        )
        for d in domains[:10]:
            result['c2Servers'].append(d.decode('ascii', errors='replace'))
        if result['c2Servers']:
            result['confidence'] += 15

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 6. BumbleBee
# ---------------------------------------------------------------------------

def extract_bumblebee_config(data: bytes):
    """Extract BumbleBee configuration from binary data."""
    result = {
        'family': 'BumbleBee',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # BumbleBee uses RC4 with a hardcoded key; common observed keys
    RC4_KEYS = [b'rSgvt3T', b'ivUFyNm', b'mQkFt5B', b'bumblebee', b'bLn3sV2']

    url_re = re.compile(
        rb'https?://(?:[a-z0-9\-]{1,63}\.)+[a-z]{2,10}(?:/[^\x00\s"\'<>]{0,128})?',
        re.IGNORECASE
    )

    best_key = None
    best_urls = []
    for key in RC4_KEYS:
        try:
            dec = rc4_decrypt(data[:65536], key)
            urls = url_re.findall(dec)
            if len(urls) > len(best_urls):
                best_urls = urls
                best_key = key
        except Exception:
            continue

    if best_urls:
        result['confidence'] += 40
        result['encryptionKeys'].append(best_key.decode('latin-1'))
        result['raw']['rc4_key'] = best_key.decode('latin-1')
        for u in best_urls[:10]:
            result['c2Servers'].append(u.decode('ascii', errors='replace'))

    # Botnet ID — typically a short alphanumeric string near "botid" marker
    botid_m = re.search(rb'(?:botid|bot_id|botnet)[\x00\x3a\x3d]{1,3}([A-Za-z0-9_\-]{4,24})', data)
    if botid_m:
        result['botId'] = botid_m.group(1).decode('ascii', errors='replace')
        result['confidence'] += 20

    # BUMBLEBEE mutex (observed format: {GUID})
    mutex_m = re.search(rb'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}', data)
    if mutex_m:
        result['mutexes'].append(mutex_m.group().decode('ascii'))
        result['confidence'] += 10

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 7. Raccoon Stealer
# ---------------------------------------------------------------------------

def extract_raccoon_config(data: bytes):
    """Extract Raccoon Stealer configuration from binary data."""
    result = {
        'family': 'RaccoonStealer',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    url_re = re.compile(
        rb'https?://[a-z0-9\-\.]{4,100}/[^\x00\s"\'<>\r\n]{0,200}',
        re.IGNORECASE
    )

    # Raccoon v1 stores gate URL as plaintext or base64
    # Try base64 windows across the binary
    gate_urls = []
    for b64_m in re.finditer(rb'[A-Za-z0-9+/]{32,256}={0,2}', data):
        try:
            dec = base64.b64decode(b64_m.group() + b'==')
            urls = url_re.findall(dec)
            gate_urls.extend(urls)
        except Exception:
            continue

    if gate_urls:
        result['confidence'] += 35
        for u in gate_urls[:5]:
            result['c2Servers'].append(u.decode('utf-8', errors='replace'))

    # Plaintext gate URLs (Raccoon v2 may embed directly)
    plain_urls = url_re.findall(data)
    for u in plain_urls[:10]:
        candidate = u.decode('utf-8', errors='replace')
        if candidate not in result['c2Servers']:
            result['c2Servers'].append(candidate)
    if plain_urls:
        result['confidence'] += 20

    # Raccoon marker strings
    for marker in (b'machineId=', b'raccoon', b'gate.php', b'logs.zip'):
        if marker in data.lower():
            result['confidence'] += 10
            break

    # Machine/bot ID format: "machineId=<hex>"
    mid_m = re.search(rb'machineId=([0-9a-fA-F]{16,32})', data)
    if mid_m:
        result['botId'] = mid_m.group(1).decode()
        result['confidence'] += 10

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 8. RedLine Stealer
# ---------------------------------------------------------------------------

def extract_redline_config(data: bytes):
    """Extract RedLine Stealer configuration from binary data."""
    result = {
        'family': 'RedLine',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # RedLine is a .NET binary; look for MVID or assembly metadata
    if b'mscoree.dll' in data or b'_CorExeMain' in data:
        result['confidence'] += 15
        result['raw']['platform'] = '.NET'

    # C2 stored as plain IP:port string in .NET string heap
    ip_port_re = re.compile(
        rb'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)):(\d{2,5})\b'
    )
    for m in ip_port_re.finditer(data):
        port = int(m.group(2))
        if 1024 <= port <= 65535:
            entry = '{}:{}'.format(m.group(1).decode(), m.group(2).decode())
            if entry not in result['c2Servers']:
                result['c2Servers'].append(entry)
    if result['c2Servers']:
        result['confidence'] += 35

    # Build ID — RedLine uses a short alphanumeric tag near "Build" string
    build_m = re.search(rb'(?:Build|build_id|buildID)[\x00\x3a\x3d\x09\x20]{0,4}([A-Za-z0-9_\-]{2,24})', data)
    if build_m:
        result['botId'] = build_m.group(1).decode('ascii', errors='replace')
        result['confidence'] += 15

    # Mutex (RedLine uses GUID-format or short string mutexes)
    mutex_m = re.search(
        rb'[\x00\x02\x04]([A-Za-z0-9_\-]{6,32}Mutex[A-Za-z0-9_\-]{0,16})\x00',
        data
    )
    if mutex_m:
        result['mutexes'].append(mutex_m.group(1).decode('ascii', errors='replace'))
        result['confidence'] += 5

    # .NET string-encoded C2 URLs
    urls = re.findall(
        rb'https?://(?:[a-z0-9\-]{1,63}\.)+[a-z]{2,10}(?::\d+)?(?:/[^\x00\s"\'<>]{0,128})?',
        data, re.IGNORECASE
    )
    for u in urls[:5]:
        candidate = u.decode('utf-8', errors='replace')
        if candidate not in result['c2Servers']:
            result['c2Servers'].append(candidate)
    if urls:
        result['confidence'] += 10

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 9. Vidar
# ---------------------------------------------------------------------------

def extract_vidar_config(data: bytes):
    """Extract Vidar configuration from binary data."""
    result = {
        'family': 'Vidar',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # Vidar stores profile ID and C2 URL separated by '|' in a plaintext block
    # Pattern: <profile_id>|<url>  or  <url>|<profile_id>
    pipe_m = re.search(
        rb'(\d{3,8})\|((https?://[^\x00\s\|"\'<>]{8,128}))',
        data
    )
    if pipe_m:
        result['campaignId'] = pipe_m.group(1).decode()
        result['c2Servers'].append(pipe_m.group(2).decode('utf-8', errors='replace'))
        result['confidence'] += 50

    # Alternative: URL first then pipe then ID
    pipe_m2 = re.search(
        rb'(https?://[^\x00\s\|"\'<>]{8,128})\|(\d{3,8})',
        data
    )
    if pipe_m2 and not result['c2Servers']:
        result['c2Servers'].append(pipe_m2.group(1).decode('utf-8', errors='replace'))
        result['campaignId'] = pipe_m2.group(2).decode()
        result['confidence'] += 50

    # Vidar also pulls additional modules from the C2; look for steam profile URLs
    steam_m = re.search(rb'steamcommunity\.com/profiles/\d+', data)
    if steam_m:
        result['confidence'] += 15
        result['raw']['steam_profile'] = steam_m.group().decode()

    # XOR-encoded variant: single byte key
    if not result['c2Servers']:
        for key in range(1, 256):
            dec = xor_decrypt(data[:32768], bytes([key]))
            m = re.search(rb'(\d{3,8})\|(https?://[^\x00\s\|"\'<>]{8,128})', dec)
            if m:
                result['campaignId'] = m.group(1).decode()
                result['c2Servers'].append(m.group(2).decode('utf-8', errors='replace'))
                result['encryptionKeys'].append(hex(key))
                result['confidence'] += 40
                break

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 10. FormBook / XLoader
# ---------------------------------------------------------------------------

def extract_formbook_config(data: bytes):
    """Extract FormBook/XLoader configuration from binary data."""
    result = {
        'family': 'FormBook',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # FormBook uses a 20-byte SHA1 hash as a key prefix before each C2 entry
    # RC4 key derived from SHA1(hardcoded_string)
    KNOWN_KEYS = [b'formbook', b'xloader', b'fbldr', b'\x41\x41\x41\x41\x41\x41\x41\x41']

    url_re = re.compile(
        rb'https?://[a-z0-9\-\.]{4,100}/[a-z0-9_\-/\.]{2,64}',
        re.IGNORECASE
    )

    # Try RC4 decryption with known keys
    best_urls = []
    used_key = None
    for key in KNOWN_KEYS:
        try:
            dec = rc4_decrypt(data[:65536], key)
            urls = url_re.findall(dec)
            if len(urls) > len(best_urls):
                best_urls = urls
                used_key = key
        except Exception:
            continue

    if best_urls:
        result['confidence'] += 40
        result['encryptionKeys'].append(used_key.hex() if isinstance(used_key, bytes) else used_key.decode())
        for u in best_urls[:10]:
            result['c2Servers'].append(u.decode('ascii', errors='replace'))

    # SHA1 block scan: 20-byte sequences followed by URL-like data
    sha1_re = re.compile(rb'[\x00-\xFF]{20}(https?://[^\x00\r\n"\'<>]{8,128})', re.IGNORECASE)
    for m in sha1_re.finditer(data):
        candidate = m.group(1).decode('utf-8', errors='replace')
        if candidate not in result['c2Servers']:
            result['c2Servers'].append(candidate)
            result['confidence'] += 10

    # FormBook marker string
    if b'formbook' in data.lower() or b'xloader' in data.lower():
        result['confidence'] += 20
        result['raw']['family_variant'] = 'XLoader' if b'xloader' in data.lower() else 'FormBook'

    # Campaign / web panel path (e.g., /fb/, /x1/)
    panel_m = re.search(rb'/(fb|x1|xl|frm|form)/[a-z0-9_\-]{1,20}/', data)
    if panel_m:
        result['campaignId'] = panel_m.group().decode('ascii', errors='replace')
        result['confidence'] += 10

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 11. LokiBot
# ---------------------------------------------------------------------------

def extract_lokibot_config(data: bytes):
    """Extract LokiBot configuration from binary data."""
    result = {
        'family': 'LokiBot',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # LokiBot gate URLs typically end with /fre.php or /login/process.php
    gate_patterns = [
        rb'https?://[^\x00\s"\'<>\r\n]{4,200}/fre\.php',
        rb'https?://[^\x00\s"\'<>\r\n]{4,200}/login/process\.php',
        rb'https?://[^\x00\s"\'<>\r\n]{4,200}/gate\.php',
    ]

    for pat in gate_patterns:
        for m in re.finditer(pat, data, re.IGNORECASE):
            url = m.group().decode('utf-8', errors='replace')
            if url not in result['c2Servers']:
                result['c2Servers'].append(url)
                result['confidence'] += 30

    # FTP C2 — LokiBot can exfiltrate via FTP
    ftp_m = re.findall(rb'ftp://[^\x00\s"\'<>\r\n]{4,200}', data)
    for ftp in ftp_m[:3]:
        result['c2Servers'].append(ftp.decode('utf-8', errors='replace'))
        result['confidence'] += 15

    # SMTP credentials
    smtp_m = re.search(rb'smtp(?:\.|\x00)([^\x00\r\n"\'<>\s]{4,100})', data, re.IGNORECASE)
    if smtp_m:
        result['raw']['smtp_host'] = smtp_m.group(1).decode('utf-8', errors='replace')
        result['confidence'] += 10

    # LokiBot mutex: lowercase hex string
    mutex_m = re.search(rb'\b([0-9a-f]{32})\b', data)
    if mutex_m:
        result['mutexes'].append(mutex_m.group(1).decode())
        result['confidence'] += 5

    # Password field near gate URL
    pass_m = re.search(rb'(?:pass|password|key)[\x00\x3a\x3d]{0,2}([^\x00\r\n\s"\'<>]{4,32})', data, re.IGNORECASE)
    if pass_m:
        result['encryptionKeys'].append(pass_m.group(1).decode('utf-8', errors='replace'))

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 12. NjRAT
# ---------------------------------------------------------------------------

def extract_njrat_config(data: bytes):
    """Extract NjRAT configuration from binary data."""
    result = {
        'family': 'NjRAT',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # NjRAT is a .NET RAT; config often stored as plaintext strings in assembly
    if b'mscoree.dll' in data or b'njrat' in data.lower() or b'Bladabindi' in data:
        result['confidence'] += 20

    # Host:port pattern — NjRAT stores C2 as plain strings
    host_port_m = re.findall(
        rb'[\x00\x02\x04\x06\x08]([a-z0-9\.\-]{4,100})\x00{0,2}[\x02\x04\x06\x08](\d{2,5})\x00',
        data, re.IGNORECASE
    )
    for host, port in host_port_m[:5]:
        entry = '{}:{}'.format(host.decode('ascii', errors='replace'), port.decode())
        if entry not in result['c2Servers']:
            result['c2Servers'].append(entry)
    if result['c2Servers']:
        result['confidence'] += 35

    # Campaign name — stored near "cam" or "campaign" string
    cam_m = re.search(rb'[\x02\x04\x06\x08]([A-Za-z0-9_\-\.]{2,32})\x00{0,2}[\x02\x04\x06\x08]HJ', data)
    if cam_m:
        result['campaignId'] = cam_m.group(1).decode('ascii', errors='replace')
        result['confidence'] += 10

    # Mutex — typically the campaign name + "---" suffix or just alphanumeric
    mutex_m = re.search(rb'([A-Za-z0-9_\-\.]{4,32})(?:---|\x00{2})', data)
    if mutex_m:
        result['mutexes'].append(mutex_m.group(1).decode('ascii', errors='replace'))
        result['confidence'] += 10

    # Version string (e.g., "0.7d" or "0.6.4")
    ver_m = re.search(rb'\b(0\.[0-9][a-z]?(?:\.[0-9]+)?)\b', data)
    if ver_m:
        result['botId'] = ver_m.group(1).decode()
        result['confidence'] += 5

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 13. DarkComet
# ---------------------------------------------------------------------------

def extract_darkcomet_config(data: bytes):
    """Extract DarkComet configuration from binary data."""
    result = {
        'family': 'DarkComet',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # DarkComet marker strings
    for marker in (b'DARKCOMET', b'DarkComet', b'DC2750', b'DC_MUTEX'):
        if marker in data:
            result['confidence'] += 20
            result['raw']['marker'] = marker.decode('ascii', errors='replace')
            break

    # RC4 key stored near "KEYLOGS" or "KEYLOGGER" string
    RC4_MARKER = b'KEYLOGGER'
    km = data.find(RC4_MARKER)
    rc4_key = None
    if km != -1 and km + 64 <= len(data):
        # Key is typically 4-16 bytes immediately following the marker
        key_candidate = data[km + len(RC4_MARKER):km + len(RC4_MARKER) + 16].split(b'\x00')[0]
        if key_candidate:
            rc4_key = key_candidate
            result['encryptionKeys'].append(key_candidate.decode('latin-1'))
            result['confidence'] += 15

    # C2 host:port — plaintext or RC4 decrypted
    url_re = re.compile(rb'([a-z0-9\.\-]{4,64}):(\d{2,5})', re.IGNORECASE)
    search_data = data
    if rc4_key:
        try:
            search_data = rc4_decrypt(data[:65536], rc4_key)
        except Exception:
            pass

    for m in url_re.finditer(search_data):
        port = int(m.group(2))
        if 1 <= port <= 65535:
            entry = '{}:{}'.format(m.group(1).decode('ascii', errors='replace'), m.group(2).decode())
            if entry not in result['c2Servers']:
                result['c2Servers'].append(entry)
    if result['c2Servers']:
        result['confidence'] += 30

    # Mutex (DC_MUTEX- prefix)
    mutex_m = re.search(rb'DC_MUTEX-([A-Za-z0-9_]{4,32})', data)
    if mutex_m:
        result['mutexes'].append('DC_MUTEX-' + mutex_m.group(1).decode('ascii', errors='replace'))
        result['confidence'] += 10

    # Campaign / FWB (FWB = "from where bot" campaign tag)
    fwb_m = re.search(rb'FWB[\x00\x3d\x7c]([^\x00\r\n"\'<>\s]{2,32})', data)
    if fwb_m:
        result['campaignId'] = fwb_m.group(1).decode('utf-8', errors='replace')
        result['confidence'] += 10

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 14. Ursnif / Gozi
# ---------------------------------------------------------------------------

def extract_ursnif_config(data: bytes):
    """Extract Ursnif/Gozi configuration from binary data."""
    result = {
        'family': 'Ursnif',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # Ursnif config block starts with a recognizable header
    # The config is typically Serpent-encrypted; we look for the decrypted form
    # after XOR with a 4-byte key found in the binary
    GOZI_TAG = b'Gozi'
    URSNIF_TAG = b'ursnif'
    if GOZI_TAG in data or URSNIF_TAG in data.lower():
        result['confidence'] += 15

    # Botnet ID stored as a DWORD near the config header
    botid_m = re.search(rb'(?:bot_id|botid|group)[\x00\x3a\x3d]{0,3}([\x00-\xFF]{4})', data, re.IGNORECASE)
    if botid_m:
        botid_val = struct.unpack('<I', botid_m.group(1))[0]
        result['botId'] = str(botid_val)
        result['confidence'] += 20

    # XOR scan for C2 domain list (4-byte rolling XOR is common in Ursnif)
    ip_domain_re = re.compile(
        rb'(?:[a-z0-9\-]{3,63}\.)+(?:com|net|org|biz|info|ru|cc)\b',
        re.IGNORECASE
    )
    for key_int in range(0x01000000, 0xFF000000, 0x01010101):
        key_bytes = struct.pack('>I', key_int)
        chunk = data[:32768]
        dec = xor_decrypt(chunk, key_bytes)
        domains = ip_domain_re.findall(dec)
        if len(domains) >= 2:
            result['encryptionKeys'].append(key_bytes.hex())
            for d in domains[:10]:
                result['c2Servers'].append(d.decode('ascii', errors='replace'))
            result['confidence'] += 35
            break

    # Fallback: plaintext domains
    if not result['c2Servers']:
        for d in ip_domain_re.findall(data)[:10]:
            result['c2Servers'].append(d.decode('ascii', errors='replace'))
        if result['c2Servers']:
            result['confidence'] += 10

    # Server URL path characteristic of Ursnif (/<random>/login.php or similar)
    path_m = re.search(rb'/[A-Za-z0-9]{8}/(?:login|news|images)\.php', data)
    if path_m:
        result['raw']['url_path'] = path_m.group().decode('ascii')
        result['confidence'] += 15

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 15. Dridex
# ---------------------------------------------------------------------------

def extract_dridex_config(data: bytes):
    """Extract Dridex configuration from binary data."""
    result = {
        'family': 'Dridex',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # Dridex embeds an RC4-encrypted config blob
    # Known botnet IDs: 200, 300, 385, 220, 7200
    KNOWN_BOTNET_IDS = [200, 300, 385, 220, 7200, 10111, 10222]

    # Botnet ID stored as DWORD in config header
    for bid in KNOWN_BOTNET_IDS:
        bid_bytes = struct.pack('<I', bid)
        if bid_bytes in data:
            result['botId'] = str(bid)
            result['campaignId'] = str(bid)
            result['confidence'] += 30
            result['raw']['botnet_id'] = bid
            break

    # RC4 key commonly follows a 4-byte length prefix
    # Try common key patterns derived from botnet ID
    RC4_KEYS = [b'\x08\x00\x00\x00', b'dridex', b'\xde\xad\xbe\xef']
    if result['botId']:
        RC4_KEYS.insert(0, struct.pack('<I', int(result['botId'])))

    ip_port_re = re.compile(
        rb'((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)):(\d{2,5})'
    )

    for key in RC4_KEYS:
        try:
            dec = rc4_decrypt(data[:65536], key)
            matches = ip_port_re.findall(dec)
            if matches:
                result['encryptionKeys'].append(key.hex())
                for ip, port in matches[:15]:
                    entry = '{}:{}'.format(ip.decode(), port.decode())
                    if entry not in result['c2Servers']:
                        result['c2Servers'].append(entry)
                result['confidence'] += 35
                break
        except Exception:
            continue

    # Fallback: plaintext IPs
    if not result['c2Servers']:
        for ip, port in ip_port_re.findall(data)[:10]:
            entry = '{}:{}'.format(ip.decode(), port.decode())
            result['c2Servers'].append(entry)
        if result['c2Servers']:
            result['confidence'] += 10

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 16. BazarLoader
# ---------------------------------------------------------------------------

def extract_bazarloader_config(data: bytes):
    """Extract BazarLoader configuration from binary data."""
    result = {
        'family': 'BazarLoader',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # BazarLoader uses XOR-encoded C2 list with a multi-byte key
    # Also uses blockchain DNS (Emercoin .bazar TLD) as backup
    bazar_re = re.compile(rb'[a-z0-9\-]{3,32}\.bazar\b', re.IGNORECASE)
    bazar_domains = bazar_re.findall(data)
    if bazar_domains:
        result['confidence'] += 30
        for d in bazar_domains[:5]:
            result['c2Servers'].append(d.decode('ascii', errors='replace'))
        result['raw']['blockchain_dns'] = True

    # Primary C2 over HTTPS — look after XOR decryption
    for key_len in (4, 8, 16):
        for offset in range(0, min(256, len(data) - key_len)):
            key = data[offset:offset + key_len]
            if len(set(key)) < 2:
                continue
            dec = xor_decrypt(data[:65536], key)
            urls = re.findall(
                rb'https?://[a-z0-9\.\-]{4,64}/[a-z0-9/\.\-_]{2,64}',
                dec, re.IGNORECASE
            )
            if urls:
                result['encryptionKeys'].append(key.hex())
                for u in urls[:5]:
                    candidate = u.decode('utf-8', errors='replace')
                    if candidate not in result['c2Servers']:
                        result['c2Servers'].append(candidate)
                result['confidence'] += 35
                break
        if result['encryptionKeys']:
            break

    # Tor backup C2
    onions = re.findall(rb'[a-z2-7]{16,56}\.onion', data)
    for o in onions[:3]:
        result['c2Servers'].append(o.decode('ascii'))
    if onions:
        result['confidence'] += 15

    # Team9 (BazarLoader internal name)
    if b'team9' in data.lower() or b'bazar' in data.lower():
        result['confidence'] += 10

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 17. SystemBC
# ---------------------------------------------------------------------------

def extract_systembc_config(data: bytes):
    """Extract SystemBC configuration from binary data."""
    result = {
        'family': 'SystemBC',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # SystemBC stores host, port, and Tor proxy config as plaintext or XOR
    # Known marker bytes that appear before the config struct
    MARKERS = [b'socks5', b'SOCKS5', b'tor', b'\x53\x59\x53\x42\x43']

    for marker in MARKERS:
        if marker in data:
            result['confidence'] += 15
            result['raw']['marker'] = marker.decode('latin-1')
            break

    # Config layout: [host\x00][port_uint16][xor_key_4bytes][tor_host\x00][tor_port_uint16]
    host_port_re = re.compile(
        rb'([a-z0-9\.\-]{4,64})\x00([\x00-\xFF]{2})',
        re.IGNORECASE
    )
    for m in host_port_re.finditer(data):
        host = m.group(1)
        port = struct.unpack('>H', m.group(2))[0]
        if 1024 <= port <= 65535 and b'.' in host:
            entry = '{}:{}'.format(host.decode('ascii', errors='replace'), port)
            if entry not in result['c2Servers']:
                result['c2Servers'].append(entry)
    if result['c2Servers']:
        result['confidence'] += 35

    # XOR key — 4 bytes after host:port block
    xor_m = re.search(rb'(?:xor|key)[\x00]{0,2}([\x01-\xFF]{4})', data, re.IGNORECASE)
    if xor_m:
        xor_key = xor_m.group(1)
        result['encryptionKeys'].append(xor_key.hex())
        result['confidence'] += 10

    # Tor proxy host (typically 127.0.0.1 or localhost with port 9050/9150)
    tor_m = re.search(rb'(127\.0\.0\.1|localhost)[\x00]{0,2}([\x00-\xFF]{2})', data)
    if tor_m:
        tor_port = struct.unpack('>H', tor_m.group(2))[0]
        if tor_port in (9050, 9150, 1080):
            result['raw']['tor_proxy'] = '{}:{}'.format(
                tor_m.group(1).decode(), tor_port
            )
            result['confidence'] += 15

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 18. SmokeLoader
# ---------------------------------------------------------------------------

def extract_smokeloader_config(data: bytes):
    """Extract SmokeLoader configuration from binary data."""
    result = {
        'family': 'SmokeLoader',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # SmokeLoader uses RC4 with a key embedded in the binary
    # The encrypted blob is typically preceded by its size as DWORD
    SMOKE_TAGS = [b'smoke', b'SmokeLdr', b'\x53\x4d\x4b']
    for tag in SMOKE_TAGS:
        if tag in data:
            result['confidence'] += 15
            break

    # Scan for 4-byte size prefix followed by RC4-encrypted data
    url_re = re.compile(
        rb'https?://[a-z0-9\.\-]{4,100}/[a-z0-9_\.\-/]{1,128}',
        re.IGNORECASE
    )

    RC4_KEYS = [b'smoke', b'ldr', b'loader', b'\x00\x01\x02\x03\x04\x05\x06\x07']
    best_key = None
    best_urls = []

    for key in RC4_KEYS:
        try:
            dec = rc4_decrypt(data[:131072], key)
            urls = url_re.findall(dec)
            if len(urls) > len(best_urls):
                best_urls = urls
                best_key = key
        except Exception:
            continue

    if best_urls:
        result['confidence'] += 40
        result['encryptionKeys'].append(best_key.hex())
        for u in best_urls[:10]:
            result['c2Servers'].append(u.decode('utf-8', errors='replace'))

    # Plaintext fallback
    if not result['c2Servers']:
        for u in url_re.findall(data)[:10]:
            result['c2Servers'].append(u.decode('utf-8', errors='replace'))
        if result['c2Servers']:
            result['confidence'] += 15

    # Bot/version ID
    ver_m = re.search(rb'(?:ver|version|build)[\x00\x3a]{0,2}([0-9]{1,5})', data, re.IGNORECASE)
    if ver_m:
        result['botId'] = ver_m.group(1).decode()
        result['confidence'] += 10

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 19. Amadey
# ---------------------------------------------------------------------------

def extract_amadey_config(data: bytes):
    """Extract Amadey configuration from binary data."""
    result = {
        'family': 'Amadey',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # Amadey stores C2 URL and panel path as plaintext in the binary
    url_re = re.compile(
        rb'https?://[a-z0-9\.\-]{4,100}/[a-z0-9_\.\-/]{0,128}(?:index|gate|panel|admin)\.php',
        re.IGNORECASE
    )
    matches = url_re.findall(data)
    for u in matches[:5]:
        result['c2Servers'].append(u.decode('utf-8', errors='replace'))
    if matches:
        result['confidence'] += 45

    # Fallback: any URL with .php gate path
    if not result['c2Servers']:
        generic_urls = re.findall(
            rb'https?://[a-z0-9\.\-]{4,100}/[a-z0-9_/\.\-]{1,128}\.php',
            data, re.IGNORECASE
        )
        for u in generic_urls[:5]:
            result['c2Servers'].append(u.decode('utf-8', errors='replace'))
        if result['c2Servers']:
            result['confidence'] += 20

    # Bot version — Amadey uses format like "3.21" or "4.02"
    ver_m = re.search(rb'\b([0-9]\.[0-9]{2})\b', data)
    if ver_m:
        result['botId'] = ver_m.group(1).decode()
        result['confidence'] += 10

    # Amadey mutex (often GUID or fixed string)
    mutex_m = re.search(
        rb'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}',
        data
    )
    if mutex_m:
        result['mutexes'].append(mutex_m.group().decode())
        result['confidence'] += 5

    # Amadey string markers
    for marker in (b'amadey', b'Amadey', b'amd_'):
        if marker in data:
            result['confidence'] += 15
            break

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 20. StealC
# ---------------------------------------------------------------------------

def extract_stealc_config(data: bytes):
    """Extract StealC configuration from binary data."""
    result = {
        'family': 'StealC',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # StealC stores C2 URL + build ID in a plaintext config block
    # Config block often preceded by a known marker sequence
    MARKER = b'stealc'
    if MARKER in data.lower():
        result['confidence'] += 20

    # URL extraction — StealC typically uses a flat HTTP gate
    url_re = re.compile(
        rb'https?://[a-z0-9\.\-]{4,100}/[a-z0-9_/\.\-]{0,128}',
        re.IGNORECASE
    )
    urls = url_re.findall(data)
    for u in urls[:10]:
        result['c2Servers'].append(u.decode('utf-8', errors='replace'))
    if urls:
        result['confidence'] += 30

    # Build ID — alphanumeric string near "build" keyword
    build_m = re.search(
        rb'(?:build|bid|build_id)[\x00\x3a\x3d\x09\x20]{0,4}([A-Za-z0-9_\-]{4,24})',
        data, re.IGNORECASE
    )
    if build_m:
        result['botId'] = build_m.group(1).decode('ascii', errors='replace')
        result['confidence'] += 20

    # Config block: look for null-terminated strings in a sequence
    config_block_m = re.search(
        rb'(https?://[^\x00]{8,128})\x00([A-Za-z0-9_\-]{4,24})\x00',
        data, re.IGNORECASE
    )
    if config_block_m:
        url_part = config_block_m.group(1).decode('utf-8', errors='replace')
        bid_part = config_block_m.group(2).decode('ascii', errors='replace')
        if url_part not in result['c2Servers']:
            result['c2Servers'].append(url_part)
        if not result['botId']:
            result['botId'] = bid_part
        result['confidence'] += 20

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 21. Lumma Stealer
# ---------------------------------------------------------------------------

def extract_lumma_config(data: bytes):
    """Extract Lumma Stealer configuration from binary data."""
    result = {
        'family': 'LummaStealer',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # Lumma Stealer markers
    for marker in (b'lumma', b'LummaC', b'lummac2'):
        if marker in data.lower():
            result['confidence'] += 20
            result['raw']['marker'] = marker.decode()
            break

    # C2 URLs — Lumma uses rotating C2 domains
    url_re = re.compile(
        rb'https?://[a-z0-9\.\-]{4,100}/api/[a-z0-9_/\.\-]{0,64}',
        re.IGNORECASE
    )
    for u in url_re.findall(data)[:5]:
        result['c2Servers'].append(u.decode('utf-8', errors='replace'))
    if result['c2Servers']:
        result['confidence'] += 30

    # XOR decrypt to find encoded C2 list
    if not result['c2Servers']:
        for key in range(1, 256):
            dec = xor_decrypt(data[:65536], bytes([key]))
            urls = url_re.findall(dec)
            if urls:
                result['encryptionKeys'].append(hex(key))
                for u in urls[:5]:
                    result['c2Servers'].append(u.decode('utf-8', errors='replace'))
                result['confidence'] += 30
                break

    # Build ID (Lumma uses short alphanumeric build tags)
    build_m = re.search(
        rb'[\x00\x02\x04]([A-Za-z0-9]{6,20})[\x00\x02\x04](?=.{0,8}https?://)',
        data
    )
    if build_m:
        result['botId'] = build_m.group(1).decode('ascii', errors='replace')
        result['confidence'] += 15

    # Steam Community profile backup C2 (Lumma uses this like Vidar)
    steam_m = re.search(rb'steamcommunity\.com/profiles/\d+', data)
    if steam_m:
        result['raw']['steam_c2'] = steam_m.group().decode()
        result['confidence'] += 10

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 22. Pikabot
# ---------------------------------------------------------------------------

def extract_pikabot_config(data: bytes):
    """Extract Pikabot configuration from binary data."""
    result = {
        'family': 'Pikabot',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # Pikabot markers
    for marker in (b'pikabot', b'pika_bot', b'PIKABOT'):
        if marker in data.lower():
            result['confidence'] += 20
            break

    # Pikabot uses RC4 or AES for config encryption
    # RC4 attempt with known/derived keys
    url_re = re.compile(
        rb'https?://[a-z0-9\.\-]{4,100}(?::\d+)?/[a-z0-9_/\.\-]{0,128}',
        re.IGNORECASE
    )

    RC4_KEYS = [b'pikabot', b'pika', b'\x50\x69\x6b\x61', b'\x00' * 16]
    for key in RC4_KEYS:
        try:
            dec = rc4_decrypt(data[:131072], key)
            urls = url_re.findall(dec)
            if urls:
                result['encryptionKeys'].append(key.hex())
                result['raw']['cipher'] = 'RC4'
                for u in urls[:10]:
                    result['c2Servers'].append(u.decode('utf-8', errors='replace'))
                result['confidence'] += 40
                break
        except Exception:
            continue

    # AES-CBC: look for 16-byte IV + 16-byte aligned ciphertext blocks
    # (heuristic: 16 high-entropy bytes followed by more high-entropy bytes)
    if not result['c2Servers']:
        for off in range(0, min(len(data) - 48, 65536), 16):
            block = data[off:off + 48]
            entropy = len(set(block)) / 48.0
            if entropy > 0.9:
                result['raw']['aes_candidate_offset'] = off
                result['confidence'] += 10
                break

    # Campaign ID near "campaign" or "camp" string
    camp_m = re.search(
        rb'(?:campaign|camp_id)[\x00\x3a\x3d]{0,3}([A-Za-z0-9_\-]{4,24})',
        data, re.IGNORECASE
    )
    if camp_m:
        result['campaignId'] = camp_m.group(1).decode('ascii', errors='replace')
        result['confidence'] += 15

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 23. DarkGate
# ---------------------------------------------------------------------------

def extract_darkgate_config(data: bytes):
    """Extract DarkGate configuration from binary data."""
    result = {
        'family': 'DarkGate',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # DarkGate uses XOR + Base64 encoding for config
    # Marker strings
    for marker in (b'darkgate', b'DarkGate', b'DARKGATE', b'dark_gate'):
        if marker in data.lower():
            result['confidence'] += 20
            break

    url_re = re.compile(
        rb'https?://[a-z0-9\.\-]{4,100}(?::\d+)?(?:/[^\x00\s"\'<>\r\n]{0,128})?',
        re.IGNORECASE
    )

    # Base64 decode attempts
    for b64_m in re.finditer(rb'[A-Za-z0-9+/]{48,512}={0,2}', data):
        try:
            dec = base64.b64decode(b64_m.group() + b'==')
        except Exception:
            continue
        # Try XOR with single byte on the decoded data
        for key in range(1, 256):
            xdec = xor_decrypt(dec, bytes([key]))
            urls = url_re.findall(xdec)
            if urls:
                result['encryptionKeys'].append(hex(key))
                result['raw']['encoding'] = 'base64+xor'
                for u in urls[:10]:
                    result['c2Servers'].append(u.decode('utf-8', errors='replace'))
                result['confidence'] += 45
                break
        if result['c2Servers']:
            break

    # Plaintext fallback
    if not result['c2Servers']:
        for u in url_re.findall(data)[:5]:
            result['c2Servers'].append(u.decode('utf-8', errors='replace'))
        if result['c2Servers']:
            result['confidence'] += 15

    # Campaign/license key — DarkGate uses a licence key as campaign marker
    lic_m = re.search(
        rb'(?:license|lic_key|campaign)[\x00\x3a\x3d]{0,3}([A-Za-z0-9_\-]{8,48})',
        data, re.IGNORECASE
    )
    if lic_m:
        result['campaignId'] = lic_m.group(1).decode('ascii', errors='replace')
        result['confidence'] += 10

    # Mutex
    mutex_m = re.search(
        rb'([A-Za-z0-9]{16,32}_mutex)\x00',
        data
    )
    if mutex_m:
        result['mutexes'].append(mutex_m.group(1).decode('ascii', errors='replace'))
        result['confidence'] += 5

    return result if result['confidence'] > 0 else None


# ---------------------------------------------------------------------------
# 24. Latrodectus
# ---------------------------------------------------------------------------

def extract_latrodectus_config(data: bytes):
    """Extract Latrodectus configuration from binary data."""
    result = {
        'family': 'Latrodectus',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }

    # Latrodectus (successor to IcedID) markers
    for marker in (b'latrodectus', b'LATRODECTUS', b'latr_'):
        if marker in data.lower():
            result['confidence'] += 20
            break

    # Config is RC4-encrypted; key is derived from a hardcoded seed
    # Also uses XOR with campaign-ID-derived key (shares IcedID lineage)
    url_re = re.compile(
        rb'https?://[a-z0-9\.\-]{4,100}(?::\d+)?/[a-z0-9_/\.\-]{0,128}',
        re.IGNORECASE
    )

    RC4_KEYS = [b'latrodectus', b'latr', b'icedid', b'\x4c\x61\x74\x72']
    for key in RC4_KEYS:
        try:
            dec = rc4_decrypt(data[:131072], key)
            urls = url_re.findall(dec)
            if urls:
                result['encryptionKeys'].append(key.decode('latin-1'))
                for u in urls[:10]:
                    result['c2Servers'].append(u.decode('utf-8', errors='replace'))
                result['confidence'] += 40
                result['raw']['cipher'] = 'RC4'
                break
        except Exception:
            continue

    # Campaign ID (4-byte DWORD, IcedID-style header)
    MAGIC_CANDIDATES = [b'\xBA\xBE\xFE\xCA', b'\xCA\xFE\xBA\xBE', b'\xDE\xAD\xBE\xEF']
    for magic in MAGIC_CANDIDATES:
        off = data.find(magic)
        if off != -1 and off + 8 <= len(data):
            cid = struct.unpack_from('<I', data, off + 4)[0]
            result['campaignId'] = hex(cid)
            result['confidence'] += 25
            result['raw']['magic'] = magic.hex()
            # Also try XOR with low byte of campaign ID
            key_byte = cid & 0xFF
            if key_byte:
                dec = xor_decrypt(data[:65536], bytes([key_byte]))
                for u in url_re.findall(dec)[:5]:
                    candidate = u.decode('utf-8', errors='replace')
                    if candidate not in result['c2Servers']:
                        result['c2Servers'].append(candidate)
                if not result['encryptionKeys']:
                    result['encryptionKeys'].append(hex(key_byte))
                    result['confidence'] += 15
            break

    # Plaintext C2 fallback
    if not result['c2Servers']:
        for u in url_re.findall(data)[:5]:
            result['c2Servers'].append(u.decode('utf-8', errors='replace'))
        if result['c2Servers']:
            result['confidence'] += 10

    # Mutex
    mutex_m = re.search(
        rb'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}',
        data
    )
    if mutex_m:
        result['mutexes'].append(mutex_m.group().decode('ascii'))
        result['confidence'] += 5

    return result if result['confidence'] > 0 else None
