
def extract_rhadamanthys_config(data):
    """Extract Rhadamanthys configuration from binary data."""
    result = {
        'family': 'Rhadamanthys',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re, struct

    text = data.decode('latin-1', errors='ignore')

    # Rhadamanthys embeds Lua scripts and C2 as plaintext or XOR-0x25 encoded
    # Look for embedded Lua script markers
    lua_marker_idx = data.find(b'\x1bLua')
    if lua_marker_idx < 0:
        lua_marker_idx = data.find(b'--[[')
    if lua_marker_idx >= 0:
        result['raw']['lua_offset'] = hex(lua_marker_idx)
        result['confidence'] += 20

    # C2 stored as length-prefixed UTF-16 or ASCII after XOR-0x25
    for xor_key in [0x25, 0x17, 0x3f, 0x00]:
        chunk = data[max(0, lua_marker_idx - 4096):lua_marker_idx + 4096] if lua_marker_idx >= 0 else data
        decrypted = xor_decrypt(chunk, xor_key) if xor_key != 0x00 else chunk
        urls = extract_urls(decrypted)
        if urls:
            result['c2Servers'].extend(urls[:10])
            result['raw']['xor_key'] = hex(xor_key)
            result['confidence'] += 40
            break

    # Rhadamanthys stores campaign tag as 8-char hex after marker b'\xDE\xAD\xBE\xEF'
    marker_idx = data.find(b'\xde\xad\xbe\xef')
    if marker_idx >= 0 and marker_idx + 12 <= len(data):
        tag_bytes = data[marker_idx + 4:marker_idx + 12]
        try:
            result['campaignId'] = tag_bytes.decode('ascii', errors='replace').strip('\x00')
            result['confidence'] += 15
        except Exception:
            pass

    # Fallback: grep for https:// C2 URLs
    if not result['c2Servers']:
        result['c2Servers'] = extract_urls(data)[:10]
        if result['c2Servers']:
            result['confidence'] += 30

    # Extract XOR key from config header (offset 0x10, 4 bytes)
    if len(data) >= 0x14:
        key_candidate = data[0x10:0x14]
        result['encryptionKeys'].append(key_candidate.hex())

    # Mutex: Rhadamanthys uses GUID-like mutex embedded as UTF-8
    mutex_match = re.search(r'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}', text)
    if mutex_match:
        result['mutexes'].append(mutex_match.group(0))

    return result if result['confidence'] > 0 else None


def extract_plugx_config(data):
    """Extract PlugX/Korplug configuration from binary data."""
    result = {
        'family': 'PlugX',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import struct, re

    # PlugX config signature: magic dword 0x504C5547 ("PLUG") or 0x58474F4C ("XGOL")
    PLUG_MAGIC = b'PLUG'
    XGOL_MAGIC = b'XGOL'

    config_offset = -1
    for magic in [PLUG_MAGIC, XGOL_MAGIC]:
        idx = data.find(magic)
        if idx >= 0:
            config_offset = idx
            result['raw']['magic'] = magic.decode('ascii')
            result['confidence'] += 30
            break

    # XOR key at fixed offset relative to magic (0x04, single byte, common: 0xFF, 0xA3, 0x53)
    raw_config = None
    if config_offset >= 0 and config_offset + 0x150 <= len(data):
        for xor_key in [0xFF, 0xA3, 0x53, 0x00]:
            chunk = data[config_offset:config_offset + 0x400]
            candidate = xor_decrypt(chunk, xor_key) if xor_key != 0x00 else chunk
            # Config starts with size dword, then C2 host at offset 0x08
            if len(candidate) >= 0x50:
                host_bytes = candidate[0x08:0x58]
                host = host_bytes.split(b'\x00')[0].decode('ascii', errors='ignore')
                if re.match(r'^[a-zA-Z0-9._\-]{4,}$', host) and '.' in host:
                    raw_config = candidate
                    result['encryptionKeys'].append(hex(xor_key))
                    break

    if raw_config is not None and len(raw_config) >= 0x100:
        # C2 hosts: three slots at 0x08, 0x68, 0xC8, each 80 bytes
        for slot_offset in [0x08, 0x68, 0xC8]:
            if slot_offset + 80 > len(raw_config):
                break
            host = raw_config[slot_offset:slot_offset + 80].split(b'\x00')[0].decode('ascii', errors='ignore').strip()
            if host and re.match(r'^[a-zA-Z0-9._\-]{3,}$', host):
                port_offset = slot_offset + 80
                if port_offset + 2 <= len(raw_config):
                    port = struct.unpack('<H', raw_config[port_offset:port_offset + 2])[0]
                    result['c2Servers'].append(f"{host}:{port}" if 0 < port < 65535 else host)
        # Mutex at offset 0x1A0
        if len(raw_config) >= 0x1E0:
            mutex = raw_config[0x1A0:0x1C0].split(b'\x00')[0].decode('utf-16-le', errors='ignore').strip()
            if mutex:
                result['mutexes'].append(mutex)
        # Campaign ID at 0x1C0
        camp = raw_config[0x1C0:0x1D0].split(b'\x00')[0].decode('ascii', errors='ignore').strip()
        if camp:
            result['campaignId'] = camp
        result['confidence'] += 55

    # Fallback
    if not result['c2Servers']:
        result['c2Servers'] = extract_ipv4_addresses(data)[:5]
        if result['c2Servers']:
            result['confidence'] = max(result['confidence'], 30)

    return result if result['confidence'] > 0 else None


def extract_shadowpad_config(data):
    """Extract ShadowPad configuration from binary data."""
    result = {
        'family': 'ShadowPad',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import struct, re

    # ShadowPad uses a custom XOR+ROL cipher; config blob starts with marker 0xCEFA1234
    SHADOWPAD_MAGIC = b'\x34\x12\xFA\xCE'
    # Also seen: 0x3C909090 NOP sled predecessor, or PE shellcode prefix
    idx = data.find(SHADOWPAD_MAGIC)
    if idx < 0:
        # Try XOR-0x41 decode of first 64KB
        decrypted = xor_decrypt(data[:65536], 0x41)
        idx = decrypted.find(SHADOWPAD_MAGIC)
        if idx >= 0:
            data = decrypted + data[65536:]
            result['encryptionKeys'].append('0x41')
            result['confidence'] += 20

    if idx >= 0:
        result['confidence'] += 30
        config_blob = data[idx + 4:]
        if len(config_blob) >= 8:
            blob_size = struct.unpack('<I', config_blob[:4])[0]
            # Decrypt inner config: XOR with rolling key derived from blob_size
            key = blob_size & 0xFF
            inner = xor_decrypt(config_blob[4:min(blob_size + 4, len(config_blob))], key)
            result['encryptionKeys'].append(hex(key))

            # Module list: each module starts with 4-byte module ID
            # C2 module ID: 0x00000400
            c2_module_marker = b'\x00\x04\x00\x00'
            c2_idx = inner.find(c2_module_marker)
            if c2_idx >= 0:
                c2_data = inner[c2_idx + 4:]
                # C2 entries: 2-byte count, then null-terminated host strings + 2-byte port
                host = c2_data.split(b'\x00')[0].decode('ascii', errors='ignore').strip()
                if host and len(host) > 3:
                    port_off = len(host) + 1
                    if port_off + 2 <= len(c2_data):
                        port = struct.unpack('<H', c2_data[port_off:port_off + 2])[0]
                        result['c2Servers'].append(f"{host}:{port}")
                    else:
                        result['c2Servers'].append(host)
                result['confidence'] += 40

    # Fallback: extract IPs/URLs from raw data
    if not result['c2Servers']:
        result['c2Servers'] = extract_ipv4_addresses(data)[:8]
        result['c2Servers'] += extract_urls(data)[:5]
        if result['c2Servers']:
            result['confidence'] = max(result['confidence'], 35)

    # Mutex: GUID stored at config+0x80
    text = data.decode('latin-1', errors='ignore')
    mutex_match = re.search(r'\{[0-9A-Fa-f\-]{36}\}', text)
    if mutex_match:
        result['mutexes'].append(mutex_match.group(0))

    return result if result['confidence'] > 0 else None


def extract_gh0strat_config(data):
    """Extract Gh0st RAT configuration from binary data."""
    result = {
        'family': 'Gh0st RAT',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import struct, re

    text = data.decode('latin-1', errors='ignore')

    # Gh0st RAT uses a plaintext "flag" string (connection marker) — default "Gh0st"
    # but variants use custom 5-byte tokens like "HEART", "PCRat", "SklJH", "beast"
    known_flags = [b'Gh0st', b'HEART', b'PCRat', b'beast', b'SklJH', b'ByShell', b'nbvcxz']
    detected_flag = None
    for flag in known_flags:
        if flag in data:
            detected_flag = flag.decode('ascii', errors='ignore')
            result['raw']['connection_flag'] = detected_flag
            result['confidence'] += 40
            break

    # C2 stored as plaintext host:port in config resource or embedded string
    # Pattern: IP or domain followed by : and 4-5 digit port
    c2_pattern = re.compile(r'([a-zA-Z0-9._\-]{3,64}):(\d{2,5})\x00')
    for match in c2_pattern.finditer(text):
        host, port = match.group(1), int(match.group(2))
        if 1 <= port <= 65535 and '.' in host:
            result['c2Servers'].append(f"{host}:{port}")

    # Connection timeout and sleep interval (4-byte LE ints after flag)
    if detected_flag:
        flag_bytes = detected_flag.encode('ascii')
        idx = data.find(flag_bytes)
        if idx >= 0 and idx + len(flag_bytes) + 8 <= len(data):
            try:
                sleep_ms = struct.unpack('<I', data[idx + len(flag_bytes):idx + len(flag_bytes) + 4])[0]
                if 100 <= sleep_ms <= 300000:
                    result['raw']['sleep_ms'] = sleep_ms
            except struct.error:
                pass

    # Mutex: Gh0st uses a hardcoded mutex string near the flag
    mutex_match = re.search(r'[A-Za-z0-9_\-]{6,32}Mutex', text)
    if mutex_match:
        result['mutexes'].append(mutex_match.group(0))

    # Fallback IPs
    if not result['c2Servers']:
        result['c2Servers'] = extract_ipv4_addresses(data)[:5]
        if result['c2Servers']:
            result['confidence'] += 20

    if result['c2Servers']:
        result['confidence'] += 30

    return result if result['confidence'] > 0 else None


def extract_poisonivy_config(data):
    """Extract Poison Ivy configuration from binary data."""
    result = {
        'family': 'Poison Ivy',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import struct, re

    # Poison Ivy stores its config in the last ~1KB of the PE file
    # Config starts with a known layout: 4-byte magic 0xBEEFCAFE or at EOF-0x3C0
    PI_MAGIC = b'\xBE\xEF\xCA\xFE'
    idx = data.rfind(PI_MAGIC)
    config_region = None
    if idx >= 0:
        config_region = data[idx + 4:]
        result['confidence'] += 30
    else:
        # Fallback: try last 960 bytes as raw config
        if len(data) >= 960:
            config_region = data[-960:]

    if config_region and len(config_region) >= 0x100:
        # Password: first 26 bytes, null-terminated
        password = config_region[:26].split(b'\x00')[0].decode('ascii', errors='ignore').strip()
        if password and len(password) >= 4:
            result['encryptionKeys'].append(password)
            result['raw']['password'] = password
            result['confidence'] += 25

        # Mutex: bytes 26..58
        mutex_raw = config_region[26:58].split(b'\x00')[0].decode('ascii', errors='ignore').strip()
        if mutex_raw:
            result['mutexes'].append(mutex_raw)

        # C2 host: bytes 58..122
        host = config_region[58:122].split(b'\x00')[0].decode('ascii', errors='ignore').strip()
        if host and re.match(r'^[a-zA-Z0-9._\-]{3,}$', host):
            # Port: next 2 bytes LE
            if len(config_region) >= 124:
                port = struct.unpack('<H', config_region[122:124])[0]
                result['c2Servers'].append(f"{host}:{port}" if 0 < port < 65535 else host)
            else:
                result['c2Servers'].append(host)
            result['confidence'] += 30

        # Campaign ID / Group name at offset 0xC0
        if len(config_region) >= 0xD0:
            group = config_region[0xC0:0xD0].split(b'\x00')[0].decode('ascii', errors='ignore').strip()
            if group:
                result['campaignId'] = group

    if not result['c2Servers']:
        result['c2Servers'] = extract_ipv4_addresses(data)[:3]
        if result['c2Servers']:
            result['confidence'] = max(result['confidence'], 30)

    return result if result['confidence'] > 0 else None


def extract_netwire_config(data):
    """Extract NetWire configuration from binary data."""
    result = {
        'family': 'NetWire',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import struct, re

    # NetWire RC4-encrypts its config. Key is typically a plaintext string
    # embedded just before the config blob, separated by a null byte.
    # Config block marker: 4-byte size LE, then RC4-encrypted blob.

    # Look for RC4 key: printable ASCII string 4-32 chars followed by null + binary blob
    key_pattern = re.compile(b'([A-Za-z0-9!@#$%^&*()_+\-=]{4,32})\x00([\x00-\xff]{64,})')
    rc4_key = None
    decrypted_config = None

    for match in key_pattern.finditer(data):
        candidate_key = match.group(1)
        candidate_blob = match.group(2)
        try:
            dec = rc4_decrypt(candidate_blob[:512], candidate_key)
            dec_text = dec.decode('ascii', errors='ignore')
            # Heuristic: decrypted config should contain a hostname or IP
            if re.search(r'[a-zA-Z0-9._\-]{3,}\.[a-zA-Z]{2,}', dec_text) or \
               re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', dec_text):
                rc4_key = candidate_key
                decrypted_config = dec
                result['encryptionKeys'].append(candidate_key.decode('ascii', errors='ignore'))
                result['confidence'] += 45
                break
        except Exception:
            continue

    if decrypted_config:
        # Layout: host (null-terminated) | port (2 bytes LE) | secondary host | ...
        parts = decrypted_config.split(b'\x00')
        for part in parts:
            p = part.decode('ascii', errors='ignore').strip()
            if re.match(r'^[a-zA-Z0-9._\-]{3,}$', p) and '.' in p:
                result['c2Servers'].append(p)
            elif re.match(r'^\d{2,5}$', p) and result['c2Servers']:
                last = result['c2Servers'][-1]
                if ':' not in last:
                    result['c2Servers'][-1] = f"{last}:{p}"

        # Mutex: often a fixed string like "NetWireControl" or variant
        mutex_match = re.search(r'[A-Za-z]{4,32}(?:Control|Mutex|Lock|Wire)', decrypted_config.decode('ascii', errors='ignore'))
        if mutex_match:
            result['mutexes'].append(mutex_match.group(0))

    if not result['c2Servers']:
        result['c2Servers'] = extract_ipv4_addresses(data)[:5]
        if result['c2Servers']:
            result['confidence'] = max(result['confidence'], 25)

    if result['c2Servers']:
        result['confidence'] += 30

    return result if result['confidence'] > 0 else None


def extract_warzoneRAT_config(data):
    """Extract Warzone RAT configuration from binary data."""
    result = {
        'family': 'Warzone RAT',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import struct, re

    text = data.decode('latin-1', errors='ignore')

    # Warzone RAT (Ave Maria) stores config as plaintext or single-XOR encrypted
    # Magic: "WARZONERAW" or "Ave_Maria" marker
    for marker in [b'WARZONERAW', b'Ave_Maria', b'warzone\x00']:
        idx = data.find(marker)
        if idx >= 0:
            result['raw']['marker'] = marker.decode('ascii', errors='ignore')
            result['confidence'] += 35
            break

    # C2: stored as host + port; config often starts with 0x04 byte count of C2s
    # Try XOR keys 0x00 (plain), 0x0D
    for xor_key in [0x00, 0x0D, 0x22, 0x44]:
        chunk = xor_decrypt(data, xor_key) if xor_key != 0x00 else data
        chunk_text = chunk.decode('latin-1', errors='ignore')
        c2_matches = re.findall(r'([a-zA-Z0-9._\-]{3,64}):(\d{3,5})\x00', chunk_text)
        if c2_matches:
            for host, port in c2_matches[:5]:
                if '.' in host:
                    result['c2Servers'].append(f"{host}:{port}")
            if result['c2Servers']:
                result['raw']['xor_key'] = hex(xor_key)
                result['confidence'] += 35
                break

    # Password field: 16 bytes at known offset relative to C2
    password_pattern = re.compile(b'([A-Za-z0-9@#!_\-]{6,16})\x00{1,4}(?=[\x01-\x09])')
    for match in password_pattern.finditer(data):
        pwd = match.group(1).decode('ascii', errors='ignore')
        result['raw']['password'] = pwd
        result['confidence'] += 10
        break

    # Feature flags: 1-byte bitmask at config+0x40
    # Bit 0: keylogger, Bit 1: reverse shell, Bit 2: webcam, Bit 3: UAC bypass
    flags_match = re.search(b'\x00{3}([\x00-\xFF])\x00{3}', data)
    if flags_match:
        flags = flags_match.group(1)[0]
        result['raw']['feature_flags'] = hex(flags)
        if flags & 0x01:
            result['raw']['keylogger'] = True
        if flags & 0x04:
            result['raw']['webcam'] = True

    # Mutex
    mutex_match = re.search(r'[A-Za-z0-9_\-]{6,32}(?:mutex|Mutex|MUTEX)', text)
    if mutex_match:
        result['mutexes'].append(mutex_match.group(0))

    if not result['c2Servers']:
        result['c2Servers'] = extract_ipv4_addresses(data)[:5]
        if result['c2Servers']:
            result['confidence'] = max(result['confidence'], 30)

    return result if result['confidence'] > 0 else None


def extract_havoc_config(data):
    """Extract Havoc C2 Demon agent configuration from binary data."""
    result = {
        'family': 'Havoc',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import struct, re

    text = data.decode('latin-1', errors='ignore')

    # Havoc Demon agent config header magic: 0xDEADBEEF or "HAVOC\x00"
    for marker in [b'\xDE\xAD\xBE\xEF', b'HAVOC\x00', b'demon\x00']:
        idx = data.find(marker)
        if idx >= 0:
            result['raw']['marker'] = marker.hex()
            result['confidence'] += 35
            break

    # Listener URL: stored as null-terminated string in config section
    # Havoc uses HTTP/HTTPS listeners with a URI path
    url_pattern = re.compile(r'https?://[a-zA-Z0-9._\-:]+(?:/[a-zA-Z0-9/_\-\.]*)?')
    for match in url_pattern.finditer(text):
        url = match.group(0)
        if len(url) > 10:
            result['c2Servers'].append(url)
            result['confidence'] += 15

    # AES key and IV: 32 bytes key + 16 bytes IV stored consecutively
    # Look for 48-byte non-ASCII sequence preceded by config size
    for offset in range(0, min(len(data) - 48, 500000), 4):
        chunk = data[offset:offset + 48]
        if all(b != 0x00 for b in chunk[:32]) and sum(1 for b in chunk if b > 0x7F) > 16:
            result['encryptionKeys'].append(chunk[:32].hex())
            result['raw']['aes_iv'] = chunk[32:48].hex()
            result['confidence'] += 15
            break

    # Sleep + jitter config (4-byte LE int for sleep in ms, 1-byte jitter %)
    sleep_pattern = re.compile(b'([\x10\x27\x00\x00]|[\x80\xBB\x00\x00]|[\x40\x9C\x00\x00])([\x01-\x32])')
    for match in sleep_pattern.finditer(data):
        sleep_val = struct.unpack('<I', match.group(1) + b'\x00\x00')[0] if len(match.group(1)) == 2 else struct.unpack('<I', match.group(1))[0]
        jitter = match.group(2)[0]
        result['raw']['sleep_ms'] = sleep_val
        result['raw']['jitter_pct'] = jitter
        break

    # User-agent embedded in agent
    ua_match = re.search(r'Mozilla/5\.0 \([^)]{10,}\)', text)
    if ua_match:
        result['raw']['user_agent'] = ua_match.group(0)

    if result['c2Servers']:
        result['confidence'] = min(95, result['confidence'])

    return result if result['confidence'] > 0 else None


def extract_sliver_config(data):
    """Extract Sliver C2 implant configuration from binary data."""
    result = {
        'family': 'Sliver',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Sliver implants are Go binaries; config is embedded as Go string literals
    # Look for Sliver-specific package path strings
    sliver_markers = [b'github.com/bishopfox/sliver', b'sliver/implant', b'sliverpb', b'sliver-']
    for marker in sliver_markers:
        if marker in data:
            result['raw']['marker'] = marker.decode('ascii', errors='ignore')
            result['confidence'] += 40
            break

    # C2 URLs: HTTP/HTTPS/mTLS/DNS embedded as Go const strings
    # Go string table stores them with 2-byte length prefix
    for protocol in ['https://', 'http://', 'mtls://', 'dns://']:
        proto_bytes = protocol.encode('ascii')
        idx = data.find(proto_bytes)
        while idx >= 0 and len(result['c2Servers']) < 10:
            end = data.find(b'\x00', idx)
            if end < 0 or end - idx > 256:
                end = idx + 256
            url = data[idx:end].decode('ascii', errors='ignore').rstrip('\x00 \n\r')
            if len(url) > len(protocol) + 3:
                result['c2Servers'].append(url)
            idx = data.find(proto_bytes, idx + 1)

    # Implant name (beacon/session ID) embedded as Go string
    name_match = re.search(r'[A-Z][A-Z_]{4,32}(?=\x00)', text)
    if name_match:
        result['botId'] = name_match.group(0)

    # mTLS certificate fingerprint (32-byte SHA256 hex or PEM block)
    pem_start = data.find(b'-----BEGIN CERTIFICATE-----')
    if pem_start >= 0:
        pem_end = data.find(b'-----END CERTIFICATE-----', pem_start)
        if pem_end > pem_start:
            result['encryptionKeys'].append('embedded_mtls_cert')
            result['confidence'] += 20

    # Reconnect interval (Go time.Duration stored as int64 nanoseconds)
    # 60s = 60000000000 = 0x00000DF847580000
    if result['c2Servers']:
        result['confidence'] += 35

    # Campaign/profile name
    campaign_match = re.search(r'profile[_\-]?(?:name)?[=:\x00]([A-Za-z0-9_\-]{3,32})', text, re.IGNORECASE)
    if campaign_match:
        result['campaignId'] = campaign_match.group(1)

    return result if result['confidence'] > 0 else None


def extract_bruteratel_config(data):
    """Extract Brute Ratel C4 Badger configuration from binary data."""
    result = {
        'family': 'Brute Ratel',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import struct, re

    text = data.decode('latin-1', errors='ignore')

    # Brute Ratel badger config is RC4-encrypted or XOR-encoded
    # Marker strings found in badger binaries
    brc4_markers = [b'BRc4', b'badger', b'brc4_', b'Brute Ratel', b'\x42\x52\x43\x34']
    for marker in brc4_markers:
        if marker in data:
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore')
            result['confidence'] += 35
            break

    # Config JSON embedded after RC4 decryption — try common keys
    # BRC4 often uses a user-supplied key stored in first 16 bytes of config blob
    config_url_pattern = re.compile(r'https?://[a-zA-Z0-9._\-:/]+')
    found_urls = config_url_pattern.findall(text)

    # Try RC4 with known static keys
    static_keys = [b'BRc4RC4Key', b'RatRC4', b'\x00' * 16]
    for key in static_keys:
        try:
            dec = rc4_decrypt(data[:4096], key)
            dec_text = dec.decode('ascii', errors='ignore')
            urls = re.findall(r'https?://[a-zA-Z0-9._\-:/]+', dec_text)
            if urls:
                found_urls.extend(urls)
                result['encryptionKeys'].append(key.decode('ascii', errors='ignore').rstrip('\x00'))
                result['confidence'] += 25
                break
        except Exception:
            continue

    for url in found_urls[:10]:
        if len(url) > 10 and url not in result['c2Servers']:
            result['c2Servers'].append(url)

    # Listener profile name
    profile_match = re.search(r'"profile"\s*:\s*"([^"]{3,64})"', text)
    if profile_match:
        result['campaignId'] = profile_match.group(1)

    # Sleep jitter
    jitter_match = re.search(r'"jitter"\s*:\s*(\d+)', text)
    if jitter_match:
        result['raw']['jitter'] = int(jitter_match.group(1))

    # User-agent
    ua_match = re.search(r'Mozilla/[0-9.]+[^\x00]{10,200}', text)
    if ua_match:
        result['raw']['user_agent'] = ua_match.group(0)[:200]

    if result['c2Servers']:
        result['confidence'] += 30

    return result if result['confidence'] > 0 else None


def extract_mythic_config(data):
    """Extract Mythic C2 agent configuration from binary data."""
    result = {
        'family': 'Mythic',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Mythic agents (Apfell, Poseidon, Apollo, etc.) embed callback config
    mythic_markers = [b'mythic', b'apfell', b'poseidon', b'apollo\x00', b'Mythic C2', b'callback_host']
    for marker in mythic_markers:
        if marker.lower() in data.lower():
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore')
            result['confidence'] += 35
            break

    # Callback URL: stored as string in agent
    callback_pattern = re.compile(r'https?://[a-zA-Z0-9._\-:]+(?:/[a-zA-Z0-9/_\-\.]*)?')
    for match in callback_pattern.finditer(text):
        url = match.group(0)
        if len(url) > 10 and url not in result['c2Servers']:
            result['c2Servers'].append(url)

    # Callback port and interval
    port_match = re.search(r'(?:callback_port|c2_port)[^0-9]{0,5}(\d{2,5})', text, re.IGNORECASE)
    if port_match:
        result['raw']['callback_port'] = int(port_match.group(1))

    interval_match = re.search(r'(?:callback_interval|sleep)[^0-9]{0,5}(\d{1,6})', text, re.IGNORECASE)
    if interval_match:
        result['raw']['callback_interval'] = int(interval_match.group(1))

    # UUID: Mythic agents have a UUID for agent identification
    uuid_match = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', text, re.IGNORECASE)
    if uuid_match:
        result['botId'] = uuid_match.group(0)
        result['confidence'] += 15

    # AES256 key: base64 encoded 44-char string
    aes_match = re.search(r'[A-Za-z0-9+/]{43}=', text)
    if aes_match:
        result['encryptionKeys'].append(aes_match.group(0))
        result['confidence'] += 15

    if result['c2Servers']:
        result['confidence'] += 30

    return result if result['confidence'] > 0 else None


def extract_meterpreter_config(data):
    """Extract Metasploit/Meterpreter configuration from binary data."""
    result = {
        'family': 'Meterpreter',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import struct, re

    text = data.decode('latin-1', errors='ignore')

    # Meterpreter reverse_tcp/reverse_http stagers embed LHOST + LPORT
    # Marker: "LHOST" or "EXITFUNC" in stager, or MZ header + known shellcode patterns

    # Shellcode pattern: call/jmp over data, then 4-byte IP + 2-byte port
    # Reverse TCP: \xFC\x48\x83\xE4\xF0 (common x64 stager prefix)
    stager_markers = [
        b'\xfc\x48\x83\xe4\xf0',  # x64 reverse TCP stager
        b'\xfc\xe8\x82\x00\x00\x00',  # x86 reverse TCP stager
        b'\xfc\x48\x81\xe4',  # x64 variant
    ]
    for marker in stager_markers:
        if marker in data:
            result['raw']['stager_type'] = 'reverse_tcp_shellcode'
            result['confidence'] += 35
            # LHOST/LPORT usually at end of stager, 4+2 bytes before null
            idx = data.find(marker)
            stager_slice = data[idx:idx + 512]
            # Scan for IP:port in the last 16 bytes of stager
            for offset in range(len(stager_slice) - 6, max(0, len(stager_slice) - 64), -1):
                ip_bytes = stager_slice[offset:offset + 4]
                port_bytes = stager_slice[offset + 4:offset + 6]
                first = ip_bytes[0]
                if first in (10, 192, 172, 1, 2, 3, 4) or (1 <= first <= 223):
                    port = struct.unpack('>H', port_bytes)[0]
                    if 1 <= port <= 65535:
                        ip_str = '.'.join(str(b) for b in ip_bytes)
                        result['c2Servers'].append(f"{ip_str}:{port}")
                        result['confidence'] += 30
                        break
            break

    # Reverse HTTP/HTTPS: URL stored as ASCII in stager
    http_c2 = re.findall(r'https?://[a-zA-Z0-9._\-:]+(?:/[a-zA-Z0-9/_\-\.]*)?', text)
    for url in http_c2[:5]:
        if url not in result['c2Servers']:
            result['c2Servers'].append(url)
            result['confidence'] += 20

    # EXITFUNC type
    exitfunc_match = re.search(r'EXITFUNC[=:\x00]([a-z_]{3,16})', text, re.IGNORECASE)
    if exitfunc_match:
        result['raw']['exitfunc'] = exitfunc_match.group(1)

    # EXP_TIMEOUT
    if b'\x00\x00\x04\xb0' in data:  # 1200 seconds default
        result['raw']['exp_timeout'] = 1200

    # Payload type string
    for pt in [b'windows/meterpreter', b'linux/x86/meterpreter', b'python/meterpreter']:
        if pt in data:
            result['raw']['payload_type'] = pt.decode('ascii')
            result['confidence'] += 10
            break

    return result if result['confidence'] > 0 else None


def extract_wannacry_config(data):
    """Extract WannaCry configuration from binary data."""
    result = {
        'family': 'WannaCry',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # WannaCry kill switch domain — hardcoded plaintext
    KILLSWITCH = b'www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com'
    if KILLSWITCH in data:
        result['raw']['killswitch_domain'] = KILLSWITCH.decode('ascii')
        result['confidence'] += 60

    # Additional kill switch variants (some samples)
    alt_killswitches = [
        b'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com',
        b'ayylmaotjhsstasdfasdfasdfasdfasdfasdfasdf.com',
    ]
    for ks in alt_killswitches:
        if ks in data:
            result['raw']['alt_killswitch'] = ks.decode('ascii')
            result['confidence'] += 20

    # Bitcoin addresses: 34-char base58 starting with 1 or 3
    btc_pattern = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
    for match in btc_pattern.finditer(text):
        addr = match.group(0)
        if addr not in result['c2Servers']:
            result['c2Servers'].append(addr)
            result['raw'].setdefault('bitcoin_addresses', []).append(addr)
            result['confidence'] += 10

    # Tor .onion C2 addresses
    onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion(?::\d+)?')
    for match in onion_pattern.finditer(text):
        onion = match.group(0)
        if onion not in result['c2Servers']:
            result['c2Servers'].append(onion)
            result['confidence'] += 15

    # WannaCry mutex
    wncry_mutex = b'MsWinZonesCacheCounterMutexA'
    if wncry_mutex in data:
        result['mutexes'].append(wncry_mutex.decode('ascii'))
        result['confidence'] += 20

    # Ransom note file name indicator
    for note in [b'@Please_Read_Me@.txt', b'@WanaDecryptor@', b'taskdl.exe']:
        if note in data:
            result['raw']['ransom_note'] = note.decode('ascii')
            result['confidence'] += 10

    return result if result['confidence'] > 0 else None


def extract_revil_config(data):
    """Extract REvil/Sodinokibi configuration from binary data."""
    result = {
        'family': 'REvil',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re, json

    text = data.decode('latin-1', errors='ignore')

    # REvil embeds a JSON config blob, typically RC4-encrypted with hardcoded key
    # or XOR-encoded. Look for the JSON config markers.
    json_start = text.find('{')
    while json_start >= 0:
        # Try to parse progressively larger JSON substrings
        for end_offset in [512, 1024, 2048, 4096]:
            candidate = text[json_start:json_start + end_offset]
            bracket_end = candidate.rfind('}')
            if bracket_end < 10:
                break
            try:
                parsed = json.loads(candidate[:bracket_end + 1])
                # REvil config has known keys
                if any(k in parsed for k in ['pk', 'pid', 'sub', 'dmn', 'nbody', 'nname']):
                    result['raw'] = {k: v for k, v in parsed.items() if k not in ('nbody', 'nname')}
                    result['confidence'] += 70

                    # C2 domains from 'dmn' key (array of domains)
                    if 'dmn' in parsed and isinstance(parsed['dmn'], list):
                        result['c2Servers'] = parsed['dmn'][:20]
                    elif 'c2' in parsed:
                        c2 = parsed['c2']
                        result['c2Servers'] = c2 if isinstance(c2, list) else [c2]

                    # RSA public key
                    if 'pk' in parsed:
                        result['encryptionKeys'].append(parsed['pk'])

                    # Campaign / affiliate ID
                    result['campaignId'] = str(parsed.get('pid', parsed.get('sub', '')))
                    break
            except (json.JSONDecodeError, ValueError):
                pass
        if result['c2Servers']:
            break
        json_start = text.find('{', json_start + 1)

    # Fallback: XOR decode with common REvil key 0x61
    if not result['c2Servers']:
        dec = xor_decrypt(data, 0x61)
        dec_text = dec.decode('latin-1', errors='ignore')
        urls = re.findall(r'https?://[a-zA-Z0-9._\-:/]+', dec_text)
        if urls:
            result['c2Servers'] = urls[:10]
            result['encryptionKeys'].append('0x61')
            result['confidence'] += 40

    # Mutex: REvil uses generated mutex from campaign ID
    mutex_match = re.search(r'Global\\[A-Fa-f0-9]{32}', text)
    if mutex_match:
        result['mutexes'].append(mutex_match.group(0))

    return result if result['confidence'] > 0 else None


def extract_ryuk_config(data):
    """Extract Ryuk ransomware configuration from binary data."""
    result = {
        'family': 'Ryuk',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Ryuk dropper contains hardcoded service names and file paths
    ryuk_markers = [b'RyukReadMe.html', b'RyukReadMe.txt', b'RYUK_CHECK', b'UNIQUE_ID_DO_NOT_REMOVE']
    for marker in ryuk_markers:
        if marker in data:
            result['raw']['marker'] = marker.decode('ascii', errors='ignore')
            result['confidence'] += 40
            break

    # Ryuk uses an embedded RSA public key
    rsa_marker = b'-----BEGIN PUBLIC KEY-----'
    rsa_idx = data.find(rsa_marker)
    if rsa_idx >= 0:
        rsa_end = data.find(b'-----END PUBLIC KEY-----', rsa_idx)
        if rsa_end > rsa_idx:
            result['encryptionKeys'].append(data[rsa_idx:rsa_end + 24].decode('ascii', errors='ignore'))
            result['confidence'] += 20

    # C2 IP addresses (Ryuk dropper phones home via hardcoded IPs)
    ips = extract_ipv4_addresses(data)
    result['c2Servers'] = ips[:5]
    if ips:
        result['confidence'] += 20

    # Bitcoin wallet addresses
    btc_pattern = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
    wallets = btc_pattern.findall(text)
    if wallets:
        result['raw']['wallets'] = wallets[:5]
        result['confidence'] += 15

    # Contact email embedded in ransom note template
    email_match = re.search(r'[a-zA-Z0-9._%+\-]+@(?:protonmail|tutanota|cock\.li|onionmail)\.[a-z]{2,}', text, re.IGNORECASE)
    if email_match:
        result['raw']['contact_email'] = email_match.group(0)
        result['confidence'] += 10

    # Ryuk process kill list (bat/service names hardcoded)
    kill_services = [b'audioendpointbuilder', b'samss', b'eventlog', b'DefWatch']
    for svc in kill_services:
        if svc.lower() in data.lower():
            result['raw']['kills_services'] = True
            result['confidence'] += 5
            break

    return result if result['confidence'] > 0 else None


def extract_hive_config(data):
    """Extract Hive ransomware configuration from binary data."""
    result = {
        'family': 'Hive',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Hive is a Rust-based ransomware; look for Rust panic metadata and Hive markers
    hive_markers = [b'HiveLeaks', b'hive_ransom', b'HOW_TO_DECRYPT.txt', b'hive\x00']
    for marker in hive_markers:
        if marker in data:
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore')
            result['confidence'] += 40
            break

    # Rust binary marker
    if b'panicked at' in data or b'src/main.rs' in data:
        result['raw']['runtime'] = 'Rust'
        result['confidence'] += 10

    # Hive C2: .onion addresses for victim portal
    onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion(?::\d+)?')
    for match in onion_pattern.finditer(text):
        onion = match.group(0)
        if onion not in result['c2Servers']:
            result['c2Servers'].append(onion)
            result['confidence'] += 20

    # Hive embeds an RSA-4096 public key or curve25519 key for key exchange
    # Look for base64-encoded key blob > 200 chars
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{200,}={0,2}')
    for match in b64_pattern.finditer(text):
        result['encryptionKeys'].append(match.group(0)[:64] + '...')
        result['confidence'] += 15
        break

    # Victim ID / campaign tag embedded in binary
    vid_match = re.search(r'[A-Z0-9]{8,16}(?=\x00)', text)
    if vid_match:
        result['campaignId'] = vid_match.group(0)

    # File extension used (.hive or randomized)
    ext_match = re.search(r'\.[a-z0-9]{4,8}\x00', text)
    if ext_match:
        result['raw']['file_extension'] = ext_match.group(0).strip('\x00')

    return result if result['confidence'] > 0 else None


def extract_royal_config(data):
    """Extract Royal ransomware configuration from binary data."""
    result = {
        'family': 'Royal',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Royal ransomware markers
    royal_markers = [b'README.TXT', b'royal_readme', b'.royal', b'ROYAL\x00', b'royal_open']
    for marker in royal_markers:
        if marker in data:
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore')
            result['confidence'] += 35
            break

    # Royal embeds a Tor .onion URL for victim negotiations
    onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion(?::\d+)?')
    for match in onion_pattern.finditer(text):
        onion = match.group(0)
        if onion not in result['c2Servers']:
            result['c2Servers'].append(onion)
            result['confidence'] += 25

    # OpenSSL AES-256 encryption parameters
    if b'aes-256' in data.lower() or b'AES_256' in data:
        result['raw']['encryption'] = 'AES-256'
        result['confidence'] += 10

    # RSA public key
    if b'-----BEGIN PUBLIC KEY-----' in data:
        idx = data.find(b'-----BEGIN PUBLIC KEY-----')
        end = data.find(b'-----END PUBLIC KEY-----', idx)
        if end > idx:
            result['encryptionKeys'].append(data[idx:end + 24].decode('ascii', errors='ignore'))
            result['confidence'] += 20

    # Encryption percentage (partial encryption config): 1-byte or 4-byte value 0x32 (50%)
    enc_pct_match = re.search(b'[\x01-\x64]\x00{3}(?=[\x00-\xFF]{4})', data)
    if enc_pct_match:
        result['raw']['enc_percentage'] = enc_pct_match.group(0)[0]

    # Exclusion list fragments
    for excl in [b'.exe\x00', b'.dll\x00', b'windows\x00', b'system32\x00']:
        if excl in data.lower():
            result['raw']['has_exclusion_list'] = True
            break

    return result if result['confidence'] > 0 else None


def extract_blackbasta_config(data):
    """Extract Black Basta ransomware configuration from binary data."""
    result = {
        'family': 'Black Basta',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Black Basta markers
    bb_markers = [b'readme.txt', b'aabbcc', b'black_basta', b'dlzmejsprvdklkin', b'.basta']
    for marker in bb_markers:
        if marker in data.lower():
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore')
            result['confidence'] += 35
            break

    # Tor .onion C2 for victim chat
    onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion(?::\d+)?')
    for match in onion_pattern.finditer(text):
        onion = match.group(0)
        if onion not in result['c2Servers']:
            result['c2Servers'].append(onion)
            result['confidence'] += 25

    # Chat ID: Black Basta assigns unique victim IDs (hex string ~16 chars)
    chat_id_match = re.search(r'[a-f0-9]{16,32}(?=\x00)', text)
    if chat_id_match:
        result['campaignId'] = chat_id_match.group(0)
        result['confidence'] += 10

    # Encryption key seed: ChaCha20 key (32 bytes) or AES key
    # Look for 32-byte non-ASCII blob
    for offset in range(0, min(len(data) - 32, 500000), 4):
        chunk = data[offset:offset + 32]
        if sum(1 for b in chunk if b > 0x7F) > 16 and len(set(chunk)) > 20:
            result['encryptionKeys'].append(chunk.hex())
            result['raw']['key_offset'] = hex(offset)
            result['confidence'] += 15
            break

    # Exclusion: Black Basta skips .dll, .exe, .sys — presence of exclusion list
    for excl in [b'.exe\x00', b'.dll\x00', b'NTDS.dit']:
        if excl in data:
            result['raw']['has_exclusion_list'] = True
            break

    # Wipe shadow copies (vssadmin delete)
    if b'vssadmin' in data.lower() or b'shadowcopy' in data.lower():
        result['raw']['deletes_shadow_copies'] = True
        result['confidence'] += 5

    return result if result['confidence'] > 0 else None


def extract_akira_config(data):
    """Extract Akira ransomware configuration from binary data."""
    result = {
        'family': 'Akira',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Akira markers
    akira_markers = [b'akira_readme.txt', b'.akira\x00', b'akiranews', b'akiraleaks']
    for marker in akira_markers:
        if marker in data.lower():
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore')
            result['confidence'] += 40
            break

    # Akira is C++ (early versions) or Rust-based; look for runtime hints
    if b'panicked at' in data:
        result['raw']['runtime'] = 'Rust'
    elif b'vcruntime' in data.lower():
        result['raw']['runtime'] = 'MSVC C++'

    # Tor .onion C2
    onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion(?::\d+)?')
    for match in onion_pattern.finditer(text):
        onion = match.group(0)
        if onion not in result['c2Servers']:
            result['c2Servers'].append(onion)
            result['confidence'] += 25

    # Akira uses hybrid encryption: RSA + ChaCha20
    # ChaCha20 nonce (12 bytes) and key (32 bytes) generated per file
    if b'chacha20' in data.lower() or b'ChaCha' in data:
        result['raw']['encryption'] = 'RSA+ChaCha20'
        result['confidence'] += 10

    # RSA public key
    rsa_idx = data.find(b'-----BEGIN PUBLIC KEY-----')
    if rsa_idx >= 0:
        rsa_end = data.find(b'-----END PUBLIC KEY-----', rsa_idx)
        if rsa_end > rsa_idx:
            result['encryptionKeys'].append(data[rsa_idx:rsa_end + 24].decode('ascii', errors='ignore'))
            result['confidence'] += 20

    # Partial encryption percentage
    pct_match = re.search(r'["\']enc_pct["\']\s*:\s*(\d{1,3})', text, re.IGNORECASE)
    if pct_match:
        result['raw']['enc_percentage'] = int(pct_match.group(1))

    # Thread count config
    thread_match = re.search(r'["\']threads["\']\s*:\s*(\d{1,3})', text, re.IGNORECASE)
    if thread_match:
        result['raw']['threads'] = int(thread_match.group(1))

    return result if result['confidence'] > 0 else None


def extract_play_config(data):
    """Extract Play ransomware configuration from binary data."""
    result = {
        'family': 'Play',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Play ransomware markers
    play_markers = [b'ReadMe.txt', b'.PLAY\x00', b'play\x00ransom', b'PLAY\x00']
    for marker in play_markers:
        if marker in data:
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore')
            result['confidence'] += 35
            break

    # Play uses AdFind.exe for domain reconnaissance; check for embedded AdFind config
    if b'AdFind' in data or b'adfind' in data.lower():
        result['raw']['uses_adfind'] = True
        result['confidence'] += 15

    # Contact email for negotiations
    email_match = re.search(r'[a-zA-Z0-9._%+\-]+@(?:protonmail|tutanota|onionmail|airmail|gmx)\.[a-z]{2,}', text, re.IGNORECASE)
    if email_match:
        result['raw']['contact_email'] = email_match.group(0)
        result['c2Servers'].append(email_match.group(0))
        result['confidence'] += 20

    # Tor .onion URL
    onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion(?::\d+)?')
    for match in onion_pattern.finditer(text):
        onion = match.group(0)
        if onion not in result['c2Servers']:
            result['c2Servers'].append(onion)
            result['confidence'] += 25

    # Exclusion path list (Play skips specific folders)
    exclusion_dirs = [b'windows', b'program files', b'appdata', b'recycle.bin']
    excluded_found = [d.decode('ascii') for d in exclusion_dirs if d in data.lower()]
    if excluded_found:
        result['raw']['exclusion_dirs'] = excluded_found

    # AES or hybrid encryption hint
    if b'aes' in data.lower():
        result['raw']['encryption'] = 'AES'
        result['confidence'] += 5

    # VSS deletion
    if b'vssadmin' in data.lower():
        result['raw']['deletes_shadow_copies'] = True

    return result if result['confidence'] > 0 else None


def extract_clop_config(data):
    """Extract Clop/Cl0p ransomware configuration from binary data."""
    result = {
        'family': 'Clop',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Clop markers
    clop_markers = [b'Cl0pReadMe.txt', b'CL0P\x00', b'clop\x00', b'CLOP_README', b'C|0P']
    for marker in clop_markers:
        if marker in data:
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore')
            result['confidence'] += 40
            break

    # Clop C2: hardcoded email addresses for contact
    email_pattern = re.compile(r'[a-zA-Z0-9._%+\-]+@(?:protonmail|tutanota|eclipso|cock\.li)\.[a-z]{2,}')
    for match in email_pattern.finditer(text):
        addr = match.group(0)
        if addr not in result['c2Servers']:
            result['c2Servers'].append(addr)
            result['confidence'] += 15

    # Tor leak site .onion URL
    onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion(?::\d+)?')
    for match in onion_pattern.finditer(text):
        onion = match.group(0)
        if onion not in result['c2Servers']:
            result['c2Servers'].append(onion)
            result['confidence'] += 20

    # RC4 encryption key embedded (Clop uses RC4 for key encryption)
    # Key is typically 117 bytes following magic 0xBAADF00D
    baad_idx = data.find(b'\xBA\xAD\xF0\x0D')
    if baad_idx >= 0 and baad_idx + 121 <= len(data):
        key_blob = data[baad_idx + 4:baad_idx + 121]
        result['encryptionKeys'].append(key_blob.hex()[:64])
        result['confidence'] += 20

    # Exclusion list: Clop skips specific file extensions
    exclusion_exts = [b'.exe\x00', b'.dll\x00', b'.sys\x00', b'.clop\x00']
    for ext in exclusion_exts:
        if ext in data:
            result['raw'].setdefault('exclusion_extensions', []).append(ext.decode('ascii', errors='ignore').strip('\x00'))

    # Mutex
    mutex_match = re.search(r'Clop(?:Dec)?[A-Za-z0-9_]{0,20}', text)
    if mutex_match:
        result['mutexes'].append(mutex_match.group(0))

    return result if result['confidence'] > 0 else None


def extract_maze_config(data):
    """Extract Maze ransomware configuration from binary data."""
    result = {
        'family': 'Maze',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re, json

    text = data.decode('latin-1', errors='ignore')

    # Maze markers
    maze_markers = [b'MAZE\x00', b'maze-decrypt.com', b'Maze_Decrypt', b'DECRYPT-FILES.html']
    for marker in maze_markers:
        if marker in data:
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore')
            result['confidence'] += 40
            break

    # Maze embeds a JSON-like config or plaintext C2 URLs
    url_pattern = re.compile(r'https?://[a-zA-Z0-9._\-:/]+')
    for match in url_pattern.finditer(text):
        url = match.group(0)
        if url not in result['c2Servers']:
            result['c2Servers'].append(url)
            result['confidence'] += 10

    # Tor .onion C2
    onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion(?::\d+)?')
    for match in onion_pattern.finditer(text):
        onion = match.group(0)
        if onion not in result['c2Servers']:
            result['c2Servers'].append(onion)
            result['confidence'] += 20

    # RSA-2048 public key
    rsa_idx = data.find(b'-----BEGIN RSA PUBLIC KEY-----')
    if rsa_idx < 0:
        rsa_idx = data.find(b'-----BEGIN PUBLIC KEY-----')
    if rsa_idx >= 0:
        rsa_end = data.find(b'-----END', rsa_idx)
        if rsa_end > rsa_idx and rsa_end - rsa_idx < 2048:
            result['encryptionKeys'].append(data[rsa_idx:rsa_end + 30].decode('ascii', errors='ignore'))
            result['confidence'] += 20

    # Campaign ID: numeric string embedded in binary
    campaign_match = re.search(r'(?:campaign|pid|cid)[_\-\x00=]([0-9]{3,10})', text, re.IGNORECASE)
    if campaign_match:
        result['campaignId'] = campaign_match.group(1)
        result['confidence'] += 10

    # Contact email
    email_match = re.search(r'[a-zA-Z0-9._%+\-]+@(?:protonmail|cock\.li|torbox3uiot6wchz|onion)\.[a-z]{2,}', text, re.IGNORECASE)
    if email_match:
        result['raw']['contact_email'] = email_match.group(0)

    return result if result['confidence'] > 0 else None


def extract_medusa_config(data):
    """Extract Medusa ransomware configuration from binary data."""
    result = {
        'family': 'Medusa',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Medusa markers
    medusa_markers = [b'MEDUSA_README.txt', b'.medusa\x00', b'medusalocker', b'MEDUSA\x00']
    for marker in medusa_markers:
        if marker in data.lower():
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore')
            result['confidence'] += 40
            break

    # Telegram bot token for victim notification (Medusa uses Telegram)
    telegram_pattern = re.compile(r'\d{8,10}:[A-Za-z0-9_\-]{35}')
    for match in telegram_pattern.finditer(text):
        token = match.group(0)
        result['raw']['telegram_bot_token'] = token
        result['c2Servers'].append(f"https://api.telegram.org/bot{token}/")
        result['confidence'] += 30
        break

    # Tor .onion URL for victim portal
    onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion(?::\d+)?')
    for match in onion_pattern.finditer(text):
        onion = match.group(0)
        if onion not in result['c2Servers']:
            result['c2Servers'].append(onion)
            result['confidence'] += 25

    # C2 HTTP URL
    url_pattern = re.compile(r'https?://[a-zA-Z0-9._\-:/]+')
    for match in url_pattern.finditer(text):
        url = match.group(0)
        if url not in result['c2Servers'] and len(url) > 12:
            result['c2Servers'].append(url)

    # RSA public key
    rsa_idx = data.find(b'-----BEGIN PUBLIC KEY-----')
    if rsa_idx >= 0:
        rsa_end = data.find(b'-----END PUBLIC KEY-----', rsa_idx)
        if rsa_end > rsa_idx:
            result['encryptionKeys'].append(data[rsa_idx:rsa_end + 24].decode('ascii', errors='ignore'))
            result['confidence'] += 20

    # Victim ID
    vid_match = re.search(r'[A-Fa-f0-9]{32}', text)
    if vid_match:
        result['campaignId'] = vid_match.group(0)

    return result if result['confidence'] > 0 else None


def extract_phobos_config(data):
    """Extract Phobos ransomware configuration from binary data."""
    result = {
        'family': 'Phobos',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Phobos markers
    phobos_markers = [b'info.hta', b'Phobos\x00', b'.phobos\x00', b'PHOBOS\x00', b'info.txt']
    for marker in phobos_markers:
        if marker in data:
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore')
            result['confidence'] += 30
            break

    # Phobos includes a victim ID and campaign tag in the file extension
    # Format: .id[XXXXXXXX-XXXX].[attacker_email].phobos
    id_match = re.search(r'id\[([A-Fa-f0-9\-]{8,36})\]', text)
    if id_match:
        result['botId'] = id_match.group(1)
        result['confidence'] += 20

    # Contact email addresses (multiple variants per campaign)
    email_pattern = re.compile(r'[a-zA-Z0-9._%+\-]+@(?:protonmail|airmail|cock\.li|onionmail|eclipso)\.[a-z]{2,}')
    for match in email_pattern.finditer(text):
        addr = match.group(0)
        if addr not in result['c2Servers']:
            result['c2Servers'].append(addr)
            result['confidence'] += 15

    # Encryption key: AES-256 session key XOR-wrapped with RSA
    # Look for RSA key blob marker
    rsa_idx = data.find(b'\x30\x82')  # DER sequence
    if rsa_idx >= 0 and rsa_idx + 4 <= len(data):
        rsa_len = (data[rsa_idx + 2] << 8) | data[rsa_idx + 3]
        if 100 <= rsa_len <= 4096:
            result['encryptionKeys'].append(data[rsa_idx:rsa_idx + min(rsa_len + 4, 512)].hex()[:64])
            result['confidence'] += 15

    # Campaign tag from file extension pattern
    camp_match = re.search(r'\.\w+\d{3,8}', text)
    if camp_match:
        result['campaignId'] = camp_match.group(0).strip('.')

    # Mutex: Phobos uses volume serial number as mutex
    vol_match = re.search(r'Global\\[A-Fa-f0-9]{8,16}', text)
    if vol_match:
        result['mutexes'].append(vol_match.group(0))

    # Tor .onion URL
    onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion(?::\d+)?')
    for match in onion_pattern.finditer(text):
        onion = match.group(0)
        if onion not in result['c2Servers']:
            result['c2Servers'].append(onion)
            result['confidence'] += 20

    return result if result['confidence'] > 0 else None


def extract_dharma_config(data):
    """Extract Dharma/CrySiS ransomware configuration from binary data."""
    result = {
        'family': 'Dharma',
        'confidence': 0,
        'c2Servers': [],
        'encryptionKeys': [],
        'mutexes': [],
        'campaignId': None,
        'botId': None,
        'raw': {}
    }
    import re

    text = data.decode('latin-1', errors='ignore')

    # Dharma/CrySiS markers
    dharma_markers = [
        b'DHARMA\x00', b'.dharma\x00', b'.wallet\x00', b'.arena\x00',
        b'.brrr\x00', b'.cesar\x00', b'.java\x00', b'CrySiS\x00',
        b'Files encrypted.txt', b'Readme to decrypt'
    ]
    for marker in dharma_markers:
        if marker in data:
            result['raw']['marker'] = marker.decode('latin-1', errors='ignore').strip('\x00')
            result['confidence'] += 35
            break

    # Victim ID: 8-char hex embedded in binary (used in ransom note and extension)
    id_match = re.search(r'\bid\[([A-Fa-f0-9]{8})\]', text)
    if id_match:
        result['botId'] = id_match.group(1)
        result['confidence'] += 20

    # Contact email addresses (primary C2 mechanism for Dharma)
    email_pattern = re.compile(r'[a-zA-Z0-9._%+\-]+@(?:protonmail|tutanota|cock\.li|airmail|bitmessage|onionmail|eclipso)\.[a-z]{2,}')
    for match in email_pattern.finditer(text):
        addr = match.group(0)
        if addr not in result['c2Servers']:
            result['c2Servers'].append(addr)
            result['confidence'] += 15

    # RSA public key embedded in PE resources
    rsa_idx = data.find(b'-----BEGIN RSA PUBLIC KEY-----')
    if rsa_idx < 0:
        rsa_idx = data.find(b'-----BEGIN PUBLIC KEY-----')
    if rsa_idx >= 0:
        rsa_end = data.find(b'-----END', rsa_idx)
        if rsa_end > rsa_idx and rsa_end - rsa_idx < 4096:
            key_pem = data[rsa_idx:rsa_end + 32].decode('ascii', errors='ignore')
            result['encryptionKeys'].append(key_pem)
            result['confidence'] += 20

    # Campaign/extension tag
    ext_match = re.search(r'\{[A-Fa-f0-9\-]{36}\}\.\w+', text)
    if ext_match:
        result['campaignId'] = ext_match.group(0)
        result['confidence'] += 10

    # Mutex: often volume-serial based or GUID
    mutex_match = re.search(r'Global\\(?:[A-Fa-f0-9]{8,16}|\{[A-Fa-f0-9\-]{36}\})', text)
    if mutex_match:
        result['mutexes'].append(mutex_match.group(0))

    # File extension list (Dharma skips many extensions)
    skip_exts = [b'.exe\x00', b'.dll\x00', b'.lnk\x00', b'.ico\x00']
    if any(e in data for e in skip_exts):
        result['raw']['has_exclusion_list'] = True

    return result if result['confidence'] > 0 else None
