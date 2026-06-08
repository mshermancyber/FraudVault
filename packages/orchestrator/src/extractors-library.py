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
