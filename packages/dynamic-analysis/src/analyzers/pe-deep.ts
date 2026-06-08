// ── Deep PE / ELF / Format Static Analysis ─────────────────────────────────
//
// Returns Python code to append to the jail analysis script in executor.ts.
// Adds deep binary-level extractions under result['deepAnalysis'].
// Each extraction is wrapped in try/except so one failure never blocks the rest.

/**
 * Returns a Python string that, when appended to the jail analysis script,
 * augments each file's `result` dict with a `deepAnalysis` key containing:
 *   - pe:       PE delay-load imports, load config, checksum, Rich header, ...
 *   - elf:      build-id, comment, RELRO, fortify, symbol versioning, ...
 *   - format:   LNK parsing, ZIP bomb detection, polyglot, embedded carving, ...
 *   - advanced: stack string detection, TLSH, XOR brute-force, byte histogram
 *
 * The code expects the caller to have already defined:
 *   - `analyze_file(path)` returning a `result` dict with keys isPE, isELF, etc.
 *   - `entropy(data)` returning Shannon entropy of a bytes object.
 *   - `import struct, hashlib, re, math, os, json`
 *
 * The returned snippet monkey-patches `analyze_file` to call
 * `deep_analysis(path, data, result)` before returning.
 */
export function getDeepStaticAnalysisScript(): string {
  return `
# ═══════════════════════════════════════════════════════════════════════════
# Deep PE / ELF / Format static analysis — appended by pe-deep.ts
# ═══════════════════════════════════════════════════════════════════════════

import xml.etree.ElementTree as _ET

def _shannon(data):
    """Shannon entropy - local helper that works on bytes."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ln = len(data)
    return -sum((c / ln) * math.log2(c / ln) for c in freq if c > 0)

# ── helpers ────────────────────────────────────────────────────────────────

def _rva_to_offset(data, rva, pe_offset):
    """Convert RVA to file offset using the section table."""
    try:
        num_sec = struct.unpack_from('<H', data, pe_offset + 6)[0]
        opt_sz = struct.unpack_from('<H', data, pe_offset + 20)[0]
        sec_off = pe_offset + 24 + opt_sz
        for i in range(min(num_sec, 96)):
            o = sec_off + i * 40
            if o + 40 > len(data):
                break
            vs = struct.unpack_from('<I', data, o + 8)[0]
            va = struct.unpack_from('<I', data, o + 12)[0]
            rs = struct.unpack_from('<I', data, o + 16)[0]
            rp = struct.unpack_from('<I', data, o + 20)[0]
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
    except Exception:
        pass
    return None

def _pe_data_dir(data, pe_offset, index):
    """Return (rva, size) for a PE data directory entry by index."""
    opt_magic = struct.unpack_from('<H', data, pe_offset + 24)[0]
    if opt_magic == 0x20b:  # PE32+
        dd_base = pe_offset + 24 + 112
    else:  # PE32
        dd_base = pe_offset + 24 + 96
    num_dd = struct.unpack_from('<I', data, dd_base - 4)[0]
    if index >= num_dd:
        return (0, 0)
    off = dd_base + index * 8
    if off + 8 > len(data):
        return (0, 0)
    rva = struct.unpack_from('<I', data, off)[0]
    sz = struct.unpack_from('<I', data, off + 4)[0]
    return (rva, sz)

def _read_cstring(data, offset, max_len=260):
    end = data.find(b'\x00', offset, offset + max_len)
    if end < 0:
        end = offset + max_len
    return data[offset:end].decode('ascii', errors='replace')

# ── PE Deep ────────────────────────────────────────────────────────────────

def _pe_deep(data, pe_offset):
    pe = {}

    # 1. Delay-Load Import Table (DD 13)
    try:
        dd_rva, dd_sz = _pe_data_dir(data, pe_offset, 13)
        delay_dlls = []
        if dd_rva and dd_sz:
            off = _rva_to_offset(data, dd_rva, pe_offset)
            if off is not None:
                pos = off
                while pos + 32 <= len(data):
                    name_rva = struct.unpack_from('<I', data, pos + 4)[0]
                    if name_rva == 0:
                        break
                    noff = _rva_to_offset(data, name_rva, pe_offset)
                    if noff is not None and noff < len(data):
                        delay_dlls.append(_read_cstring(data, noff))
                    pos += 32
        pe['delayLoadImports'] = delay_dlls[:50]
    except Exception:
        pe['delayLoadImports'] = []

    # 2. Load Config Directory (DD 10)
    try:
        lc_rva, lc_sz = _pe_data_dir(data, pe_offset, 10)
        lc_info = {}
        if lc_rva and lc_sz:
            lc_off = _rva_to_offset(data, lc_rva, pe_offset)
            if lc_off is not None and lc_off + 72 <= len(data):
                opt_magic = struct.unpack_from('<H', data, pe_offset + 24)[0]
                is64 = opt_magic == 0x20b
                sz_field = struct.unpack_from('<I', data, lc_off)[0]
                lc_info['size'] = sz_field
                if is64 and lc_off + 120 <= len(data):
                    lc_info['securityCookiePresent'] = struct.unpack_from('<Q', data, lc_off + 88)[0] != 0
                    if sz_field >= 148:
                        lc_info['SEHandlerCount'] = struct.unpack_from('<Q', data, lc_off + 96)[0]
                    if sz_field >= 168:
                        lc_info['guardCFFunctionCount'] = struct.unpack_from('<Q', data, lc_off + 152)[0]
                elif not is64 and lc_off + 80 <= len(data):
                    lc_info['securityCookiePresent'] = struct.unpack_from('<I', data, lc_off + 60)[0] != 0
                    if sz_field >= 92:
                        lc_info['SEHandlerCount'] = struct.unpack_from('<I', data, lc_off + 72)[0]
                    if sz_field >= 108:
                        lc_info['guardCFFunctionCount'] = struct.unpack_from('<I', data, lc_off + 100)[0]
        pe['loadConfig'] = lc_info
    except Exception:
        pe['loadConfig'] = {}

    # 3. PE Checksum verification
    try:
        stored_ck = struct.unpack_from('<I', data, pe_offset + 24 + 64)[0]
        ck_off = pe_offset + 24 + 64
        s = 0
        for i in range(0, len(data), 2):
            if i == ck_off or i == ck_off + 2:
                continue
            if i + 2 <= len(data):
                word = struct.unpack_from('<H', data, i)[0]
            else:
                word = data[i]
            s += word
            s = (s & 0xFFFF) + (s >> 16)
        s = (s & 0xFFFF) + (s >> 16)
        computed = s + len(data)
        pe['checksum'] = {
            'stored': stored_ck,
            'computed': computed,
            'mismatch': stored_ck != 0 and stored_ck != computed
        }
    except Exception:
        pe['checksum'] = {}

    # 4-5-14. Section anomalies, VirtualSize/RawSize, ratios
    try:
        standard_names = {'.text', '.rdata', '.data', '.rsrc', '.reloc', '.bss',
                          '.idata', '.edata', '.tls', '.pdata', '.crt', '.CRT'}
        num_sec = struct.unpack_from('<H', data, pe_offset + 6)[0]
        opt_sz = struct.unpack_from('<H', data, pe_offset + 20)[0]
        sec_off = pe_offset + 24 + opt_sz
        non_std = []
        unpack_flags = []
        ratios = []
        for i in range(min(num_sec, 96)):
            o = sec_off + i * 40
            if o + 40 > len(data):
                break
            name = data[o:o + 8].rstrip(b'\x00').decode('ascii', errors='replace')
            vs = struct.unpack_from('<I', data, o + 8)[0]
            rs = struct.unpack_from('<I', data, o + 16)[0]
            ratio = round(vs / rs, 2) if rs > 0 else (0 if vs == 0 else 999999)
            ratios.append({'name': name, 'virtualSize': vs, 'rawSize': rs, 'ratio': ratio})
            if name not in standard_names:
                non_std.append(name)
            if rs > 0 and vs > 10 * rs:
                unpack_flags.append({'name': name, 'virtualSize': vs, 'rawSize': rs})
        pe['nonStandardSections'] = non_std
        pe['sectionAnomalyScore'] = len(non_std)
        pe['unpackingIndicators'] = unpack_flags
        pe['sectionRatios'] = ratios
    except Exception:
        pe['nonStandardSections'] = []
        pe['sectionAnomalyScore'] = 0
        pe['unpackingIndicators'] = []
        pe['sectionRatios'] = []

    # 6. IAT entropy
    try:
        iat_rva, iat_sz = _pe_data_dir(data, pe_offset, 12)  # DD 12 = IAT
        iat_ent = 0.0
        if iat_rva and iat_sz:
            iat_off = _rva_to_offset(data, iat_rva, pe_offset)
            if iat_off is not None and iat_off + iat_sz <= len(data):
                iat_ent = round(_shannon(data[iat_off:iat_off + iat_sz]), 4)
        pe['iatEntropy'] = iat_ent
    except Exception:
        pe['iatEntropy'] = 0.0

    # 7. DOS stub size
    try:
        dos_stub_size = pe_offset - 64  # PE sig starts right after DOS stub
        pe['dosStubSize'] = max(0, dos_stub_size)
        pe['dosStubSuspicious'] = dos_stub_size > 256
    except Exception:
        pe['dosStubSize'] = 0
        pe['dosStubSuspicious'] = False

    # 8. Export name anomalies
    try:
        exp_rva, exp_sz = _pe_data_dir(data, pe_offset, 0)
        anomalous_exports = []
        export_names = []
        if exp_rva and exp_sz:
            exp_off = _rva_to_offset(data, exp_rva, pe_offset)
            if exp_off is not None and exp_off + 40 <= len(data):
                num_names = struct.unpack_from('<I', data, exp_off + 24)[0]
                names_rva = struct.unpack_from('<I', data, exp_off + 32)[0]
                names_off = _rva_to_offset(data, names_rva, pe_offset)
                if names_off is not None:
                    for i in range(min(num_names, 500)):
                        nrva_off = names_off + i * 4
                        if nrva_off + 4 > len(data):
                            break
                        nrva = struct.unpack_from('<I', data, nrva_off)[0]
                        noff = _rva_to_offset(data, nrva, pe_offset)
                        if noff is not None and noff < len(data):
                            nm = _read_cstring(data, noff, 128)
                            export_names.append(nm)
                            if not re.match(r'^[A-Z][a-zA-Z0-9_]+$', nm):
                                anomalous_exports.append(nm)
        pe['exportNameAnomalies'] = anomalous_exports[:50]
        pe['exportAnomalyScore'] = len(anomalous_exports)
        pe['totalExports'] = len(export_names)
    except Exception:
        pe['exportNameAnomalies'] = []
        pe['exportAnomalyScore'] = 0
        pe['totalExports'] = 0

    # 9. TLS data region size (DD 9)
    try:
        tls_rva, tls_sz = _pe_data_dir(data, pe_offset, 9)
        tls_info = {'directorySize': tls_sz, 'present': tls_rva != 0}
        if tls_rva and tls_sz:
            tls_off = _rva_to_offset(data, tls_rva, pe_offset)
            opt_magic = struct.unpack_from('<H', data, pe_offset + 24)[0]
            if tls_off is not None:
                if opt_magic == 0x20b and tls_off + 40 <= len(data):
                    start = struct.unpack_from('<Q', data, tls_off)[0]
                    end = struct.unpack_from('<Q', data, tls_off + 8)[0]
                    tls_info['dataRegionSize'] = end - start if end > start else 0
                elif tls_off + 24 <= len(data):
                    start = struct.unpack_from('<I', data, tls_off)[0]
                    end = struct.unpack_from('<I', data, tls_off + 4)[0]
                    tls_info['dataRegionSize'] = end - start if end > start else 0
        pe['tls'] = tls_info
    except Exception:
        pe['tls'] = {'present': False}

    # 10. Rich header decode
    try:
        rich_idx = data.find(b'Rich')
        rich_entries = []
        if 0 < rich_idx < pe_offset:
            xor_key = struct.unpack_from('<I', data, rich_idx + 4)[0]
            # Scan backwards for "DanS" XOR'd marker
            dans_marker = struct.pack('<I', 0x536E6144 ^ xor_key)
            dans_idx = data.rfind(dans_marker, 0, rich_idx)
            if dans_idx >= 0:
                # Rich header starts after DanS + 3 padding DWORDs
                rh_start = dans_idx + 16
                pos = rh_start
                while pos + 8 <= rich_idx:
                    val1 = struct.unpack_from('<I', data, pos)[0] ^ xor_key
                    val2 = struct.unpack_from('<I', data, pos + 4)[0] ^ xor_key
                    comp_id = val1 >> 16
                    minor = val1 & 0xFFFF
                    count = val2
                    if comp_id or minor or count:
                        rich_entries.append({
                            'compId': comp_id,
                            'minorVersion': minor,
                            'buildCount': count
                        })
                    pos += 8
        pe['richHeader'] = {
            'present': len(rich_entries) > 0,
            'entries': rich_entries[:30],
            'xorKey': hex(xor_key) if rich_idx > 0 and rich_idx < pe_offset else None
        }
    except Exception:
        pe['richHeader'] = {'present': False, 'entries': []}

    # 11. Resource language IDs
    try:
        rsrc_rva, rsrc_sz = _pe_data_dir(data, pe_offset, 2)
        lang_ids = set()
        if rsrc_rva and rsrc_sz:
            rsrc_off = _rva_to_offset(data, rsrc_rva, pe_offset)
            if rsrc_off is not None and rsrc_off + 16 <= len(data):
                def _walk(base, off, depth):
                    if depth > 2 or off + 16 > len(data): return
                    n = struct.unpack_from('<H', data, off+12)[0] + struct.unpack_from('<H', data, off+14)[0]
                    p = off + 16
                    for _ in range(min(n, 200)):
                        if p + 8 > len(data): break
                        eid = struct.unpack_from('<I', data, p)[0]
                        eoff = struct.unpack_from('<I', data, p+4)[0]; p += 8
                        if depth == 2: lang_ids.add(eid & 0xFFFF)
                        elif eoff & 0x80000000:
                            so = base + (eoff & 0x7FFFFFFF)
                            if so + 16 <= len(data): _walk(base, so, depth+1)
                _walk(rsrc_off, rsrc_off, 0)
        pe['resourceLanguageIds'] = sorted(list(lang_ids))[:50]
    except Exception:
        pe['resourceLanguageIds'] = []

    # 12. Manifest parsing — embedded XML manifest
    try:
        manifest_text = None
        exec_level = None
        # Search for XML manifest via resource or raw scan
        xml_start = data.find(b'<?xml')
        while xml_start >= 0:
            xml_end = data.find(b'</assembly>', xml_start)
            if xml_end > xml_start and xml_end - xml_start < 8192:
                candidate = data[xml_start:xml_end + 11].decode('utf-8', errors='ignore')
                if 'requestedExecutionLevel' in candidate or 'assemblyIdentity' in candidate:
                    manifest_text = candidate[:4096]
                    # Extract requestedExecutionLevel
                    m = re.search(r'requestedExecutionLevel\\s+level=[\\x22\\x27](\\w+)', candidate)
                    if m:
                        exec_level = m.group(1)
                    break
            xml_start = data.find(b'<?xml', xml_start + 5)
        pe['manifest'] = {
            'present': manifest_text is not None,
            'requestedExecutionLevel': exec_level
        }
    except Exception:
        pe['manifest'] = {'present': False, 'requestedExecutionLevel': None}

    # 13. .NET CLR version (DD 14 = COM Descriptor / CLR Header)
    try:
        clr_rva, clr_sz = _pe_data_dir(data, pe_offset, 14)
        clr_info = {'present': clr_rva != 0 and clr_sz != 0}
        if clr_info['present']:
            clr_off = _rva_to_offset(data, clr_rva, pe_offset)
            if clr_off is not None and clr_off + 16 <= len(data):
                maj = struct.unpack_from('<H', data, clr_off + 4)[0]
                minor = struct.unpack_from('<H', data, clr_off + 6)[0]
                clr_info['runtimeVersion'] = f'{maj}.{minor}'
                flags = struct.unpack_from('<I', data, clr_off + 16)[0]
                clr_info['flags'] = flags
                clr_info['ilOnly'] = bool(flags & 1)
        pe['dotnetClr'] = clr_info
    except Exception:
        pe['dotnetClr'] = {'present': False}

    return pe

# ── ELF Deep ───────────────────────────────────────────────────────────────

def _elf_deep(data):
    elf = {}
    if len(data) < 64:
        return elf

    ei_class = data[4]  # 1=32-bit, 2=64-bit
    ei_data = data[5]   # 1=LE, 2=BE
    fmt = '<' if ei_data == 1 else '>'
    is64 = ei_class == 2

    try:
        if is64:
            e_phoff = struct.unpack_from(fmt + 'Q', data, 32)[0]
            e_shoff = struct.unpack_from(fmt + 'Q', data, 40)[0]
            e_phentsize = struct.unpack_from(fmt + 'H', data, 54)[0]
            e_phnum = struct.unpack_from(fmt + 'H', data, 56)[0]
            e_shentsize = struct.unpack_from(fmt + 'H', data, 58)[0]
            e_shnum = struct.unpack_from(fmt + 'H', data, 60)[0]
            e_shstrndx = struct.unpack_from(fmt + 'H', data, 62)[0]
        else:
            e_phoff = struct.unpack_from(fmt + 'I', data, 28)[0]
            e_shoff = struct.unpack_from(fmt + 'I', data, 32)[0]
            e_phentsize = struct.unpack_from(fmt + 'H', data, 42)[0]
            e_phnum = struct.unpack_from(fmt + 'H', data, 44)[0]
            e_shentsize = struct.unpack_from(fmt + 'H', data, 46)[0]
            e_shnum = struct.unpack_from(fmt + 'H', data, 48)[0]
            e_shstrndx = struct.unpack_from(fmt + 'H', data, 50)[0]
    except Exception:
        return elf

    # Build section name lookup
    def _sh_field(idx, field_off, field_fmt):
        o = e_shoff + idx * e_shentsize + field_off
        if o + struct.calcsize(field_fmt) > len(data):
            return 0
        return struct.unpack_from(fmt + field_fmt, data, o)[0]

    def _sh_name(idx):
        if e_shstrndx == 0 or e_shstrndx >= e_shnum:
            return ''
        if is64:
            strtab_off = _sh_field(e_shstrndx, 24, 'Q')
        else:
            strtab_off = _sh_field(e_shstrndx, 16, 'I')
        name_off_val = _sh_field(idx, 0, 'I')
        o = strtab_off + name_off_val
        if o >= len(data):
            return ''
        return _read_cstring(data, o, 128)

    def _sh_offset_size(idx):
        if is64:
            off = _sh_field(idx, 24, 'Q')
            sz = _sh_field(idx, 32, 'Q')
        else:
            off = _sh_field(idx, 16, 'I')
            sz = _sh_field(idx, 20, 'I')
        return off, sz

    sec_map = {}
    for i in range(min(e_shnum, 200)):
        nm = _sh_name(i)
        if nm:
            sec_map[nm] = i

    # 15. .note.gnu.build-id
    try:
        bid = ''
        if '.note.gnu.build-id' in sec_map:
            off, sz = _sh_offset_size(sec_map['.note.gnu.build-id'])
            if off + sz <= len(data) and sz > 16:
                namesz = struct.unpack_from(fmt + 'I', data, off)[0]
                descsz = struct.unpack_from(fmt + 'I', data, off + 4)[0]
                desc_off = off + 12 + ((namesz + 3) & ~3)
                if desc_off + descsz <= len(data):
                    bid = data[desc_off:desc_off + descsz].hex()
        elf['buildId'] = bid
    except Exception:
        elf['buildId'] = ''

    # 16. .comment section (compiler version)
    try:
        comment = ''
        if '.comment' in sec_map:
            off, sz = _sh_offset_size(sec_map['.comment'])
            if off + sz <= len(data) and sz < 4096:
                comment = data[off:off + sz].decode('ascii', errors='ignore').strip('\x00').strip()
        elf['comment'] = comment[:500]
    except Exception:
        elf['comment'] = ''

    # 17. .gnu.hash vs .hash presence
    try:
        elf['hasGnuHash'] = '.gnu.hash' in sec_map
        elf['hasHash'] = '.hash' in sec_map
    except Exception:
        pass

    # 18. PT_INTERP (dynamic linker path)
    try:
        interp = ''
        PT_INTERP = 3
        for i in range(min(e_phnum, 100)):
            ph_off = e_phoff + i * e_phentsize
            if ph_off + e_phentsize > len(data):
                break
            p_type = struct.unpack_from(fmt + 'I', data, ph_off)[0]
            if p_type == PT_INTERP:
                if is64:
                    p_offset = struct.unpack_from(fmt + 'Q', data, ph_off + 8)[0]
                    p_filesz = struct.unpack_from(fmt + 'Q', data, ph_off + 32)[0]
                else:
                    p_offset = struct.unpack_from(fmt + 'I', data, ph_off + 4)[0]
                    p_filesz = struct.unpack_from(fmt + 'I', data, ph_off + 16)[0]
                if p_offset + p_filesz <= len(data) and p_filesz < 512:
                    interp = data[p_offset:p_offset + p_filesz].decode('ascii', errors='ignore').strip('\x00')
                break
        elf['interpreter'] = interp
    except Exception:
        elf['interpreter'] = ''

    # 19. Full RELRO detection
    try:
        has_relro, has_bind = False, False
        for i in range(min(e_phnum, 100)):
            ph_off = e_phoff + i * e_phentsize
            if ph_off + e_phentsize > len(data): break
            p_type = struct.unpack_from(fmt + 'I', data, ph_off)[0]
            if p_type == 0x6474e552: has_relro = True  # PT_GNU_RELRO
            if p_type == 2:  # PT_DYNAMIC
                p_off = struct.unpack_from(fmt + ('Q' if is64 else 'I'), data, ph_off + (8 if is64 else 4))[0]
                p_fsz = struct.unpack_from(fmt + ('Q' if is64 else 'I'), data, ph_off + (32 if is64 else 16))[0]
                esz = 16 if is64 else 8
                pos, dend = p_off, min(p_off + p_fsz, len(data))
                while pos + esz <= dend:
                    dt = struct.unpack_from(fmt + ('q' if is64 else 'i'), data, pos)[0]
                    dv = struct.unpack_from(fmt + ('Q' if is64 else 'I'), data, pos + (8 if is64 else 4))[0]
                    if dt == 0: break
                    if dt == 24 or (dt == 30 and dv & 0x8) or (dt == 0x6ffffffb and dv & 0x1): has_bind = True
                    pos += esz
        elf['relro'] = 'full' if (has_relro and has_bind) else ('partial' if has_relro else 'none')
    except Exception:
        elf['relro'] = 'unknown'

    # 20. Fortify coverage ratio
    try:
        # Read .dynsym + .dynstr to count __*_chk vs total candidates
        chk_count = 0
        candidate_names = {'memcpy', 'memset', 'strcpy', 'strncpy', 'strcat', 'strncat',
                           'sprintf', 'snprintf', 'vsprintf', 'vsnprintf', 'gets', 'fprintf',
                           'printf', 'vfprintf', 'vprintf', 'fgets', 'read', 'recv', 'recvfrom'}
        candidate_count = 0
        text_blob = data.decode('ascii', errors='ignore')
        for cn in candidate_names:
            if cn in text_blob:
                candidate_count += 1
            if ('__' + cn + '_chk') in text_blob:
                chk_count += 1
        elf['fortify'] = {
            'fortifiedFunctions': chk_count,
            'candidateFunctions': candidate_count,
            'ratio': round(chk_count / candidate_count, 2) if candidate_count > 0 else 0
        }
    except Exception:
        elf['fortify'] = {'fortifiedFunctions': 0, 'candidateFunctions': 0, 'ratio': 0}

    # 21. Symbol versioning — minimum glibc version from .gnu.version_r
    try:
        glibc_versions = []
        if '.gnu.version_r' in sec_map:
            off, sz = _sh_offset_size(sec_map['.gnu.version_r'])
            if off + sz <= len(data) and sz < 65536:
                chunk = data[off:off + sz].decode('ascii', errors='ignore')
                for m in re.finditer(r'GLIBC_(\\d+\\.\\d+(?:\\.\\d+)?)', chunk):
                    glibc_versions.append(m.group(1))
        if not glibc_versions:
            # Fallback: scan the whole binary for GLIBC_ version tags
            ascii_blob = data.decode('ascii', errors='ignore')
            for m in re.finditer(r'GLIBC_(\\d+\\.\\d+(?:\\.\\d+)?)', ascii_blob):
                glibc_versions.append(m.group(1))
        unique_versions = sorted(set(glibc_versions), key=lambda v: [int(x) for x in v.split('.')])
        elf['glibcVersions'] = unique_versions[:20]
        elf['minGlibcVersion'] = unique_versions[-1] if unique_versions else None
    except Exception:
        elf['glibcVersions'] = []
        elf['minGlibcVersion'] = None

    return elf

# ── File Format Analysis ───────────────────────────────────────────────────

def _format_analysis(data, filepath):
    fmt = {}

    # 22. LNK file parsing
    try:
        lnk = {}
        LNK_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'
        if len(data) >= 76 and data[:4] == b'\x4c\x00\x00\x00' and data[4:20] == LNK_CLSID:
            flags = struct.unpack_from('<I', data, 20)[0]
            lnk['isLnk'] = True
            offset = 76
            if flags & 0x1 and offset + 2 <= len(data):  # HasLinkTargetIDList
                offset += 2 + struct.unpack_from('<H', data, offset)[0]
            if flags & 0x2 and offset + 4 <= len(data):  # LinkInfo
                li_sz = struct.unpack_from('<I', data, offset)[0]
                if offset + li_sz <= len(data) and li_sz >= 28:
                    li_flags = struct.unpack_from('<I', data, offset + 8)[0]
                    lp_off = struct.unpack_from('<I', data, offset + 16)[0]
                    if li_flags & 0x1 and lp_off:
                        lnk['targetPath'] = _read_cstring(data, offset + lp_off, 260)
                offset += li_sz
            for bit, field in [(0x4,'name'),(0x8,'relativePath'),(0x10,'workingDir'),(0x20,'commandLineArgs'),(0x40,'iconLocation')]:
                if not (flags & bit) or offset + 2 > len(data): continue
                cnt = struct.unpack_from('<H', data, offset)[0]; offset += 2
                if flags & 0x80:  # IsUnicode
                    bs = cnt * 2
                    if offset + bs <= len(data): lnk[field] = data[offset:offset+bs].decode('utf-16-le', errors='ignore')
                    offset += bs
                else:
                    if offset + cnt <= len(data): lnk[field] = data[offset:offset+cnt].decode('ascii', errors='ignore')
                    offset += cnt
        fmt['lnk'] = lnk if lnk else None
    except Exception:
        fmt['lnk'] = None

    # 23. ZIP bomb detection
    try:
        zip_info = None
        if data[:2] == b'PK' and len(data) >= 30:
            # Read first local file header
            comp_sz = struct.unpack_from('<I', data, 18)[0]
            uncomp_sz = struct.unpack_from('<I', data, 22)[0]
            if comp_sz > 0:
                ratio = uncomp_sz / comp_sz
                zip_info = {
                    'compressedSize': comp_sz,
                    'uncompressedSize': uncomp_sz,
                    'ratio': round(ratio, 2),
                    'isBomb': ratio > 100
                }
        fmt['zipBomb'] = zip_info
    except Exception:
        fmt['zipBomb'] = None

    # 24. Polyglot detection — check if file matches multiple magic signatures
    try:
        sigs = []
        if data[:2] == b'MZ': sigs.append('PE')
        if data[:4] == b'\x7fELF': sigs.append('ELF')
        if data[:2] == b'PK': sigs.append('ZIP')
        if data[:5] == b'%PDF-': sigs.append('PDF')
        if data[:6] in (b'\xd0\xcf\x11\xe0\xa1\xb1', ): sigs.append('OLE')
        if data[:3] == b'\xff\xd8\xff': sigs.append('JPEG')
        if data[:8] == b'\x89PNG\\r\\n\x1a\\n': sigs.append('PNG')
        if data[:4] == b'GIF8': sigs.append('GIF')
        if data[:4] == b'RIFF': sigs.append('RIFF')
        if b'{\\\\rtf' in data[:64]: sigs.append('RTF')
        # Check for embedded secondary signatures deeper in the file
        if len(sigs) == 1:
            if sigs[0] != 'PE' and b'MZ' in data[1:4096]: sigs.append('PE_embed')
            if sigs[0] != 'PDF' and b'%PDF-' in data[1:4096]: sigs.append('PDF_embed')
        fmt['polyglot'] = {
            'signatures': sigs,
            'isPolyglot': len(sigs) > 1
        }
    except Exception:
        fmt['polyglot'] = {'signatures': [], 'isPolyglot': False}

    # 25. Embedded file carving — scan for known magic at arbitrary offsets
    try:
        carve_sigs = [
            (b'MZ', 'PE/MZ'),
            (b'\x7fELF', 'ELF'),
            (b'PK\x03\x04', 'ZIP/PK'),
            (b'%PDF-', 'PDF'),
            (b'{\\\\rtf', 'RTF'),
            (b'\xd0\xcf\x11\xe0', 'OLE/CFBF'),
        ]
        carved = []
        scan_limit = min(len(data), 4 * 1024 * 1024)  # scan first 4MB
        for sig, label in carve_sigs:
            pos = 0
            count = 0
            while count < 10:
                idx = data.find(sig, pos, scan_limit)
                if idx < 0:
                    break
                if idx > 0:  # skip if at position 0 (that is the file itself)
                    carved.append({'offset': idx, 'type': label})
                pos = idx + 1
                count += 1
        fmt['embeddedFiles'] = carved[:30]
    except Exception:
        fmt['embeddedFiles'] = []

    # 26. Byte-level entropy histogram + chi-squared vs uniform
    try:
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        expected = n / 256.0
        chi2 = sum((f - expected) ** 2 / expected for f in freq) if n > 0 else 0
        fmt['byteHistogram'] = {
            'chiSquared': round(chi2, 2),
            'topBytes': sorted(range(256), key=lambda i: -freq[i])[:10],
            'zeroByteFraction': round(freq[0] / n, 4) if n > 0 else 0,
            'printableFraction': round(sum(freq[i] for i in range(32, 127)) / n, 4) if n > 0 else 0
        }
    except Exception:
        fmt['byteHistogram'] = {}

    # 27. XOR brute-force 1-byte keys on high-entropy regions
    try:
        xor_results = []
        # Use first 4KB of each high-entropy section or the whole file header
        check_region = data[:4096]
        needles = [b'http://', b'https://', b'MZ', b'This program', b'.exe', b'.dll',
                   b'<html', b'<?xml', b'cmd.exe', b'powershell']
        for key in range(1, 256):
            decoded = bytes(b ^ key for b in check_region)
            for needle in needles:
                if needle in decoded:
                    idx = decoded.find(needle)
                    xor_results.append({
                        'key': hex(key),
                        'match': needle.decode('ascii', errors='replace'),
                        'offset': idx,
                        'preview': decoded[idx:idx + 40].decode('ascii', errors='replace')
                    })
        # Deduplicate by key+match
        seen = set()
        unique_xor = []
        for r in xor_results:
            k = r['key'] + ':' + r['match']
            if k not in seen:
                seen.add(k)
                unique_xor.append(r)
        fmt['xorBruteForce'] = unique_xor[:30]
    except Exception:
        fmt['xorBruteForce'] = []

    return fmt

# ── Advanced Analysis ──────────────────────────────────────────────────────

def _advanced_analysis(data):
    adv = {}

    # 28. Stack string detection — x86 mov byte [esp+N]/[ebp+N], imm8
    try:
        stack_strings = []
        limit = min(len(data), 2 * 1024 * 1024)
        for prefix, stride, ch_off in [(b'\xC6\x44\x24', 5, 4), (b'\xC6\x45', 4, 3)]:
            plen = len(prefix)
            i = 0
            while i < limit - stride:
                if data[i:i+plen] == prefix:
                    chars, j = [], i
                    while j < limit - stride and data[j:j+plen] == prefix:
                        ch = data[j + ch_off]
                        if 0x20 <= ch < 0x7f: chars.append(chr(ch))
                        j += stride
                    if len(chars) >= 4: stack_strings.append(''.join(chars))
                    i = j
                else:
                    i += 1
        adv['stackStrings'] = list(set(stack_strings))[:50]
    except Exception:
        adv['stackStrings'] = []

    # 29. TLSH (Trend Micro Locality Sensitive Hash) — simplified implementation
    try:
        if len(data) >= 256:
            BC = 128
            bk = [0] * BC
            td = data[:min(len(data), 1024 * 1024)]
            for i in range(2, len(td)):
                bk[((td[i-2]*5) + (td[i-1]*3) + td[i]) & 0x7F] += 1
            sb = sorted(bk)
            q1, q2, q3 = sb[BC//4], sb[BC//2], sb[3*BC//4]
            bits = [0 if b<=q1 else 1 if b<=q2 else 2 if b<=q3 else 3 for b in bk]
            hx = [format((bits[i]<<6)|(bits[i+1]<<4)|(bits[i+2]<<2)|bits[i+3], '02x') for i in range(0, BC, 4)]
            ll = int(math.log2(len(data))) if len(data) > 0 else 0
            qr1 = (q1*16)//(q3+1) if q3>0 else 0
            qr2 = (q2*16)//(q3+1) if q3>0 else 0
            adv['tlsh'] = 'T1' + format(ll&0xFF,'02x') + format(qr1&0xFF,'02x') + format(qr2&0xFF,'02x') + ''.join(hx)
        else:
            adv['tlsh'] = None
    except Exception:
        adv['tlsh'] = None

    return adv

# ── Orchestrator: called for each file ─────────────────────────────────────

def deep_analysis(path, data, result):
    """Add deepAnalysis sub-dict to an existing result dict."""
    deep = {'pe': {}, 'elf': {}, 'format': {}, 'advanced': {}}

    # PE deep analysis
    is_pe = data[:2] == b'MZ' if len(data) >= 2 else False
    is_elf = data[:4] == b'\x7fELF' if len(data) >= 4 else False
    if is_pe and len(data) >= 64:
        try:
            pe_offset = struct.unpack_from('<I', data, 60)[0]
            if data[pe_offset:pe_offset + 4] == b'PE\x00\x00':
                deep['pe'] = _pe_deep(data, pe_offset)
        except Exception:
            pass

    # ELF deep analysis
    if is_elf and len(data) >= 64:
        try:
            deep['elf'] = _elf_deep(data)
        except Exception:
            pass

    # Format analysis (applies to all files)
    try:
        deep['format'] = _format_analysis(data, path)
    except Exception:
        pass

    # Advanced analysis
    try:
        deep['advanced'] = _advanced_analysis(data)
    except Exception:
        pass

    result['deepAnalysis'] = deep

# deep_analysis() is callable standalone — no monkey-patching needed
`;
}
