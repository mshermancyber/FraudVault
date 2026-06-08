// ── YARA-like Pattern Scanner ───────────────────────────────────────────────
//
// Implements ~50 high-value YARA-like pattern detection rules as a Python
// script that runs inside the sandbox jail. Checks for:
//   - Known packer signatures
//   - Malware family byte patterns
//   - Suspicious PE characteristics
//   - Anti-debug/anti-VM tricks
//   - Crypto constants
//   - Ransomware indicators
//   - RAT/C2 indicators
//
// Results are stored in the yara_scan_results table.

import type pg from 'pg';
import type { Logger } from 'pino';

// ── Types ──────────────────────────────────────────────────────────────────────

export interface YaraMatchResult {
  ruleName: string;
  category: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  matchedStrings: string[];
  matchOffset: number | null;
}

export interface YaraScanOutput {
  filePath: string;
  fileSize: number;
  matches: YaraMatchResult[];
  scanDuration: number;
  error: string | null;
}

// ── Python Script for Jail Execution ───────────────────────────────────────────

/**
 * Returns the Python script that performs YARA-like pattern scanning.
 * This script is injected into the sandbox container and executed after
 * the main analysis script.
 */
export function getYaraScannerScript(): string {
  return `
import json, os, sys, struct, re, time, hashlib

# ═══════════════════════════════════════════════════════════════════════════════
# YARA-like Pattern Rules
# ═══════════════════════════════════════════════════════════════════════════════
#
# Each rule has:
#   name       - unique rule identifier
#   category   - classification (packer, malware, technique, crypto, etc.)
#   desc       - human-readable description
#   severity   - critical/high/medium/low/info
#   strings    - list of byte patterns to match (raw bytes or regex)
#   condition  - 'any' (any string matches), 'all' (all must match),
#                '2_of' (at least 2), '3_of' (at least 3)
#   pe_only    - if True, only scan PE files

RULES = [
    # ─── Packers ─────────────────────────────────────────────────────────────
    {
        'name': 'UPX_Packer',
        'category': 'packer',
        'desc': 'UPX packer signatures detected',
        'severity': 'medium',
        'strings': [b'UPX0', b'UPX1', b'UPX!', b'UPX2'],
        'condition': 'any',
        'pe_only': False,
    },
    {
        'name': 'ASPack_Packer',
        'category': 'packer',
        'desc': 'ASPack packer detected',
        'severity': 'medium',
        'strings': [b'.aspack', b'ASPack', b'.adata'],
        'condition': 'any',
        'pe_only': True,
    },
    {
        'name': 'Themida_Packer',
        'category': 'packer',
        'desc': 'Themida/WinLicense protector detected',
        'severity': 'high',
        'strings': [b'.themida', b'Themida', b'WinLicense', b'.winlice'],
        'condition': 'any',
        'pe_only': True,
    },
    {
        'name': 'VMProtect_Packer',
        'category': 'packer',
        'desc': 'VMProtect software protection detected',
        'severity': 'high',
        'strings': [b'.vmp0', b'.vmp1', b'VMProtect', b'.vmp2'],
        'condition': 'any',
        'pe_only': True,
    },
    {
        'name': 'PECompact_Packer',
        'category': 'packer',
        'desc': 'PECompact packer detected',
        'severity': 'medium',
        'strings': [b'PEC2', b'PECompact2', b'pec1', b'pec2'],
        'condition': 'any',
        'pe_only': True,
    },
    {
        'name': 'MPRESS_Packer',
        'category': 'packer',
        'desc': 'MPRESS packer detected',
        'severity': 'medium',
        'strings': [b'.MPRESS1', b'.MPRESS2', b'MPRESS'],
        'condition': 'any',
        'pe_only': True,
    },
    {
        'name': 'NSPack_Packer',
        'category': 'packer',
        'desc': 'NSPack/North Star packer detected',
        'severity': 'medium',
        'strings': [b'nsp0', b'nsp1', b'nsp2', b'.nsp'],
        'condition': 'any',
        'pe_only': True,
    },

    # ─── Ransomware Indicators ───────────────────────────────────────────────
    {
        'name': 'Ransomware_Note_Indicators',
        'category': 'ransomware',
        'desc': 'Ransomware note language patterns detected',
        'severity': 'critical',
        'strings': [b'YOUR FILES', b'ENCRYPTED', b'BITCOIN', b'RANSOM', b'DECRYPT', b'PAYMENT'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'Ransomware_Extension_Changer',
        'category': 'ransomware',
        'desc': 'File extension modification patterns (ransomware behavior)',
        'severity': 'high',
        'strings': [b'.encrypted', b'.locked', b'.crypto', b'.crypt', b'.enc', b'.pay', b'.WNCRY'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'Ransomware_Recovery_Inhibitor',
        'category': 'ransomware',
        'desc': 'Shadow copy/recovery deletion commands',
        'severity': 'critical',
        'strings': [b'vssadmin', b'delete shadows', b'bcdedit', b'recoveryenabled', b'wbadmin', b'wmic shadowcopy'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'WannaCry_Indicators',
        'category': 'ransomware',
        'desc': 'WannaCry ransomware indicators',
        'severity': 'critical',
        'strings': [b'WanaCrypt0r', b'WANACRY', b'wncry', b'tasksche.exe', b'@wanadecryptor'],
        'condition': 'any',
        'pe_only': False,
    },

    # ─── Cobalt Strike / C2 ──────────────────────────────────────────────────
    {
        'name': 'Cobalt_Strike_Beacon',
        'category': 'c2',
        'desc': 'Cobalt Strike beacon indicators',
        'severity': 'critical',
        'strings': [b'ReflectiveLoader', b'beacon.dll', b'beacon.x64.dll', b'beacon_metadata', b'beacon_keys'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'Meterpreter_Indicators',
        'category': 'c2',
        'desc': 'Metasploit Meterpreter indicators',
        'severity': 'critical',
        'strings': [b'metsrv', b'meterpreter', b'stdapi_', b'priv_elevate', b'ext_server_'],
        'condition': 'any',
        'pe_only': False,
    },
    {
        'name': 'Generic_RAT_Indicators',
        'category': 'c2',
        'desc': 'Generic RAT/backdoor command patterns',
        'severity': 'high',
        'strings': [b'cmd.exe /c', b'powershell -enc', b'powershell -e ', b'iex(', b'IEX (', b'downloadstring'],
        'condition': '2_of',
        'pe_only': False,
    },

    # ─── Anti-Debug / Anti-VM ────────────────────────────────────────────────
    {
        'name': 'Anti_Debug_API',
        'category': 'anti-analysis',
        'desc': 'Anti-debugging API calls detected',
        'severity': 'high',
        'strings': [b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent', b'NtQueryInformationProcess', b'OutputDebugString'],
        'condition': '2_of',
        'pe_only': True,
    },
    {
        'name': 'Anti_VM_Detection',
        'category': 'anti-analysis',
        'desc': 'Virtual machine detection techniques',
        'severity': 'high',
        'strings': [b'VMware', b'VBoxGuest', b'VBOX HARDDISK', b'Virtual HD', b'QEMU', b'Xen', b'SbieDll.dll'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'Anti_Sandbox_Timing',
        'category': 'anti-analysis',
        'desc': 'Sandbox evasion via timing checks',
        'severity': 'medium',
        'strings': [b'GetTickCount', b'QueryPerformanceCounter', b'Sleep', b'NtDelayExecution'],
        'condition': '3_of',
        'pe_only': True,
    },
    {
        'name': 'Anti_Analysis_Environment',
        'category': 'anti-analysis',
        'desc': 'Checks for analysis environment artifacts',
        'severity': 'high',
        'strings': [b'wireshark', b'procmon', b'ollydbg', b'x64dbg', b'ida.exe', b'fiddler', b'ProcessHacker'],
        'condition': '2_of',
        'pe_only': False,
    },

    # ─── Process Injection ───────────────────────────────────────────────────
    {
        'name': 'Process_Injection_Classic',
        'category': 'technique',
        'desc': 'Classic process injection API pattern',
        'severity': 'high',
        'strings': [b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread', b'NtWriteVirtualMemory'],
        'condition': 'all',
        'pe_only': True,
    },
    {
        'name': 'Process_Hollowing',
        'category': 'technique',
        'desc': 'Process hollowing technique indicators',
        'severity': 'critical',
        'strings': [b'NtUnmapViewOfSection', b'ZwUnmapViewOfSection', b'NtResumeThread', b'CREATE_SUSPENDED'],
        'condition': '2_of',
        'pe_only': True,
    },
    {
        'name': 'APC_Injection',
        'category': 'technique',
        'desc': 'APC-based code injection',
        'severity': 'high',
        'strings': [b'QueueUserAPC', b'NtQueueApcThread', b'SuspendThread', b'ResumeThread'],
        'condition': '2_of',
        'pe_only': True,
    },

    # ─── Privilege Escalation ────────────────────────────────────────────────
    {
        'name': 'Privilege_Escalation',
        'category': 'technique',
        'desc': 'Privilege escalation indicators',
        'severity': 'medium',
        'strings': [b'SeDebugPrivilege', b'ImpersonateLoggedOnUser', b'NtSetInformationToken', b'RtlAdjustPrivilege'],
        'condition': '2_of',
        'pe_only': True,
    },
    {
        'name': 'UAC_Bypass',
        'category': 'technique',
        'desc': 'UAC bypass indicators',
        'severity': 'high',
        'strings': [b'eventvwr.exe', b'fodhelper.exe', b'computerdefaults.exe', b'sdclt.exe', b'slui.exe'],
        'condition': 'any',
        'pe_only': False,
    },

    # ─── Persistence ─────────────────────────────────────────────────────────
    {
        'name': 'Registry_Persistence',
        'category': 'persistence',
        'desc': 'Registry-based persistence mechanisms',
        'severity': 'high',
        'strings': [b'CurrentVersion\\\\Run', b'CurrentVersion\\\\RunOnce', b'Winlogon\\\\Shell', b'Image File Execution', b'AppInit_DLLs'],
        'condition': 'any',
        'pe_only': False,
    },
    {
        'name': 'Scheduled_Task_Persistence',
        'category': 'persistence',
        'desc': 'Scheduled task creation for persistence',
        'severity': 'high',
        'strings': [b'schtasks', b'/create', b'SCHED_TASK', b'Register-ScheduledTask'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'Service_Installation',
        'category': 'persistence',
        'desc': 'Windows service installation for persistence',
        'severity': 'high',
        'strings': [b'CreateService', b'StartService', b'sc create', b'New-Service'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'WMI_Persistence',
        'category': 'persistence',
        'desc': 'WMI event subscription persistence',
        'severity': 'high',
        'strings': [b'__EventFilter', b'__EventConsumer', b'__FilterToConsumerBinding', b'ActiveScriptEventConsumer'],
        'condition': '2_of',
        'pe_only': False,
    },

    # ─── Credential Theft ────────────────────────────────────────────────────
    {
        'name': 'Credential_Dumping',
        'category': 'credential-access',
        'desc': 'Credential dumping indicators (Mimikatz-like)',
        'severity': 'critical',
        'strings': [b'mimikatz', b'sekurlsa', b'logonpasswords', b'lsadump', b'kerberos::'],
        'condition': 'any',
        'pe_only': False,
    },
    {
        'name': 'Browser_Credential_Theft',
        'category': 'credential-access',
        'desc': 'Browser credential theft indicators',
        'severity': 'high',
        'strings': [b'Login Data', b'\\\\Google\\\\Chrome', b'\\\\Mozilla\\\\Firefox', b'logins.json', b'signons.sqlite', b'cookies.sqlite'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'Keylogger_Indicators',
        'category': 'credential-access',
        'desc': 'Keylogging capability indicators',
        'severity': 'high',
        'strings': [b'SetWindowsHookEx', b'GetAsyncKeyState', b'GetKeyState', b'GetKeyboardState', b'keylog'],
        'condition': '2_of',
        'pe_only': False,
    },

    # ─── Network / Exfiltration ──────────────────────────────────────────────
    {
        'name': 'Data_Exfiltration_Indicators',
        'category': 'exfiltration',
        'desc': 'Data exfiltration technique indicators',
        'severity': 'high',
        'strings': [b'FtpPutFile', b'HttpSendRequest', b'InternetWriteFile', b'URLDownloadToFile', b'WinHttpSendRequest'],
        'condition': '2_of',
        'pe_only': True,
    },
    {
        'name': 'DNS_Tunneling_Indicators',
        'category': 'exfiltration',
        'desc': 'DNS tunneling indicators',
        'severity': 'high',
        'strings': [b'DnsQuery_A', b'DnsQuery_W', b'nslookup', b'txt record', b'.dnscat.'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'Tor_Communication',
        'category': 'c2',
        'desc': 'Tor network communication indicators',
        'severity': 'high',
        'strings': [b'.onion', b'tor2web', b'torproject.org', b'SOCKS5', b'127.0.0.1:9050'],
        'condition': '2_of',
        'pe_only': False,
    },

    # ─── Crypto Constants ────────────────────────────────────────────────────
    {
        'name': 'AES_Constants',
        'category': 'crypto',
        'desc': 'AES S-box constants detected (encryption capability)',
        'severity': 'medium',
        'strings': [
            b'\\x63\\x7c\\x77\\x7b\\xf2\\x6b\\x6f\\xc5\\x30\\x01\\x67\\x2b\\xfe\\xd7\\xab\\x76',
            b'\\x52\\x09\\x6a\\xd5\\x30\\x36\\xa5\\x38\\xbf\\x40\\xa3\\x9e\\x81\\xf3\\xd7\\xfb',
        ],
        'condition': 'any',
        'pe_only': False,
    },
    {
        'name': 'RC4_Indicators',
        'category': 'crypto',
        'desc': 'RC4 cipher implementation indicators',
        'severity': 'medium',
        'strings': [b'CryptDecrypt', b'CryptEncrypt', b'RC4', b'ARC4', b'CryptDeriveKey'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'RSA_Key_Indicators',
        'category': 'crypto',
        'desc': 'RSA key handling indicators',
        'severity': 'medium',
        'strings': [b'RSA1', b'-----BEGIN RSA', b'-----BEGIN PUBLIC KEY', b'CryptImportKey', b'PUBLICKEYBLOB'],
        'condition': 'any',
        'pe_only': False,
    },
    {
        'name': 'Base64_Encoded_PE',
        'category': 'technique',
        'desc': 'Base64-encoded PE file detected',
        'severity': 'high',
        'strings': [b'TVqQAAMAAAA', b'TVpQAAIAAAA', b'TVoAAAAAAAA', b'TVpBRUAAAA'],
        'condition': 'any',
        'pe_only': False,
    },

    # ─── Shellcode / Exploit ─────────────────────────────────────────────────
    {
        'name': 'Shellcode_Indicators',
        'category': 'technique',
        'desc': 'Shellcode execution indicators',
        'severity': 'critical',
        'strings': [b'\\xfc\\xe8', b'\\x60\\x89\\xe5', b'\\xeb\\xfe', b'VirtualProtect', b'PAGE_EXECUTE_READWRITE'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'Heap_Spray_Indicators',
        'category': 'technique',
        'desc': 'Heap spray technique indicators',
        'severity': 'high',
        'strings': [b'\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c', b'\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90', b'\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41'],
        'condition': 'any',
        'pe_only': False,
    },

    # ─── Information Gathering ───────────────────────────────────────────────
    {
        'name': 'System_Reconnaissance',
        'category': 'discovery',
        'desc': 'System information gathering commands',
        'severity': 'medium',
        'strings': [b'systeminfo', b'ipconfig /all', b'whoami', b'net user', b'net group', b'tasklist'],
        'condition': '3_of',
        'pe_only': False,
    },
    {
        'name': 'Network_Discovery',
        'category': 'discovery',
        'desc': 'Network discovery/scanning indicators',
        'severity': 'medium',
        'strings': [b'net view', b'arp -a', b'nbtstat', b'netstat -an', b'net share', b'route print'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'Domain_Enumeration',
        'category': 'discovery',
        'desc': 'Active Directory enumeration indicators',
        'severity': 'high',
        'strings': [b'dsquery', b'net group "domain admins"', b'nltest', b'ldap://', b'Get-ADUser', b'Get-ADComputer'],
        'condition': '2_of',
        'pe_only': False,
    },

    # ─── Suspicious PE Characteristics ───────────────────────────────────────
    {
        'name': 'Suspicious_Section_Names',
        'category': 'suspicious',
        'desc': 'Non-standard PE section names indicating modification',
        'severity': 'medium',
        'strings': [b'.evil', b'.virus', b'.hack', b'.infect', b'.boom', b'.dead'],
        'condition': 'any',
        'pe_only': True,
    },
    {
        'name': 'Double_Extension_Trick',
        'category': 'technique',
        'desc': 'Double file extension social engineering trick',
        'severity': 'high',
        'strings': [b'.pdf.exe', b'.doc.exe', b'.jpg.exe', b'.txt.exe', b'.docx.scr', b'.pdf.scr'],
        'condition': 'any',
        'pe_only': False,
    },
    {
        'name': 'Embedded_PowerShell',
        'category': 'technique',
        'desc': 'Embedded PowerShell script execution',
        'severity': 'high',
        'strings': [b'powershell.exe', b'-ExecutionPolicy Bypass', b'-WindowStyle Hidden', b'-NonInteractive', b'FromBase64String'],
        'condition': '2_of',
        'pe_only': False,
    },

    # ─── Specific Malware Families ───────────────────────────────────────────
    {
        'name': 'Emotet_Indicators',
        'category': 'malware',
        'desc': 'Emotet malware family indicators',
        'severity': 'critical',
        'strings': [b'\\\\Outlook\\\\', b'\\\\Thunderbird\\\\', b'GetExtendedTcpTable', b'regsvr32', b'rundll32.exe'],
        'condition': '3_of',
        'pe_only': False,
    },
    {
        'name': 'AgentTesla_Indicators',
        'category': 'malware',
        'desc': 'Agent Tesla stealer indicators',
        'severity': 'critical',
        'strings': [b'smtp.gmail.com', b'smtp.yandex.com', b'\\\\Chromium\\\\', b'\\\\Opera Software\\\\', b'passwords.txt'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'Remcos_RAT',
        'category': 'malware',
        'desc': 'Remcos RAT indicators',
        'severity': 'critical',
        'strings': [b'Remcos', b'remcos.exe', b'Breaking-Security.Net', b'licence_code'],
        'condition': 'any',
        'pe_only': False,
    },
    {
        'name': 'AsyncRAT_Indicators',
        'category': 'malware',
        'desc': 'AsyncRAT indicators',
        'severity': 'critical',
        'strings': [b'AsyncClient', b'AsyncRAT', b'ABORTING', b'pastebin.com', b'Stub.exe'],
        'condition': '2_of',
        'pe_only': False,
    },
    {
        'name': 'Qakbot_Indicators',
        'category': 'malware',
        'desc': 'Qakbot/QBot banking trojan indicators',
        'severity': 'critical',
        'strings': [b'%s\\\\system32\\\\', b'C:\\\\INTERNAL\\\\__empty', b'/t5', b'stager_1.dll'],
        'condition': '2_of',
        'pe_only': False,
    },
]


def check_condition(matches, condition):
    """Evaluate the match condition."""
    if condition == 'any':
        return len(matches) >= 1
    elif condition == 'all':
        return len(matches) == len(RULES)  # not useful here; uses per-rule string count
    elif condition == '2_of':
        return len(matches) >= 2
    elif condition == '3_of':
        return len(matches) >= 3
    return False


def scan_file(filepath):
    """Scan a single file against all YARA-like rules."""
    start_time = time.time()
    results = []
    error = None

    try:
        with open(filepath, 'rb') as f:
            data = f.read(50 * 1024 * 1024)  # Max 50MB per file

        file_size = len(data)
        is_pe = data[:2] == b'MZ' if len(data) >= 2 else False

        for rule in RULES:
            # Skip PE-only rules for non-PE files
            if rule.get('pe_only', False) and not is_pe:
                continue

            matched_strings = []
            for pattern in rule['strings']:
                # Check if pattern is found in the data
                try:
                    idx = data.find(pattern)
                    if idx >= 0:
                        matched_strings.append({
                            'pattern': pattern.decode('ascii', errors='replace')[:60],
                            'offset': idx,
                        })
                except Exception:
                    continue

            # Evaluate condition with matched unique strings
            condition = rule['condition']
            required = 1
            if condition == 'all':
                required = len(rule['strings'])
            elif condition == '2_of':
                required = 2
            elif condition == '3_of':
                required = 3

            if len(matched_strings) >= required:
                results.append({
                    'ruleName': rule['name'],
                    'category': rule['category'],
                    'description': rule['desc'],
                    'severity': rule['severity'],
                    'matchedStrings': [m['pattern'] for m in matched_strings],
                    'matchOffset': matched_strings[0]['offset'] if matched_strings else None,
                })

    except Exception as e:
        error = str(e)

    scan_duration = time.time() - start_time

    return {
        'filePath': filepath,
        'fileSize': file_size if 'file_size' in dir() else 0,
        'matches': results,
        'scanDuration': round(scan_duration, 3),
        'error': error,
    }


# ─── Main Entry Point ────────────────────────────────────────────────────────

if __name__ == '__main__':
    targets = []

    # Scan extracted files and the sample itself
    for d in ['/tmp/scanboy-extracted', '/opt/scanboy']:
        if os.path.isdir(d):
            for root_dir, dirs, files in os.walk(d):
                for f in files:
                    fp = os.path.join(root_dir, f)
                    if os.path.isfile(fp) and os.path.getsize(fp) > 0:
                        targets.append(fp)

    all_results = []
    for target in targets[:10]:  # Limit to 10 files
        result = scan_file(target)
        all_results.append(result)

    print(json.dumps({'yaraResults': all_results}))
`;
}

// ── DB Storage ─────────────────────────────────────────────────────────────────

/**
 * Store YARA scan results in the database.
 * Since the yara_scan_results table requires a rule_id FK to yara_rules,
 * we first ensure the rule exists in yara_rules, then insert the scan result.
 */
export async function storeYaraResults(
  pool: pg.Pool,
  submissionId: string,
  scanOutputs: YaraScanOutput[],
  logger: Logger,
): Promise<void> {
  for (const output of scanOutputs) {
    if (output.error) {
      logger.warn({ filePath: output.filePath, error: output.error }, 'YARA scan error for file');
      continue;
    }

    for (const match of output.matches) {
      try {
        // Upsert the rule into yara_rules if it doesn't exist
        const ruleResult = await pool.query<{ id: string }>(
          `INSERT INTO yara_rules (name, description, content, category, author, is_active)
           VALUES ($1, $2, $3, $4, 'scanboy-builtin', TRUE)
           ON CONFLICT ON CONSTRAINT uq_yara_rules_name DO UPDATE SET match_count = yara_rules.match_count + 1
           RETURNING id`,
          [
            match.ruleName,
            match.description,
            `rule ${match.ruleName} { /* built-in pattern rule */ }`,
            match.category,
          ],
        );

        const ruleRow = ruleResult.rows[0];
        if (!ruleRow) continue;

        // Insert the scan result
        await pool.query(
          `INSERT INTO yara_scan_results (submission_id, rule_id, matched, match_details)
           VALUES ($1, $2, TRUE, $3)
           ON CONFLICT DO NOTHING`,
          [
            submissionId,
            ruleRow.id,
            JSON.stringify({
              filePath: output.filePath,
              fileSize: output.fileSize,
              severity: match.severity,
              matchedStrings: match.matchedStrings,
              matchOffset: match.matchOffset,
              scanDuration: output.scanDuration,
            }),
          ],
        );
      } catch (err) {
        logger.warn({ err, ruleName: match.ruleName }, 'Failed to store YARA result');
      }
    }
  }
}

/**
 * Parse the JSON output from the YARA scanner Python script.
 */
export function parseYaraScanOutput(jsonOutput: string): YaraScanOutput[] {
  try {
    const parsed = JSON.parse(jsonOutput.trim()) as { yaraResults: YaraScanOutput[] };
    if (Array.isArray(parsed.yaraResults)) {
      return parsed.yaraResults;
    }
    return [];
  } catch {
    return [];
  }
}
