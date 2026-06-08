/**
 * Built-in YARA-like pattern scanner Python script.
 * Runs inside the sandbox container to detect ransomware, RATs, anti-debug,
 * process injection, and other suspicious patterns via byte-level matching.
 * Complements the community YARA rules from vuln-feeds.
 */
export function getYaraScannerScript(): string {
  return `
import json, os, sys, struct, re, time

RULES = [
    # Packers
    {'name': 'UPX_Packer', 'category': 'packer', 'desc': 'UPX packer signatures detected', 'severity': 'medium', 'strings': [b'UPX0', b'UPX1', b'UPX!', b'UPX2'], 'condition': 'any', 'pe_only': False},
    {'name': 'Themida_Packer', 'category': 'packer', 'desc': 'Themida/WinLicense protector detected', 'severity': 'high', 'strings': [b'.themida', b'Themida', b'WinLicense', b'.winlice'], 'condition': 'any', 'pe_only': True},
    {'name': 'VMProtect_Packer', 'category': 'packer', 'desc': 'VMProtect software protection detected', 'severity': 'high', 'strings': [b'.vmp0', b'.vmp1', b'VMProtect', b'.vmp2'], 'condition': 'any', 'pe_only': True},

    # Ransomware
    {'name': 'Ransomware_Note_Indicators', 'category': 'ransomware', 'desc': 'Ransomware note language patterns detected', 'severity': 'critical', 'strings': [b'YOUR FILES', b'ENCRYPTED', b'BITCOIN', b'RANSOM', b'DECRYPT', b'PAYMENT'], 'condition': '2_of', 'pe_only': False},
    {'name': 'Ransomware_Extension_Changer', 'category': 'ransomware', 'desc': 'File extension modification patterns', 'severity': 'high', 'strings': [b'.encrypted', b'.locked', b'.crypto', b'.crypt', b'.enc', b'.pay', b'.WNCRY'], 'condition': '2_of', 'pe_only': False},
    {'name': 'Ransomware_Recovery_Inhibitor', 'category': 'ransomware', 'desc': 'Shadow copy/recovery deletion commands', 'severity': 'critical', 'strings': [b'vssadmin', b'delete shadows', b'bcdedit', b'recoveryenabled', b'wbadmin', b'wmic shadowcopy'], 'condition': '2_of', 'pe_only': False},
    {'name': 'WannaCry_Indicators', 'category': 'ransomware', 'desc': 'WannaCry ransomware indicators', 'severity': 'critical', 'strings': [b'WanaCrypt0r', b'WANACRY', b'wncry', b'tasksche.exe', b'@wanadecryptor'], 'condition': 'any', 'pe_only': False},

    # C2 / RAT
    {'name': 'Cobalt_Strike_Beacon', 'category': 'c2', 'desc': 'Cobalt Strike beacon indicators', 'severity': 'critical', 'strings': [b'ReflectiveLoader', b'beacon.dll', b'beacon.x64.dll', b'beacon_metadata', b'beacon_keys'], 'condition': '2_of', 'pe_only': False},
    {'name': 'Meterpreter_Indicators', 'category': 'c2', 'desc': 'Metasploit Meterpreter indicators', 'severity': 'critical', 'strings': [b'metsrv', b'meterpreter', b'stdapi_', b'priv_elevate', b'ext_server_'], 'condition': 'any', 'pe_only': False},
    {'name': 'Generic_RAT_Indicators', 'category': 'c2', 'desc': 'Generic RAT/backdoor command patterns', 'severity': 'high', 'strings': [b'cmd.exe /c', b'powershell -enc', b'powershell -e ', b'iex(', b'IEX (', b'downloadstring'], 'condition': '2_of', 'pe_only': False},

    # Anti-debug / Anti-VM
    {'name': 'Anti_Debug_API', 'category': 'anti-analysis', 'desc': 'Anti-debugging API calls detected', 'severity': 'high', 'strings': [b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent', b'NtQueryInformationProcess', b'OutputDebugString'], 'condition': 'all', 'pe_only': True},
    {'name': 'Anti_VM_Detection', 'category': 'anti-analysis', 'desc': 'Virtual machine detection techniques', 'severity': 'high', 'strings': [b'VMware', b'VBoxGuest', b'VBOX HARDDISK', b'Virtual HD', b'QEMU', b'Xen', b'SbieDll.dll'], 'condition': '2_of', 'pe_only': False},

    # Process Injection
    {'name': 'Process_Injection_Classic', 'category': 'technique', 'desc': 'Classic process injection API pattern', 'severity': 'high', 'strings': [b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread', b'NtWriteVirtualMemory'], 'condition': 'all', 'pe_only': True},
    {'name': 'Process_Hollowing', 'category': 'technique', 'desc': 'Process hollowing technique indicators', 'severity': 'critical', 'strings': [b'NtUnmapViewOfSection', b'ZwUnmapViewOfSection', b'NtResumeThread', b'CREATE_SUSPENDED'], 'condition': '2_of', 'pe_only': True},

    # Persistence
    {'name': 'Registry_Persistence', 'category': 'persistence', 'desc': 'Registry-based persistence mechanisms', 'severity': 'high', 'strings': [b'CurrentVersion\\\\Run', b'CurrentVersion\\\\RunOnce', b'Winlogon\\\\Shell', b'Image File Execution', b'AppInit_DLLs'], 'condition': 'any', 'pe_only': False},
    {'name': 'Service_Installation', 'category': 'persistence', 'desc': 'Windows service installation for persistence', 'severity': 'high', 'strings': [b'CreateService', b'StartService', b'sc create', b'New-Service'], 'condition': '2_of', 'pe_only': False},

    # Credential Theft
    {'name': 'Credential_Dumping', 'category': 'credential-access', 'desc': 'Credential dumping indicators (Mimikatz-like)', 'severity': 'critical', 'strings': [b'mimikatz', b'sekurlsa', b'logonpasswords', b'lsadump', b'kerberos::'], 'condition': 'any', 'pe_only': False},
    {'name': 'Keylogger_Indicators', 'category': 'credential-access', 'desc': 'Keylogging capability indicators', 'severity': 'high', 'strings': [b'SetWindowsHookEx', b'GetAsyncKeyState', b'GetKeyState', b'GetKeyboardState', b'keylog'], 'condition': 'all', 'pe_only': True},

    # Network / Exfiltration
    {'name': 'Data_Exfiltration_Indicators', 'category': 'exfiltration', 'desc': 'Data exfiltration technique indicators', 'severity': 'high', 'strings': [b'FtpPutFile', b'HttpSendRequest', b'InternetWriteFile', b'URLDownloadToFile', b'WinHttpSendRequest'], 'condition': 'all', 'pe_only': True},
    {'name': 'Tor_Communication', 'category': 'c2', 'desc': 'Tor network communication indicators', 'severity': 'high', 'strings': [b'.onion', b'tor2web', b'torproject.org', b'SOCKS5', b'127.0.0.1:9050'], 'condition': '2_of', 'pe_only': False},

    # Crypto
    {'name': 'RSA_Key_Indicators', 'category': 'crypto', 'desc': 'RSA key handling indicators', 'severity': 'medium', 'strings': [b'RSA1', b'-----BEGIN RSA', b'-----BEGIN PUBLIC KEY', b'CryptImportKey', b'PUBLICKEYBLOB'], 'condition': 'any', 'pe_only': False},
    {'name': 'Base64_Encoded_PE', 'category': 'technique', 'desc': 'Base64-encoded PE file detected', 'severity': 'high', 'strings': [b'TVqQAAMAAAA', b'TVpQAAIAAAA', b'TVoAAAAAAAA', b'TVpBRUAAAA'], 'condition': 'any', 'pe_only': False},

    # Shellcode
    {'name': 'Shellcode_Indicators', 'category': 'technique', 'desc': 'Shellcode execution indicators', 'severity': 'critical', 'strings': [b'VirtualProtect', b'PAGE_EXECUTE_READWRITE'], 'condition': 'all', 'pe_only': False},

    # Specific malware families
    {'name': 'Emotet_Indicators', 'category': 'malware', 'desc': 'Emotet malware family indicators', 'severity': 'critical', 'strings': [b'\\\\Outlook\\\\', b'\\\\Thunderbird\\\\', b'GetExtendedTcpTable', b'regsvr32', b'rundll32.exe'], 'condition': '3_of', 'pe_only': False},
    {'name': 'AgentTesla_Indicators', 'category': 'malware', 'desc': 'Agent Tesla stealer indicators', 'severity': 'critical', 'strings': [b'smtp.gmail.com', b'smtp.yandex.com', b'\\\\Chromium\\\\', b'\\\\Opera Software\\\\', b'passwords.txt'], 'condition': '2_of', 'pe_only': False},
    {'name': 'Remcos_RAT', 'category': 'malware', 'desc': 'Remcos RAT indicators', 'severity': 'critical', 'strings': [b'Remcos', b'remcos.exe', b'Breaking-Security.Net', b'licence_code'], 'condition': 'any', 'pe_only': False},

    # Embedded PowerShell
    {'name': 'Embedded_PowerShell', 'category': 'technique', 'desc': 'Embedded PowerShell script execution', 'severity': 'high', 'strings': [b'powershell.exe', b'-ExecutionPolicy Bypass', b'-WindowStyle Hidden', b'-NonInteractive', b'FromBase64String'], 'condition': '2_of', 'pe_only': False},

    # RedBoot-specific
    {'name': 'MBR_Overwrite', 'category': 'ransomware', 'desc': 'MBR overwrite indicators', 'severity': 'critical', 'strings': [b'\\\\\\\\.\\\\PhysicalDrive', b'MBR', b'boot.asm', b'overwrite'], 'condition': '2_of', 'pe_only': False},
]


def scan_file(filepath):
    start_time = time.time()
    results = []
    error = None
    file_size = 0

    try:
        with open(filepath, 'rb') as f:
            data = f.read(50 * 1024 * 1024)

        file_size = len(data)
        is_pe = data[:2] == b'MZ' if len(data) >= 2 else False

        for rule in RULES:
            if rule.get('pe_only', False) and not is_pe:
                continue

            matched_strings = []
            for pattern in rule['strings']:
                try:
                    idx = data.find(pattern)
                    if idx >= 0:
                        matched_strings.append({
                            'pattern': pattern.decode('ascii', errors='replace')[:60],
                            'offset': idx,
                        })
                except Exception:
                    continue

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

    return {
        'filePath': filepath,
        'fileSize': file_size,
        'matches': results,
        'scanDuration': round(time.time() - start_time, 3),
        'error': error,
    }


if __name__ == '__main__':
    targets = []
    for d in ['/tmp/scanboy-extracted', '/opt/scanboy']:
        if os.path.isdir(d):
            for root_dir, dirs, files in os.walk(d):
                for f in files:
                    fp = os.path.join(root_dir, f)
                    if os.path.isfile(fp) and os.path.getsize(fp) > 0:
                        targets.append(fp)

    all_results = []
    for target in targets[:10]:
        result = scan_file(target)
        all_results.append(result)

    print(json.dumps({'yaraResults': all_results}))
`;
}
