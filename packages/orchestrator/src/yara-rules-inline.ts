// ── Inline YARA Rules for Real Binary Scanning ────────────────────────────────
//
// Contains 50 actual YARA rules as a string constant that can be written to
// the sandbox container filesystem and executed by the `yara` binary.
// These rules target packers, known malware families, suspicious techniques,
// ransomware, RATs, credential stealers, and other high-signal indicators.
//
// Usage: Write YARA_RULES_CONTENT to a file in the container, then run:
//   yara -w /tmp/scanboy-rules.yar /opt/scanboy/sample
//
// The executor installs `yara` (apt-get) in the running container on first
// use. The rules are intentionally self-contained with no external imports.

/**
 * Complete YARA ruleset as a single string, ready to be written to a file
 * inside the sandbox container for scanning with the `yara` binary.
 */
export const YARA_RULES_CONTENT = `
// ═══════════════════════════════════════════════════════════════════════════════
// FraudVault YARA Rules — 50 High-Signal Detection Rules
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Packers & Protectors ──────────────────────────────────────────────────────

rule UPX_Packer {
    meta:
        description = "UPX packer signatures detected"
        severity = "medium"
        category = "packer"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule ASPack_Packer {
    meta:
        description = "ASPack packer detected"
        severity = "medium"
        category = "packer"
    strings:
        $s1 = ".aspack"
        $s2 = "ASPack"
        $s3 = ".adata"
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Themida_VMProtect {
    meta:
        description = "Themida/WinLicense or VMProtect protector detected"
        severity = "high"
        category = "packer"
    strings:
        $t1 = ".themida"
        $t2 = "Themida"
        $t3 = "WinLicense"
        $v1 = ".vmp0"
        $v2 = ".vmp1"
        $v3 = "VMProtect"
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PECompact_Packer {
    meta:
        description = "PECompact packer detected"
        severity = "medium"
        category = "packer"
    strings:
        $s1 = "PEC2"
        $s2 = "PECompact2"
        $s3 = "pec1"
        $s4 = "pec2"
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule MPRESS_Packer {
    meta:
        description = "MPRESS packer detected"
        severity = "medium"
        category = "packer"
    strings:
        $s1 = ".MPRESS1"
        $s2 = ".MPRESS2"
        $s3 = "MPRESS"
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Enigma_Protector {
    meta:
        description = "Enigma Protector detected"
        severity = "high"
        category = "packer"
    strings:
        $s1 = ".enigma1"
        $s2 = ".enigma2"
        $s3 = "Enigma protector"
    condition:
        uint16(0) == 0x5A4D and any of them
}

// ─── Ransomware ────────────────────────────────────────────────────────────────

rule Ransomware_Indicators {
    meta:
        description = "Generic ransomware behavior indicators"
        severity = "critical"
        category = "ransomware"
    strings:
        $s1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $s2 = "bitcoin" nocase
        $s3 = "wallet" nocase
        $s4 = "ransom" nocase
        $s5 = "decrypt" nocase
        $s6 = "payment" nocase
        $s7 = "restore your files" nocase
    condition:
        3 of them
}

rule Ransomware_Recovery_Inhibitor {
    meta:
        description = "Shadow copy and recovery deletion commands"
        severity = "critical"
        category = "ransomware"
    strings:
        $s1 = "vssadmin delete shadows" nocase
        $s2 = "vssadmin.exe delete shadows" nocase
        $s3 = "bcdedit /set {default} recoveryenabled no" nocase
        $s4 = "wbadmin delete catalog" nocase
        $s5 = "wmic shadowcopy delete" nocase
        $s6 = "delete shadows /all /quiet" nocase
    condition:
        2 of them
}

rule WannaCry {
    meta:
        description = "WannaCry ransomware indicators"
        severity = "critical"
        category = "ransomware"
    strings:
        $s1 = "WanaCrypt0r"
        $s2 = "WANACRY"
        $s3 = "wncry"
        $s4 = "tasksche.exe"
        $s5 = "@WanaDecryptor"
        $s6 = "msg/m_bulgarian.wnry"
    condition:
        any of them
}

rule LockBit_Ransomware {
    meta:
        description = "LockBit ransomware indicators"
        severity = "critical"
        category = "ransomware"
    strings:
        $s1 = "LockBit" nocase
        $s2 = ".lockbit"
        $s3 = "Restore-My-Files.txt"
        $s4 = "lockbit-decryptor"
    condition:
        2 of them
}

rule Conti_Ransomware {
    meta:
        description = "Conti ransomware indicators"
        severity = "critical"
        category = "ransomware"
    strings:
        $s1 = "CONTI" fullword
        $s2 = "readme.txt"
        $s3 = "All of your files are currently encrypted"
        $s4 = ".CONTI"
    condition:
        2 of them
}

// ─── C2 Frameworks ─────────────────────────────────────────────────────────────

rule Cobalt_Strike_Beacon {
    meta:
        description = "Cobalt Strike beacon indicators"
        severity = "critical"
        category = "c2"
    strings:
        $s1 = "ReflectiveLoader"
        $s2 = "beacon.dll"
        $s3 = "beacon.x64.dll"
        $s4 = "%s.4%s.%s"
        $s5 = { 00 01 00 01 00 02 }
        $s6 = "libwinhttp.dll"
    condition:
        any of them
}

rule Cobalt_Strike_Stager {
    meta:
        description = "Cobalt Strike stager/shellcode"
        severity = "critical"
        category = "c2"
    strings:
        $s1 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        $s2 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
        $s3 = "cobaltstrike"
    condition:
        any of them
}

rule Meterpreter {
    meta:
        description = "Metasploit Meterpreter payload"
        severity = "critical"
        category = "c2"
    strings:
        $s1 = "metsrv"
        $s2 = "meterpreter"
        $s3 = "stdapi_"
        $s4 = "priv_elevate"
        $s5 = "ext_server_"
    condition:
        any of them
}

rule Sliver_C2 {
    meta:
        description = "Sliver C2 framework implant indicators"
        severity = "critical"
        category = "c2"
    strings:
        $s1 = "sliverpb"
        $s2 = "sliver-client"
        $s3 = "bishopfox"
        $s4 = "consts.SliverName"
    condition:
        any of them
}

rule Brute_Ratel_C4 {
    meta:
        description = "Brute Ratel C4 framework indicators"
        severity = "critical"
        category = "c2"
    strings:
        $s1 = "bruteratel"
        $s2 = "BRc4"
        $s3 = "badger_"
        $s4 = "brc4.exe"
    condition:
        any of them
}

// ─── RATs ──────────────────────────────────────────────────────────────────────

rule Remcos_RAT {
    meta:
        description = "Remcos RAT indicators"
        severity = "critical"
        category = "malware"
    strings:
        $s1 = "Remcos"
        $s2 = "remcos.exe"
        $s3 = "Breaking-Security.Net"
        $s4 = "licence_code"
        $s5 = "SETTINGS"
    condition:
        2 of them
}

rule AsyncRAT {
    meta:
        description = "AsyncRAT indicators"
        severity = "critical"
        category = "malware"
    strings:
        $s1 = "AsyncClient"
        $s2 = "AsyncRAT"
        $s3 = "Stub.exe"
        $s4 = "pastebin.com/raw"
        $s5 = "ABORTING"
    condition:
        2 of them
}

rule NjRAT {
    meta:
        description = "njRAT indicators"
        severity = "critical"
        category = "malware"
    strings:
        $s1 = "njRAT"
        $s2 = "njq8"
        $s3 = "im523"
        $s4 = "cmd.exe /c ping 0 -n 2 & del"
        $s5 = "netsh firewall add allowedprogram"
    condition:
        2 of them
}

rule DarkComet_RAT {
    meta:
        description = "DarkComet RAT indicators"
        severity = "critical"
        category = "malware"
    strings:
        $s1 = "DarkComet"
        $s2 = "DC_MUTEX"
        $s3 = "RCDATA"
        $s4 = "#BOT#"
        $s5 = "EditSvr"
    condition:
        2 of them
}

rule QuasarRAT {
    meta:
        description = "Quasar RAT indicators"
        severity = "critical"
        category = "malware"
    strings:
        $s1 = "QuasarRAT"
        $s2 = "Quasar.Client"
        $s3 = "SubDirectory"
        $s4 = "InstallClient"
        $s5 = "GetDrivesHandler"
    condition:
        2 of them
}

// ─── Stealers & Banking Trojans ────────────────────────────────────────────────

rule Agent_Tesla {
    meta:
        description = "Agent Tesla stealer indicators"
        severity = "critical"
        category = "malware"
    strings:
        $s1 = "smtp.gmail.com"
        $s2 = "smtp.yandex.com"
        $s3 = "passwords.txt"
        $s4 = "\\\\Chromium\\\\"
        $s5 = "\\\\Opera Software\\\\"
        $s6 = "SmtpClient"
    condition:
        2 of ($s1, $s2, $s6) or 3 of them
}

rule Emotet {
    meta:
        description = "Emotet malware family indicators"
        severity = "critical"
        category = "malware"
    strings:
        $s1 = "\\\\Outlook\\\\"
        $s2 = "\\\\Thunderbird\\\\"
        $s3 = "GetExtendedTcpTable"
        $s4 = "regsvr32"
        $s5 = "rundll32.exe"
    condition:
        3 of them
}

rule Qakbot {
    meta:
        description = "QakBot banking trojan indicators"
        severity = "critical"
        category = "malware"
    strings:
        $s1 = "C:\\\\INTERNAL\\\\__empty"
        $s2 = "/t5"
        $s3 = "stager_1.dll"
        $s4 = "%s\\\\system32\\\\"
        $s5 = "c:\\\\Temp\\\\"
    condition:
        2 of them
}

rule RedLine_Stealer {
    meta:
        description = "RedLine stealer indicators"
        severity = "critical"
        category = "malware"
    strings:
        $s1 = "RedLine"
        $s2 = "Yandex\\\\YandexBrowser"
        $s3 = "Login Data"
        $s4 = "AutoFill"
        $s5 = "CryptoWallets"
    condition:
        3 of them
}

rule Raccoon_Stealer {
    meta:
        description = "Raccoon stealer indicators"
        severity = "critical"
        category = "malware"
    strings:
        $s1 = "sstmnfo"
        $s2 = "machineId"
        $s3 = "configId"
        $s4 = "libs_"
        $s5 = "\\\\Raccoon\\\\"
    condition:
        2 of them
}

// ─── Techniques: Process Injection ─────────────────────────────────────────────

rule Process_Injection_Classic {
    meta:
        description = "Classic process injection API pattern"
        severity = "high"
        category = "technique"
    strings:
        $s1 = "VirtualAllocEx"
        $s2 = "WriteProcessMemory"
        $s3 = "CreateRemoteThread"
        $s4 = "OpenProcess"
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Process_Hollowing {
    meta:
        description = "Process hollowing technique indicators"
        severity = "critical"
        category = "technique"
    strings:
        $s1 = "NtUnmapViewOfSection"
        $s2 = "ZwUnmapViewOfSection"
        $s3 = "NtResumeThread"
        $s4 = "CREATE_SUSPENDED"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule APC_Injection {
    meta:
        description = "APC-based code injection"
        severity = "high"
        category = "technique"
    strings:
        $s1 = "QueueUserAPC"
        $s2 = "NtQueueApcThread"
        $s3 = "SuspendThread"
        $s4 = "ResumeThread"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

// ─── Techniques: Anti-Analysis ─────────────────────────────────────────────────

rule Anti_Debug {
    meta:
        description = "Anti-debugging API calls detected"
        severity = "high"
        category = "anti-analysis"
    strings:
        $s1 = "IsDebuggerPresent"
        $s2 = "CheckRemoteDebuggerPresent"
        $s3 = "NtQueryInformationProcess"
        $s4 = "OutputDebugString"
        $s5 = "NtSetInformationThread"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Anti_VM {
    meta:
        description = "Virtual machine detection techniques"
        severity = "high"
        category = "anti-analysis"
    strings:
        $s1 = "VMware"
        $s2 = "VBoxGuest"
        $s3 = "VBOX HARDDISK"
        $s4 = "Virtual HD"
        $s5 = "QEMU"
        $s6 = "SbieDll.dll"
        $s7 = "sbiedll.dll"
    condition:
        2 of them
}

rule Anti_Sandbox {
    meta:
        description = "Sandbox evasion techniques"
        severity = "high"
        category = "anti-analysis"
    strings:
        $s1 = "wireshark.exe" nocase
        $s2 = "procmon.exe" nocase
        $s3 = "ollydbg.exe" nocase
        $s4 = "x64dbg.exe" nocase
        $s5 = "ida.exe" nocase
        $s6 = "fiddler.exe" nocase
        $s7 = "ProcessHacker.exe" nocase
    condition:
        2 of them
}

// ─── Techniques: Persistence ───────────────────────────────────────────────────

rule Registry_Persistence {
    meta:
        description = "Registry-based persistence mechanisms"
        severity = "high"
        category = "persistence"
    strings:
        $s1 = "CurrentVersion\\\\Run" nocase
        $s2 = "CurrentVersion\\\\RunOnce" nocase
        $s3 = "Winlogon\\\\Shell" nocase
        $s4 = "Image File Execution" nocase
        $s5 = "AppInit_DLLs" nocase
    condition:
        any of them
}

rule Scheduled_Task_Persistence {
    meta:
        description = "Scheduled task creation for persistence"
        severity = "high"
        category = "persistence"
    strings:
        $s1 = "schtasks" nocase
        $s2 = "/create" nocase
        $s3 = "Register-ScheduledTask" nocase
        $s4 = "ITaskScheduler"
    condition:
        2 of them
}

rule WMI_Persistence {
    meta:
        description = "WMI event subscription persistence"
        severity = "high"
        category = "persistence"
    strings:
        $s1 = "__EventFilter"
        $s2 = "__EventConsumer"
        $s3 = "__FilterToConsumerBinding"
        $s4 = "ActiveScriptEventConsumer"
    condition:
        2 of them
}

// ─── Techniques: Credential Access ─────────────────────────────────────────────

rule Mimikatz {
    meta:
        description = "Mimikatz or similar credential dumping tool"
        severity = "critical"
        category = "credential-access"
    strings:
        $s1 = "mimikatz"
        $s2 = "sekurlsa"
        $s3 = "logonpasswords"
        $s4 = "lsadump"
        $s5 = "kerberos::"
        $s6 = "gentilkiwi"
    condition:
        any of them
}

rule Browser_Credential_Theft {
    meta:
        description = "Browser credential theft indicators"
        severity = "high"
        category = "credential-access"
    strings:
        $s1 = "Login Data"
        $s2 = "\\\\Google\\\\Chrome\\\\"
        $s3 = "\\\\Mozilla\\\\Firefox\\\\"
        $s4 = "logins.json"
        $s5 = "signons.sqlite"
        $s6 = "cookies.sqlite"
    condition:
        2 of them
}

rule Keylogger {
    meta:
        description = "Keylogging capability indicators"
        severity = "high"
        category = "credential-access"
    strings:
        $s1 = "SetWindowsHookEx"
        $s2 = "GetAsyncKeyState"
        $s3 = "GetKeyState"
        $s4 = "GetKeyboardState"
        $s5 = "keylog"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

// ─── Techniques: Privilege Escalation ──────────────────────────────────────────

rule Privilege_Escalation {
    meta:
        description = "Privilege escalation indicators"
        severity = "high"
        category = "technique"
    strings:
        $s1 = "AdjustTokenPrivileges"
        $s2 = "SeDebugPrivilege"
        $s3 = "LookupPrivilegeValue"
        $s4 = "ImpersonateLoggedOnUser"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule UAC_Bypass {
    meta:
        description = "UAC bypass indicators"
        severity = "high"
        category = "technique"
    strings:
        $s1 = "eventvwr.exe"
        $s2 = "fodhelper.exe"
        $s3 = "computerdefaults.exe"
        $s4 = "sdclt.exe"
        $s5 = "slui.exe"
    condition:
        any of them
}

// ─── Techniques: Exfiltration & C2 Communication ───────────────────────────────

rule DNS_Tunneling {
    meta:
        description = "DNS tunneling indicators"
        severity = "high"
        category = "exfiltration"
    strings:
        $s1 = "DnsQuery_A"
        $s2 = "DnsQuery_W"
        $s3 = ".dnscat."
        $s4 = "dnscat2"
        $s5 = "iodine"
    condition:
        2 of them
}

rule Tor_Communication {
    meta:
        description = "Tor network communication indicators"
        severity = "high"
        category = "c2"
    strings:
        $s1 = ".onion"
        $s2 = "tor2web"
        $s3 = "torproject.org"
        $s4 = "127.0.0.1:9050"
        $s5 = "SOCKS5"
    condition:
        2 of them
}

// ─── Techniques: Crypto ────────────────────────────────────────────────────────

rule AES_SBox {
    meta:
        description = "AES S-box constants detected (encryption capability)"
        severity = "medium"
        category = "crypto"
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $inv_sbox = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
    condition:
        any of them
}

rule RSA_Key_Material {
    meta:
        description = "RSA key material detected"
        severity = "medium"
        category = "crypto"
    strings:
        $s1 = "-----BEGIN RSA"
        $s2 = "-----BEGIN PUBLIC KEY"
        $s3 = "-----BEGIN PRIVATE KEY"
        $s4 = "PUBLICKEYBLOB"
        $s5 = "RSA1"
    condition:
        any of them
}

// ─── Techniques: Shellcode & Exploits ──────────────────────────────────────────

rule Shellcode_x86 {
    meta:
        description = "x86 shellcode patterns"
        severity = "critical"
        category = "technique"
    strings:
        $seh = { FC E8 ?? 00 00 00 60 89 E5 31 }
        $egg = { EB FE }
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $seh or ($egg and $nop_sled)
}

rule Base64_Encoded_PE {
    meta:
        description = "Base64-encoded PE file detected"
        severity = "high"
        category = "technique"
    strings:
        $s1 = "TVqQAAMAAAA"
        $s2 = "TVpQAAIAAAA"
        $s3 = "TVoAAAAAAAA"
        $s4 = "TVpBRUAAAA"
    condition:
        any of them
}

rule Embedded_PowerShell {
    meta:
        description = "Embedded PowerShell execution"
        severity = "high"
        category = "technique"
    strings:
        $s1 = "powershell" nocase
        $s2 = "-ExecutionPolicy Bypass" nocase
        $s3 = "-WindowStyle Hidden" nocase
        $s4 = "-NonInteractive" nocase
        $s5 = "FromBase64String" nocase
        $s6 = "-EncodedCommand" nocase
        $s7 = "Invoke-Expression" nocase
    condition:
        2 of them
}

// ─── Techniques: Discovery ─────────────────────────────────────────────────────

rule System_Reconnaissance {
    meta:
        description = "System information gathering commands"
        severity = "medium"
        category = "discovery"
    strings:
        $s1 = "systeminfo"
        $s2 = "ipconfig /all"
        $s3 = "whoami"
        $s4 = "net user"
        $s5 = "net group"
        $s6 = "tasklist"
    condition:
        3 of them
}

rule Domain_Enumeration {
    meta:
        description = "Active Directory enumeration indicators"
        severity = "high"
        category = "discovery"
    strings:
        $s1 = "dsquery"
        $s2 = "net group \\"domain admins\\""
        $s3 = "nltest"
        $s4 = "ldap://"
        $s5 = "Get-ADUser"
        $s6 = "Get-ADComputer"
    condition:
        2 of them
}

// ─── Suspicious Characteristics ────────────────────────────────────────────────

rule Double_Extension_Trick {
    meta:
        description = "Double file extension social engineering"
        severity = "high"
        category = "suspicious"
    strings:
        $s1 = ".pdf.exe"
        $s2 = ".doc.exe"
        $s3 = ".jpg.exe"
        $s4 = ".txt.exe"
        $s5 = ".docx.scr"
        $s6 = ".pdf.scr"
        $s7 = ".xlsx.exe"
    condition:
        any of them
}

rule Suspicious_PE_Sections {
    meta:
        description = "Non-standard PE section names"
        severity = "medium"
        category = "suspicious"
    strings:
        $s1 = ".evil"
        $s2 = ".virus"
        $s3 = ".hack"
        $s4 = ".infect"
        $s5 = ".boom"
        $s6 = ".dead"
        $s7 = ".mal"
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule High_Entropy_Overlay {
    meta:
        description = "PE with high-entropy overlay (possible encrypted payload)"
        severity = "medium"
        category = "suspicious"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and filesize > 100KB and filesize < 50MB
}
`;

/**
 * Shell commands to install YARA and run a scan inside a running container.
 * Call this function to get the commands to execute via `docker exec`.
 *
 * @param rulesPath - The path inside the container where rules were written
 * @param samplePath - The path to the sample file to scan
 * @returns A bash command string that installs yara and runs the scan
 */
export function getYaraInstallAndScanCommand(rulesPath: string, samplePath: string): string {
  return [
    '(which yara >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq yara >/dev/null 2>&1))',
    `yara -w -s "${rulesPath}" "${samplePath}" 2>/dev/null || echo "SCANBOY_NO_MATCHES"`,
  ].join(' && ');
}

/**
 * Represents a single YARA match parsed from the `yara` binary output.
 */
export interface YaraBinaryMatch {
  ruleName: string;
  filePath: string;
  matchedStrings: string[];
}

/**
 * Parse the output of the `yara` binary.
 * Format: `rule_name [matched_strings] target_file`
 * With -s flag: also shows matched strings as `0x offset:$identifier: matched_data`
 */
export function parseYaraBinaryOutput(output: string): YaraBinaryMatch[] {
  if (!output || output.includes('SCANBOY_NO_MATCHES')) {
    return [];
  }

  const matches: YaraBinaryMatch[] = [];
  const lines = output.split('\n').filter(l => l.trim());

  let currentMatch: YaraBinaryMatch | null = null;

  for (const line of lines) {
    // Rule match line format: "RuleName filepath"
    const ruleMatch = /^([A-Za-z0-9_]+)\s+(.+)$/.exec(line);
    if (ruleMatch && !line.startsWith('0x')) {
      if (currentMatch) {
        matches.push(currentMatch);
      }
      currentMatch = {
        ruleName: ruleMatch[1]!,
        filePath: ruleMatch[2]!,
        matchedStrings: [],
      };
    }
    // String match line format: "0xOFFSET:$identifier: data"
    else if (line.startsWith('0x') && currentMatch) {
      const strMatch = /^0x[0-9a-fA-F]+:(\$[a-zA-Z0-9_]+):\s*(.*)$/.exec(line);
      if (strMatch) {
        currentMatch.matchedStrings.push(`${strMatch[1]}: ${strMatch[2]?.slice(0, 60) ?? ''}`);
      }
    }
  }

  if (currentMatch) {
    matches.push(currentMatch);
  }

  return matches;
}
