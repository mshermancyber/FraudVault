import type {
  ATTACKTechnique,
  DynamicAnalysisResult,
  StaticAnalysisResult,
  ProcessInfo,
  NetworkConnection,
  FileModification,
  RegistryModification,
} from '@scanboy/shared';
import { getTechniqueById } from './techniques.js';

/**
 * A single behaviour-to-ATT&CK mapping rule.
 *
 * The `detect` callback inspects analysis data and returns a confidence
 * score (0-100) if the behaviour is present, or 0 if not.
 */
interface MappingRule {
  techniqueId: string;
  detect: (ctx: MappingContext) => number;
}

/** Aggregated analysis data passed to each mapping rule. */
export interface MappingContext {
  staticAnalysis: StaticAnalysisResult | null;
  dynamicAnalysis: DynamicAnalysisResult | null;
}

// ── Helper predicates ─────────────────────────────────────────────────────

function cmdContains(processes: ProcessInfo[], ...patterns: string[]): boolean {
  return processes.some((p) => {
    const cmd = p.commandLine.toLowerCase();
    return patterns.some((pat) => cmd.includes(pat.toLowerCase()));
  });
}

function processNameMatches(processes: ProcessInfo[], ...names: string[]): boolean {
  return processes.some((p) => {
    const name = p.name.toLowerCase();
    return names.some((n) => name === n.toLowerCase() || name.endsWith(`\\${n.toLowerCase()}`));
  });
}

function registryKeyContains(mods: RegistryModification[], ...patterns: string[]): boolean {
  return mods.some((m) => {
    const key = m.key.toLowerCase();
    return patterns.some((pat) => key.includes(pat.toLowerCase()));
  });
}

function filePathContains(mods: FileModification[], ...patterns: string[]): boolean {
  return mods.some((m) => {
    const p = m.path.toLowerCase();
    return patterns.some((pat) => p.includes(pat.toLowerCase()));
  });
}

function hasNetworkTo(connections: NetworkConnection[], port: number): boolean {
  return connections.some((c) => c.destinationPort === port);
}

function hasProtocol(connections: NetworkConnection[], protocol: string): boolean {
  return connections.some((c) => c.protocol === protocol);
}

function importsContain(imports: string[], ...apis: string[]): boolean {
  const lower = imports.map((i) => i.toLowerCase());
  return apis.some((api) => lower.some((i) => i.includes(api.toLowerCase())));
}

// ── Mapping Rules (30+ technique mappings) ────────────────────────────────

const MAPPING_RULES: MappingRule[] = [
  // 1. T1055 - Process Injection
  {
    techniqueId: 'T1055',
    detect: (ctx) => {
      if (!ctx.dynamicAnalysis && !ctx.staticAnalysis) return 0;
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      const imports = ctx.staticAnalysis?.imports ?? [];

      if (importsContain(imports, 'WriteProcessMemory', 'NtWriteVirtualMemory', 'VirtualAllocEx', 'CreateRemoteThread')) return 85;
      if (importsContain(imports, 'NtMapViewOfSection', 'QueueUserAPC')) return 80;
      if (cmdContains(procs, 'inject', 'hollowing')) return 70;
      return 0;
    },
  },
  // 2. T1055.001 - DLL Injection
  {
    techniqueId: 'T1055.001',
    detect: (ctx) => {
      const imports = ctx.staticAnalysis?.imports ?? [];
      if (importsContain(imports, 'LoadLibraryA', 'LoadLibraryW') &&
          importsContain(imports, 'CreateRemoteThread', 'VirtualAllocEx')) return 85;
      return 0;
    },
  },
  // 3. T1055.012 - Process Hollowing
  {
    techniqueId: 'T1055.012',
    detect: (ctx) => {
      const imports = ctx.staticAnalysis?.imports ?? [];
      if (importsContain(imports, 'NtUnmapViewOfSection', 'ZwUnmapViewOfSection') &&
          importsContain(imports, 'WriteProcessMemory', 'SetThreadContext')) return 90;
      return 0;
    },
  },
  // 4. T1547.001 - Registry Run Keys / Startup Folder
  {
    techniqueId: 'T1547.001',
    detect: (ctx) => {
      const regMods = ctx.dynamicAnalysis?.registryModifications ?? [];
      const fileMods = ctx.dynamicAnalysis?.filesModified ?? [];

      const runKeyPatterns = [
        'software\\microsoft\\windows\\currentversion\\run',
        'software\\microsoft\\windows\\currentversion\\runonce',
        'software\\wow6432node\\microsoft\\windows\\currentversion\\run',
      ];
      if (registryKeyContains(regMods, ...runKeyPatterns)) return 90;
      if (filePathContains(fileMods, 'startup', 'start menu\\programs\\startup')) return 85;
      return 0;
    },
  },
  // 5. T1053.005 - Scheduled Task
  {
    techniqueId: 'T1053.005',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (processNameMatches(procs, 'schtasks.exe')) return 90;
      if (cmdContains(procs, 'schtasks', '/create')) return 90;
      if (cmdContains(procs, 'at.exe', '/interactive')) return 75;
      return 0;
    },
  },
  // 6. T1543.003 - Windows Service
  {
    techniqueId: 'T1543.003',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      const regMods = ctx.dynamicAnalysis?.registryModifications ?? [];

      if (cmdContains(procs, 'sc.exe', 'create')) return 90;
      if (cmdContains(procs, 'sc', 'config', 'start= auto')) return 80;
      if (registryKeyContains(regMods, 'system\\currentcontrolset\\services')) return 80;
      const imports = ctx.staticAnalysis?.imports ?? [];
      if (importsContain(imports, 'CreateServiceA', 'CreateServiceW', 'OpenServiceA')) return 75;
      return 0;
    },
  },
  // 7. T1059.001 - PowerShell Execution
  {
    techniqueId: 'T1059.001',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (processNameMatches(procs, 'powershell.exe', 'pwsh.exe')) return 90;
      if (cmdContains(procs, 'powershell', '-encodedcommand', '-enc', '-e ')) return 95;
      if (cmdContains(procs, 'powershell', 'invoke-expression', 'iex', 'downloadstring')) return 95;
      return 0;
    },
  },
  // 8. T1059.003 - Windows Command Shell
  {
    techniqueId: 'T1059.003',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (processNameMatches(procs, 'cmd.exe')) return 70;
      if (cmdContains(procs, 'cmd.exe', '/c')) return 75;
      return 0;
    },
  },
  // 9. T1059.005 - Visual Basic
  {
    techniqueId: 'T1059.005',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (processNameMatches(procs, 'cscript.exe', 'wscript.exe')) return 80;
      if (processNameMatches(procs, 'mshta.exe')) return 85;
      return 0;
    },
  },
  // 10. T1059.007 - JavaScript
  {
    techniqueId: 'T1059.007',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'wscript', '.js')) return 80;
      if (cmdContains(procs, 'cscript', '.js')) return 80;
      if (cmdContains(procs, 'node', '.js')) return 60;
      return 0;
    },
  },
  // 11. T1027 - Obfuscated Files or Information / Encoded Commands
  {
    techniqueId: 'T1027',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      const staticResult = ctx.staticAnalysis;

      if (cmdContains(procs, '-encodedcommand', '-enc', 'frombase64string')) return 90;
      if (cmdContains(procs, 'certutil', '-decode', '-urlcache')) return 85;
      if (staticResult?.isPacked) return 80;
      // Entropy: >7.7 discriminates; normal PEs with compressed resources sit at 7.0-7.7
      if (staticResult && staticResult.entropy > 7.7) return 70;
      return 0;
    },
  },
  // 12. T1027.002 - Software Packing
  {
    techniqueId: 'T1027.002',
    detect: (ctx) => {
      const staticResult = ctx.staticAnalysis;
      if (!staticResult) return 0;
      if (staticResult.isPacked) return 90;
      if (staticResult.packerName) return 95;
      // High entropy in code section
      const textSection = staticResult.sections.find((s) => s.name === '.text' || s.name === 'CODE');
      if (textSection && textSection.entropy > 7.7) return 75;
      return 0;
    },
  },
  // 13. T1574.002 - DLL Side-Loading
  {
    techniqueId: 'T1574.002',
    detect: (ctx) => {
      const fileMods = ctx.dynamicAnalysis?.filesModified ?? [];
      const imports = ctx.staticAnalysis?.imports ?? [];

      // DLL written next to a legitimate executable
      if (fileMods.some((f) => f.operation === 'create' && f.path.toLowerCase().endsWith('.dll'))) {
        if (importsContain(imports, 'LoadLibraryA', 'LoadLibraryW')) return 75;
        return 60;
      }
      return 0;
    },
  },
  // 14. T1574.001 - DLL Search Order Hijacking
  {
    techniqueId: 'T1574.001',
    detect: (ctx) => {
      const fileMods = ctx.dynamicAnalysis?.filesModified ?? [];
      // DLLs dropped in system directories or application directories
      if (fileMods.some((f) =>
        f.operation === 'create' &&
        f.path.toLowerCase().endsWith('.dll') &&
        (f.path.toLowerCase().includes('\\system32\\') || f.path.toLowerCase().includes('\\syswow64\\'))
      )) return 80;
      return 0;
    },
  },
  // 15. T1071 - Application Layer Protocol (Network connections)
  {
    techniqueId: 'T1071',
    detect: (ctx) => {
      const conns = ctx.dynamicAnalysis?.networkConnections ?? [];
      if (conns.length > 0) return 50;
      return 0;
    },
  },
  // 16. T1071.001 - Web Protocols
  {
    techniqueId: 'T1071.001',
    detect: (ctx) => {
      const conns = ctx.dynamicAnalysis?.networkConnections ?? [];
      if (hasProtocol(conns, 'http') || hasProtocol(conns, 'https')) return 60;
      if (hasNetworkTo(conns, 80) || hasNetworkTo(conns, 443) || hasNetworkTo(conns, 8080)) return 55;
      return 0;
    },
  },
  // 17. T1071.004 - DNS
  {
    techniqueId: 'T1071.004',
    detect: (ctx) => {
      const conns = ctx.dynamicAnalysis?.networkConnections ?? [];
      if (hasProtocol(conns, 'dns')) return 60;
      if (hasNetworkTo(conns, 53)) return 55;
      // Excessive DNS queries may indicate DNS tunneling
      const dnsConns = conns.filter((c) => c.protocol === 'dns' || c.destinationPort === 53);
      if (dnsConns.length > 50) return 80;
      return 0;
    },
  },
  // 18. T1074.001 - Local Data Staging (File creation in temp)
  {
    techniqueId: 'T1074.001',
    detect: (ctx) => {
      const fileMods = ctx.dynamicAnalysis?.filesModified ?? [];
      if (filePathContains(fileMods, '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\')) return 65;
      if (fileMods.filter((f) => f.operation === 'create' && f.path.toLowerCase().includes('\\temp\\')).length > 3) return 80;
      return 0;
    },
  },
  // 19. T1003 - Credential Dumping
  {
    techniqueId: 'T1003',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      const imports = ctx.staticAnalysis?.imports ?? [];

      if (processNameMatches(procs, 'mimikatz.exe', 'procdump.exe')) return 95;
      if (cmdContains(procs, 'sekurlsa', 'logonpasswords')) return 95;
      if (cmdContains(procs, 'procdump', 'lsass')) return 90;
      if (cmdContains(procs, 'comsvcs.dll', 'minidump')) return 90;
      if (importsContain(imports, 'LsaRetrievePrivateData', 'CredEnumerateA', 'CredEnumerateW')) return 80;
      if (cmdContains(procs, 'reg', 'save', 'sam')) return 85;
      return 0;
    },
  },
  // 20. T1003.001 - LSASS Memory
  {
    techniqueId: 'T1003.001',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'lsass', 'minidump')) return 95;
      if (cmdContains(procs, 'procdump', 'lsass')) return 95;
      if (cmdContains(procs, 'comsvcs.dll', 'minidump')) return 90;
      return 0;
    },
  },
  // 21. T1082 - System Information Discovery
  {
    techniqueId: 'T1082',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (processNameMatches(procs, 'systeminfo.exe')) return 80;
      if (cmdContains(procs, 'hostname', 'ver', 'systeminfo')) return 70;
      if (cmdContains(procs, 'wmic', 'os get')) return 75;
      return 0;
    },
  },
  // 22. T1083 - File and Directory Discovery
  {
    techniqueId: 'T1083',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'dir /s', 'dir /b', 'tree /f')) return 75;
      if (cmdContains(procs, 'get-childitem', 'ls -r', 'find /')) return 70;
      return 0;
    },
  },
  // 23. T1057 - Process Discovery
  {
    techniqueId: 'T1057',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (processNameMatches(procs, 'tasklist.exe')) return 80;
      if (cmdContains(procs, 'tasklist', 'get-process', 'wmic process')) return 80;
      if (cmdContains(procs, 'ps aux', 'ps -ef')) return 70;
      return 0;
    },
  },
  // 24. T1016 - System Network Configuration Discovery
  {
    techniqueId: 'T1016',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (processNameMatches(procs, 'ipconfig.exe', 'ifconfig')) return 80;
      if (cmdContains(procs, 'ipconfig', 'route print', 'arp -a', 'ifconfig')) return 80;
      if (cmdContains(procs, 'nslookup', 'netsh interface')) return 70;
      return 0;
    },
  },
  // 25. T1112 - Modify Registry
  {
    techniqueId: 'T1112',
    detect: (ctx) => {
      const regMods = ctx.dynamicAnalysis?.registryModifications ?? [];
      if (regMods.length > 0) return 60;
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'reg add', 'reg delete', 'reg import')) return 80;
      return 0;
    },
  },
  // 26. T1140 - Deobfuscate/Decode Files
  {
    techniqueId: 'T1140',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'certutil', '-decode')) return 90;
      if (cmdContains(procs, 'base64', '--decode', 'frombase64string')) return 85;
      if (cmdContains(procs, 'openssl', 'enc', '-d')) return 80;
      return 0;
    },
  },
  // 27. T1105 - Ingress Tool Transfer
  {
    techniqueId: 'T1105',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'wget', 'curl', 'invoke-webrequest', 'downloadfile', 'downloadstring', 'bitsadmin', 'certutil', '-urlcache')) return 85;
      if (processNameMatches(procs, 'bitsadmin.exe')) return 80;
      return 0;
    },
  },
  // 28. T1562.001 - Disable or Modify Tools
  {
    techniqueId: 'T1562.001',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      const regMods = ctx.dynamicAnalysis?.registryModifications ?? [];

      if (cmdContains(procs, 'set-mppreference', 'disablerealtimemonitoring')) return 95;
      if (cmdContains(procs, 'sc stop', 'windefend', 'mpssvc', 'wscsvc')) return 90;
      if (cmdContains(procs, 'taskkill', 'msmpeng', 'avp', 'norton', 'mcafee')) return 85;
      if (registryKeyContains(regMods, 'windows defender', 'disableantispyware')) return 90;
      return 0;
    },
  },
  // 29. T1562.004 - Disable or Modify System Firewall
  {
    techniqueId: 'T1562.004',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'netsh', 'advfirewall', 'set', 'state off')) return 95;
      if (cmdContains(procs, 'netsh', 'firewall', 'disable')) return 90;
      if (cmdContains(procs, 'ufw disable', 'iptables -F')) return 85;
      return 0;
    },
  },
  // 30. T1547.004 - Winlogon Helper DLL
  {
    techniqueId: 'T1547.004',
    detect: (ctx) => {
      const regMods = ctx.dynamicAnalysis?.registryModifications ?? [];
      if (registryKeyContains(regMods, 'microsoft\\windows nt\\currentversion\\winlogon', 'userinit', 'shell', 'notify')) return 90;
      return 0;
    },
  },
  // 31. T1036.005 - Match Legitimate Name or Location
  {
    techniqueId: 'T1036.005',
    detect: (ctx) => {
      const fileMods = ctx.dynamicAnalysis?.filesModified ?? [];
      // Look for executables with legitimate-sounding names in unusual locations
      const suspiciousNames = ['svchost.exe', 'csrss.exe', 'lsass.exe', 'services.exe', 'explorer.exe', 'winlogon.exe'];
      for (const f of fileMods) {
        const lower = f.path.toLowerCase();
        if (f.operation === 'create' && suspiciousNames.some((n) => lower.endsWith(n)) &&
            !lower.includes('\\system32\\') && !lower.includes('\\syswow64\\')) {
          return 90;
        }
      }
      return 0;
    },
  },
  // 32. T1486 - Data Encrypted for Impact (Ransomware)
  {
    techniqueId: 'T1486',
    detect: (ctx) => {
      const fileMods = ctx.dynamicAnalysis?.filesModified ?? [];
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];

      // Mass file modifications (rename with unusual extensions)
      const renameOps = fileMods.filter((f) => f.operation === 'rename');
      if (renameOps.length > 20) return 85;

      // Look for common ransomware patterns
      if (cmdContains(procs, 'vssadmin', 'delete shadows')) return 95;
      if (cmdContains(procs, 'wbadmin', 'delete catalog')) return 90;
      if (cmdContains(procs, 'bcdedit', 'recoveryenabled', 'no')) return 90;

      // Encrypted file extensions
      const encryptedExts = ['.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.ransom'];
      if (fileMods.some((f) => f.newPath && encryptedExts.some((ext) => f.newPath!.toLowerCase().endsWith(ext)))) return 90;
      return 0;
    },
  },
  // 33. T1490 - Inhibit System Recovery
  {
    techniqueId: 'T1490',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'vssadmin', 'delete', 'shadows')) return 95;
      if (cmdContains(procs, 'wmic', 'shadowcopy', 'delete')) return 95;
      if (cmdContains(procs, 'bcdedit', '/set', 'recoveryenabled', 'no')) return 90;
      if (cmdContains(procs, 'wbadmin', 'delete', 'catalog')) return 90;
      return 0;
    },
  },
  // 34. T1489 - Service Stop
  {
    techniqueId: 'T1489',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'net stop', 'sc stop')) return 75;
      // Multiple service stops is more suspicious
      const stopCmds = (ctx.dynamicAnalysis?.processesCreated ?? []).filter(
        (p) => p.commandLine.toLowerCase().includes('net stop') || p.commandLine.toLowerCase().includes('sc stop'),
      );
      if (stopCmds.length >= 3) return 85;
      return 0;
    },
  },
  // 35. T1555.003 - Credentials from Web Browsers
  {
    techniqueId: 'T1555.003',
    detect: (ctx) => {
      const fileMods = ctx.dynamicAnalysis?.filesModified ?? [];
      const browserPaths = ['\\appdata\\local\\google\\chrome\\user data', '\\appdata\\roaming\\mozilla\\firefox\\profiles', '\\appdata\\local\\microsoft\\edge\\user data'];
      if (fileMods.some((f) => browserPaths.some((bp) => f.path.toLowerCase().includes(bp)))) return 85;
      if (filePathContains(fileMods, 'login data', 'logins.json', 'cookies.sqlite', 'web data')) return 80;
      return 0;
    },
  },
  // 36. T1573 - Encrypted Channel
  {
    techniqueId: 'T1573',
    detect: (ctx) => {
      const conns = ctx.dynamicAnalysis?.networkConnections ?? [];
      if (hasProtocol(conns, 'tls') || hasProtocol(conns, 'https')) return 50;
      if (hasNetworkTo(conns, 443)) return 45;
      return 0;
    },
  },
  // 37. T1571 - Non-Standard Port
  {
    techniqueId: 'T1571',
    detect: (ctx) => {
      const conns = ctx.dynamicAnalysis?.networkConnections ?? [];
      const standardPorts = new Set([80, 443, 53, 25, 587, 993, 995, 110, 143, 21, 22, 23, 3389]);
      const nonStandard = conns.filter((c) => !standardPorts.has(c.destinationPort) && c.destinationPort > 1024);
      if (nonStandard.length > 3) return 75;
      if (nonStandard.length > 0) return 50;
      return 0;
    },
  },
  // 38. T1047 - WMI
  {
    techniqueId: 'T1047',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (processNameMatches(procs, 'wmic.exe')) return 80;
      if (cmdContains(procs, 'wmic', 'process call create')) return 90;
      if (cmdContains(procs, 'get-wmiobject', 'invoke-wmimethod')) return 85;
      return 0;
    },
  },
  // 39. T1070.004 - File Deletion
  {
    techniqueId: 'T1070.004',
    detect: (ctx) => {
      const fileMods = ctx.dynamicAnalysis?.filesModified ?? [];
      const deletions = fileMods.filter((f) => f.operation === 'delete');
      if (deletions.length > 5) return 70;
      // Deleting self is suspicious
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'del /f', 'remove-item', 'rm -f')) return 65;
      return 0;
    },
  },
  // 40. T1056.001 - Keylogging
  {
    techniqueId: 'T1056.001',
    detect: (ctx) => {
      const imports = ctx.staticAnalysis?.imports ?? [];
      if (importsContain(imports, 'SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'GetKeyState')) return 85;
      if (importsContain(imports, 'RegisterRawInputDevices', 'GetRawInputData')) return 80;
      return 0;
    },
  },
  // 41. T1113 - Screen Capture
  {
    techniqueId: 'T1113',
    detect: (ctx) => {
      const imports = ctx.staticAnalysis?.imports ?? [];
      if (importsContain(imports, 'BitBlt', 'GetDC', 'CreateCompatibleBitmap', 'GetDesktopWindow')) return 75;
      return 0;
    },
  },
  // 42. T1115 - Clipboard Data
  {
    techniqueId: 'T1115',
    detect: (ctx) => {
      const imports = ctx.staticAnalysis?.imports ?? [];
      if (importsContain(imports, 'OpenClipboard', 'GetClipboardData', 'EmptyClipboard')) return 75;
      return 0;
    },
  },
  // 43. T1136 - Create Account
  {
    techniqueId: 'T1136',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'net user', '/add')) return 90;
      if (cmdContains(procs, 'useradd', 'adduser')) return 85;
      return 0;
    },
  },
  // 44. T1546.003 - WMI Event Subscription
  {
    techniqueId: 'T1546.003',
    detect: (ctx) => {
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, '__eventfilter', '__eventconsumer', 'commandlineeventconsumer')) return 90;
      if (cmdContains(procs, 'register-wmievent', 'set-wmiinstance')) return 85;
      return 0;
    },
  },
  // 45. T1021.002 - SMB/Windows Admin Shares
  {
    techniqueId: 'T1021.002',
    detect: (ctx) => {
      const conns = ctx.dynamicAnalysis?.networkConnections ?? [];
      if (hasNetworkTo(conns, 445) || hasNetworkTo(conns, 139)) return 70;
      const procs = ctx.dynamicAnalysis?.processesCreated ?? [];
      if (cmdContains(procs, 'net use', '\\\\', 'admin$', 'c$', 'ipc$')) return 85;
      return 0;
    },
  },
];

/**
 * Map analysis results to MITRE ATT&CK techniques.
 *
 * Evaluates all mapping rules against the provided static and dynamic analysis
 * data and returns the set of detected techniques with confidence scores.
 */
export function mapToAttackTechniques(
  staticAnalysis: StaticAnalysisResult | null,
  dynamicAnalysis: DynamicAnalysisResult | null,
): ATTACKTechnique[] {
  const ctx: MappingContext = { staticAnalysis, dynamicAnalysis };
  const results: ATTACKTechnique[] = [];
  let idCounter = 0;

  for (const rule of MAPPING_RULES) {
    const confidence = rule.detect(ctx);
    if (confidence <= 0) continue;

    const technique = getTechniqueById(rule.techniqueId);
    if (!technique) continue;

    idCounter++;
    results.push({
      id: `attack-${idCounter}`,
      techniqueId: technique.id,
      name: technique.name,
      tactic: technique.tactic,
      description: technique.description,
      dataSource: technique.dataSources.join(', '),
      confidence: Math.min(100, Math.max(0, confidence)),
    });
  }

  // Sort by confidence descending
  results.sort((a, b) => b.confidence - a.confidence);

  return results;
}

/** Return the total number of mapping rules registered. */
export function getMappingRuleCount(): number {
  return MAPPING_RULES.length;
}
