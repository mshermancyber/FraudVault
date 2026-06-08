import type { StaticAnalysisResult, ExtractedString } from '@scanboy/shared';

/** Generated YARA rule recommendation. */
export interface YaraRuleRecommendation {
  ruleName: string;
  description: string;
  ruleContent: string;
  confidence: number;
  basedOn: 'strings' | 'imports' | 'byte_patterns' | 'combined';
}

/**
 * Escape a string for use in a YARA string definition.
 */
function escapeYaraString(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
}

/**
 * Sanitize a name for use as a YARA rule identifier.
 */
function sanitizeRuleName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^[0-9]/, '_$&');
}

/**
 * Categorize strings by their likely purpose.
 */
function categorizeStrings(strings: ExtractedString[]): {
  urls: ExtractedString[];
  ips: ExtractedString[];
  registry: ExtractedString[];
  paths: ExtractedString[];
  commands: ExtractedString[];
  suspicious: ExtractedString[];
  cryptographic: ExtractedString[];
} {
  const urls: ExtractedString[] = [];
  const ips: ExtractedString[] = [];
  const registry: ExtractedString[] = [];
  const paths: ExtractedString[] = [];
  const commands: ExtractedString[] = [];
  const suspicious: ExtractedString[] = [];
  const cryptographic: ExtractedString[] = [];

  for (const str of strings) {
    const val = str.value;
    if (/^https?:\/\//i.test(val)) {
      urls.push(str);
    } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) {
      ips.push(str);
    } else if (/^(HKEY_|HKLM|HKCU|SOFTWARE\\)/i.test(val)) {
      registry.push(str);
    } else if (/^[A-Z]:\\|^\\\\|^\/[a-z]/i.test(val)) {
      paths.push(str);
    } else if (/^(cmd|powershell|net\s|sc\s|reg\s|schtasks|wmic)/i.test(val)) {
      commands.push(str);
    } else if (/BEGIN (RSA|CERTIFICATE|PUBLIC|PRIVATE)|-----BEGIN/i.test(val)) {
      cryptographic.push(str);
    } else if (
      val.length >= 6 &&
      (/base64|decrypt|encrypt|xor|inject|hook|bypass|exploit|payload|shellcode|beacon|c2|callback/i.test(val))
    ) {
      suspicious.push(str);
    }
  }

  return { urls, ips, registry, paths, commands, suspicious, cryptographic };
}

/**
 * Generate a YARA rule based on unique strings found in the binary.
 */
function generateStringBasedRule(
  strings: ExtractedString[],
  submissionId: string,
  sha256: string,
): YaraRuleRecommendation | null {
  const categorized = categorizeStrings(strings);
  const allInteresting = [
    ...categorized.urls,
    ...categorized.ips,
    ...categorized.registry,
    ...categorized.commands,
    ...categorized.suspicious,
  ];

  if (allInteresting.length < 2) return null;

  const ruleName = sanitizeRuleName(`fraudvault_strings_${submissionId.slice(0, 8)}`);
  const selectedStrings = allInteresting.slice(0, 20); // Limit to 20 strings

  const stringDefs: string[] = [];
  const stringNames: string[] = [];

  for (let i = 0; i < selectedStrings.length; i++) {
    const str = selectedStrings[i]!;
    const name = `$s${i}`;
    stringNames.push(name);

    if (str.encoding === 'utf16') {
      stringDefs.push(`        ${name} = "${escapeYaraString(str.value)}" wide`);
    } else {
      stringDefs.push(`        ${name} = "${escapeYaraString(str.value)}"`);
    }
  }

  // Require at least half of the strings to match
  const threshold = Math.max(2, Math.floor(stringNames.length / 2));

  const ruleContent = [
    `rule ${ruleName}`,
    `{`,
    `    meta:`,
    `        description = "FraudVault auto-generated rule based on extracted strings"`,
    `        author = "FraudVault Detection Engine"`,
    `        date = "${new Date().toISOString().split('T')[0]}"`,
    `        submission_id = "${submissionId}"`,
    `        reference_hash = "${sha256}"`,
    ``,
    `    strings:`,
    ...stringDefs,
    ``,
    `    condition:`,
    `        uint16(0) == 0x5A4D and ${threshold} of them`,
    `}`,
  ].join('\n');

  return {
    ruleName,
    description: `String-based rule for submission ${submissionId} (${selectedStrings.length} unique strings, threshold ${threshold})`,
    ruleContent,
    confidence: Math.min(90, 40 + selectedStrings.length * 3),
    basedOn: 'strings',
  };
}

/**
 * Generate a YARA rule based on suspicious imports.
 */
function generateImportBasedRule(
  imports: string[],
  submissionId: string,
  sha256: string,
): YaraRuleRecommendation | null {
  // Flag suspicious import combinations
  const suspiciousImports: Record<string, string[]> = {
    process_injection: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtWriteVirtualMemory'],
    process_hollowing: ['NtUnmapViewOfSection', 'SetThreadContext', 'ResumeThread'],
    keylogging: ['SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState'],
    credential_access: ['CredEnumerateA', 'CredEnumerateW', 'LsaRetrievePrivateData'],
    anti_debug: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'],
    network: ['InternetOpenA', 'InternetOpenUrlA', 'HttpSendRequestA', 'URLDownloadToFileA'],
    crypto: ['CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash', 'CryptGenKey'],
    screen_capture: ['BitBlt', 'CreateCompatibleBitmap', 'GetDesktopWindow'],
  };

  const lowerImports = imports.map((i) => i.toLowerCase());
  const matchedCategories: Array<{ category: string; matched: string[] }> = [];

  for (const [category, apis] of Object.entries(suspiciousImports)) {
    const matched = apis.filter((api) => lowerImports.some((i) => i.includes(api.toLowerCase())));
    if (matched.length >= 2) {
      matchedCategories.push({ category, matched });
    }
  }

  if (matchedCategories.length === 0) return null;

  const ruleName = sanitizeRuleName(`fraudvault_imports_${submissionId.slice(0, 8)}`);
  const stringDefs: string[] = [];
  const stringNames: string[] = [];

  let idx = 0;
  for (const { matched } of matchedCategories) {
    for (const api of matched) {
      const name = `$api${idx}`;
      stringNames.push(name);
      stringDefs.push(`        ${name} = "${api}" ascii`);
      idx++;
    }
  }

  const threshold = Math.max(2, Math.floor(stringNames.length * 0.6));

  const ruleContent = [
    `rule ${ruleName}`,
    `{`,
    `    meta:`,
    `        description = "FraudVault auto-generated rule based on suspicious API imports"`,
    `        author = "FraudVault Detection Engine"`,
    `        date = "${new Date().toISOString().split('T')[0]}"`,
    `        submission_id = "${submissionId}"`,
    `        reference_hash = "${sha256}"`,
    `        categories = "${matchedCategories.map((c) => c.category).join(', ')}"`,
    ``,
    `    strings:`,
    ...stringDefs,
    ``,
    `    condition:`,
    `        uint16(0) == 0x5A4D and ${threshold} of them`,
    `}`,
  ].join('\n');

  return {
    ruleName,
    description: `Import-based rule for submission ${submissionId} (categories: ${matchedCategories.map((c) => c.category).join(', ')})`,
    ruleContent,
    confidence: Math.min(85, 50 + matchedCategories.length * 10),
    basedOn: 'imports',
  };
}

/**
 * Generate a YARA rule based on byte patterns (section entropy / packing).
 */
function generateBytePatternRule(
  staticAnalysis: StaticAnalysisResult,
  submissionId: string,
  sha256: string,
): YaraRuleRecommendation | null {
  const { sections, isPacked, packerName, entropy } = staticAnalysis;

  // Only generate for packed or near-random entropy files (>7.7 discriminates; >7.0 does not)
  if (!isPacked && entropy < 7.7) return null;

  const ruleName = sanitizeRuleName(`fraudvault_packed_${submissionId.slice(0, 8)}`);
  const conditions: string[] = ['uint16(0) == 0x5A4D'];

  if (isPacked) {
    conditions.push('// Packed binary detected');
  }

  // Add section-based conditions
  const highEntropySections = sections.filter((s) => s.entropy > 7.7);
  if (highEntropySections.length > 0) {
    conditions.push(`// ${highEntropySections.length} high-entropy section(s) detected`);
  }

  // Check for unusual section names
  const normalSectionNames = new Set(['.text', '.rdata', '.data', '.rsrc', '.reloc', '.bss', '.edata', '.idata', '.pdata', '.tls']);
  const unusualSections = sections.filter((s) => !normalSectionNames.has(s.name.toLowerCase()));

  const stringDefs: string[] = [];
  if (unusualSections.length > 0) {
    for (let i = 0; i < Math.min(unusualSections.length, 5); i++) {
      const sect = unusualSections[i]!;
      stringDefs.push(`        $section${i} = "${escapeYaraString(sect.name)}" ascii`);
    }
  }

  // Math module for entropy checks
  const conditionParts = [...conditions];
  // Entropy: >7.9 near-random (encrypted/packed), >7.7 elevated. Normal PEs sit 7.0-7.7.
  if (entropy > 7.9) {
    conditionParts.push('math.entropy(0, filesize) > 7.9');
  } else if (entropy > 7.7) {
    conditionParts.push('math.entropy(0, filesize) > 7.7');
  }

  if (stringDefs.length > 0) {
    conditionParts.push('any of ($section*)');
  }

  const ruleContent = [
    `import "math"`,
    ``,
    `rule ${ruleName}`,
    `{`,
    `    meta:`,
    `        description = "FraudVault auto-generated rule for packed/obfuscated binary"`,
    `        author = "FraudVault Detection Engine"`,
    `        date = "${new Date().toISOString().split('T')[0]}"`,
    `        submission_id = "${submissionId}"`,
    `        reference_hash = "${sha256}"`,
    ...(packerName ? [`        packer = "${escapeYaraString(packerName)}"`] : []),
    `        overall_entropy = "${entropy.toFixed(2)}"`,
    ``,
    ...(stringDefs.length > 0 ? [`    strings:`, ...stringDefs, ``] : []),
    `    condition:`,
    `        ${conditionParts.join(' and\n        ')}`,
    `}`,
  ].join('\n');

  return {
    ruleName,
    description: `Byte-pattern rule for packed/obfuscated submission ${submissionId}${packerName ? ` (packer: ${packerName})` : ''}`,
    ruleContent,
    confidence: isPacked ? 80 : 60,
    basedOn: 'byte_patterns',
  };
}

/**
 * Generate a combined YARA rule using the strongest signals from all sources.
 */
function generateCombinedRule(
  staticAnalysis: StaticAnalysisResult,
  submissionId: string,
  sha256: string,
): YaraRuleRecommendation | null {
  const categorized = categorizeStrings(staticAnalysis.strings);
  const interestingStrings = [
    ...categorized.urls.slice(0, 3),
    ...categorized.ips.slice(0, 3),
    ...categorized.commands.slice(0, 3),
    ...categorized.suspicious.slice(0, 3),
  ];

  // Need at least some data to combine
  if (interestingStrings.length < 2 && staticAnalysis.imports.length < 5) return null;

  const ruleName = sanitizeRuleName(`fraudvault_combined_${submissionId.slice(0, 8)}`);
  const stringDefs: string[] = [];
  const conditionParts: string[] = ['uint16(0) == 0x5A4D'];

  // Add interesting strings
  for (let i = 0; i < interestingStrings.length; i++) {
    const str = interestingStrings[i]!;
    const encoding = str.encoding === 'utf16' ? ' wide' : '';
    stringDefs.push(`        $str${i} = "${escapeYaraString(str.value)}"${encoding}`);
  }

  // Add key API imports
  const dangerousApis = ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
    'URLDownloadToFileA', 'InternetOpenA', 'ShellExecuteA', 'WinExec'];
  const matchedApis = dangerousApis.filter((api) =>
    staticAnalysis.imports.some((i) => i.toLowerCase().includes(api.toLowerCase())),
  );

  for (let i = 0; i < matchedApis.length; i++) {
    stringDefs.push(`        $api${i} = "${matchedApis[i]}" ascii`);
  }

  if (interestingStrings.length > 0) {
    const threshold = Math.max(1, Math.floor(interestingStrings.length / 2));
    conditionParts.push(`${threshold} of ($str*)`);
  }
  if (matchedApis.length > 0) {
    conditionParts.push(`${Math.max(1, Math.floor(matchedApis.length / 2))} of ($api*)`);
  }

  if (stringDefs.length < 3) return null;

  const ruleContent = [
    `rule ${ruleName}`,
    `{`,
    `    meta:`,
    `        description = "FraudVault auto-generated combined detection rule"`,
    `        author = "FraudVault Detection Engine"`,
    `        date = "${new Date().toISOString().split('T')[0]}"`,
    `        submission_id = "${submissionId}"`,
    `        reference_hash = "${sha256}"`,
    ``,
    `    strings:`,
    ...stringDefs,
    ``,
    `    condition:`,
    `        ${conditionParts.join(' and\n        ')}`,
    `}`,
  ].join('\n');

  return {
    ruleName,
    description: `Combined rule for submission ${submissionId} (${interestingStrings.length} strings, ${matchedApis.length} APIs)`,
    ruleContent,
    confidence: Math.min(85, 45 + interestingStrings.length * 3 + matchedApis.length * 5),
    basedOn: 'combined',
  };
}

/**
 * Generate YARA rule recommendations from static analysis results.
 */
export function generateYaraRecommendations(
  staticAnalysis: StaticAnalysisResult,
  submissionId: string,
  sha256: string,
): YaraRuleRecommendation[] {
  const recommendations: YaraRuleRecommendation[] = [];

  const stringRule = generateStringBasedRule(staticAnalysis.strings, submissionId, sha256);
  if (stringRule) recommendations.push(stringRule);

  const importRule = generateImportBasedRule(staticAnalysis.imports, submissionId, sha256);
  if (importRule) recommendations.push(importRule);

  const byteRule = generateBytePatternRule(staticAnalysis, submissionId, sha256);
  if (byteRule) recommendations.push(byteRule);

  const combinedRule = generateCombinedRule(staticAnalysis, submissionId, sha256);
  if (combinedRule) recommendations.push(combinedRule);

  // Sort by confidence descending
  recommendations.sort((a, b) => b.confidence - a.confidence);

  return recommendations;
}
