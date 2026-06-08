// ── YARA rule feed downloader ────────────────────────────────────────────────
// Downloads public YARA rule repositories from GitHub, parses .yar/.yara files,
// extracts rule names and metadata, stores in SQLite.

import pino from 'pino';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { YARA_SOURCES, YARA_TIMEOUT } from '../config.js';
import { replaceYaraRulesForSource, getYaraRuleFeedCount, purgeStaleYaraSources, stampMeta } from '../db.js';

const log = pino({ name: 'yara-downloader' });

interface ParsedRule {
  name: string;
  category: string | null;
  severity: string | null;
  ruleText: string;
}

function parseYaraFile(content: string, filePath: string): ParsedRule[] {
  const rules: ParsedRule[] = [];
  // Match rule declarations: rule RuleName { ... }
  // Use a simple state machine to handle nested braces
  const rulePattern = /^(private\s+)?rule\s+(\w+)\s*(?::\s*([^\n{]+))?\s*\{/gm;
  let match: RegExpExecArray | null;

  while ((match = rulePattern.exec(content)) !== null) {
    const ruleName = match[2]!;
    const tags = match[3]?.trim() ?? '';
    const startIdx = match.index;

    // Find the matching closing brace
    let depth = 0;
    let endIdx = content.indexOf('{', startIdx);
    if (endIdx === -1) continue;

    for (let i = endIdx; i < content.length; i++) {
      if (content[i] === '{') depth++;
      else if (content[i] === '}') {
        depth--;
        if (depth === 0) {
          endIdx = i + 1;
          break;
        }
      }
    }

    const ruleText = content.slice(startIdx, endIdx);
    if (ruleText.length < 20 || ruleText.length > 100_000) continue;

    // Skip rules with known problematic patterns that cause YARA compile errors
    if (ruleText.includes('include "') || ruleText.includes("include '")) continue;
    // Skip rules referencing modules we don't have (cuckoo is deprecated in newer YARA)
    if (ruleText.includes('cuckoo.') && !content.includes('import "cuckoo"')) continue;

    // Extract category from path or tags
    let category: string | null = null;
    const dirName = path.dirname(filePath).toLowerCase();
    if (dirName.includes('malware')) category = 'malware';
    else if (dirName.includes('exploit')) category = 'exploit';
    else if (dirName.includes('apt')) category = 'apt';
    else if (dirName.includes('packer') || dirName.includes('peid')) category = 'packer';
    else if (dirName.includes('webshell')) category = 'webshell';
    else if (dirName.includes('cve')) category = 'exploit';
    else if (dirName.includes('crypto') || dirName.includes('miner')) category = 'crypto';
    else if (dirName.includes('ransom')) category = 'ransomware';
    else if (tags) category = tags.split(/\s+/)[0] ?? null;

    // Extract severity from meta section
    let severity: string | null = null;
    const severityMatch = ruleText.match(/severity\s*=\s*["']?(critical|high|medium|low)["']?/i);
    if (severityMatch) severity = severityMatch[1]!.toLowerCase();
    else if (category === 'apt' || category === 'ransomware') severity = 'critical';
    else if (category === 'malware' || category === 'exploit') severity = 'high';
    else if (category === 'packer') severity = 'medium';

    rules.push({ name: ruleName, category, severity, ruleText });
  }

  return rules;
}

async function downloadAndExtract(source: { name: string; url: string; subdir: string }): Promise<ParsedRule[]> {
  log.info({ source: source.name, url: source.url }, 'Downloading YARA rules');

  const response = await fetch(source.url, {
    signal: AbortSignal.timeout(YARA_TIMEOUT),
    headers: { 'User-Agent': 'FraudVault-YARA-Fetcher/1.0' },
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} from ${source.url}`);
  }

  const arrayBuf = await response.arrayBuffer();
  const zipBuffer = Buffer.from(arrayBuf);
  log.info({ source: source.name, sizeMb: Math.round(zipBuffer.length / 1024 / 1024) }, 'ZIP downloaded');

  // Write to temp file and extract with 7z (available on host)
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `yara-${source.name}-`));
  const zipPath = path.join(tmpDir, 'rules.zip');
  fs.writeFileSync(zipPath, zipBuffer);

  const { execFileSync } = await import('node:child_process');
  try {
    execFileSync('unzip', ['-q', '-o', 'rules.zip'], { cwd: tmpDir, timeout: 60_000, maxBuffer: 50 * 1024 * 1024 });
  } catch {
    try {
      execFileSync('7z', ['x', '-y', 'rules.zip'], { cwd: tmpDir, timeout: 60_000, maxBuffer: 50 * 1024 * 1024 });
    } catch (e2) {
      throw new Error(`Failed to extract ZIP for ${source.name}: ${String(e2)}`);
    }
  }

  // Find all .yar and .yara files
  const allRules: ParsedRule[] = [];
  function walkDir(dir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch { return; }
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walkDir(fullPath);
      } else if (/\.yar[a]?$/i.test(entry.name)) {
        try {
          const content = fs.readFileSync(fullPath, 'utf-8');
          const parsed = parseYaraFile(content, fullPath);
          allRules.push(...parsed);
        } catch { /* skip unreadable files */ }
      }
    }
  }

  // Walk from the extracted directory (GitHub ZIPs have a root folder)
  const extracted = fs.readdirSync(tmpDir).filter(f => f !== 'rules.zip');
  for (const dir of extracted) {
    const startDir = source.subdir
      ? path.join(tmpDir, dir, source.subdir)
      : path.join(tmpDir, dir);
    walkDir(startDir);
  }

  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });

  log.info({ source: source.name, ruleCount: allRules.length }, 'Parsed YARA rules');
  return allRules;
}

export async function refreshYaraRules(): Promise<void> {
  stampMeta('yara_rules', 0, 'refreshing', 'Downloading YARA rule repositories');
  let totalRules = 0;

  for (const source of YARA_SOURCES) {
    try {
      const rules = await downloadAndExtract(source);
      const count = replaceYaraRulesForSource(source.name, rules);
      totalRules += count;
      log.info({ source: source.name, stored: count }, 'YARA rules stored for source');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log.error({ source: source.name, err: msg }, 'Failed to download YARA source');
    }
  }

  const activeNames = YARA_SOURCES.map(s => s.name);
  const purged = purgeStaleYaraSources(activeNames);
  if (purged > 0) log.info({ purged }, 'Purged rules from removed YARA sources');

  const finalCount = getYaraRuleFeedCount();
  stampMeta('yara_rules', finalCount, 'ready');
  log.info({ totalRules: finalCount }, 'YARA rules refresh complete');
}
