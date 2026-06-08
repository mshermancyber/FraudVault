import * as dns from 'node:dns/promises';
import type pg from 'pg';
import type { Logger } from 'pino';
import type Redis from 'ioredis';
import {
  JobType,
  JobStatus,
  type ThreatLevel,
  threatLevelFromScore,
} from '@scanboy/shared';
import { lookupVulnerabilities, lookupTechDebt, classifyApplicationFromCpe, storeCpeClassification, type PeVersionInfo, type VulnResult, type TechDebtResult } from '../vuln-lookup.js';
import { storeYaraResults, parseYaraScanOutput } from '../yara-scanner.js';
import { extractMalwareConfig, storeExtractedConfig, parseConfigExtractionOutput } from '../config-extractor.js';
import {
  type SiemConfig,
  type AlertPayload,
  forwardToSiem,
  sendWebhookAlert,
  shouldAlert,
  buildAlertPayload,
} from '../integrations/siem-forwarder.js';
import {
  type EdrConfig,
  pushHashToEdr,
  isValidSha256,
  shouldPushToEdr,
} from '../integrations/edr-push.js';
import {
  computeVerdict,
  buildVtEvidence,
  buildSandboxEvidence,
  buildYaraEvidence,
  buildStaticEvidence,
  buildCertificateEvidence,
  buildNetworkEvidence,
  type EvidenceItem,
  type Verdict,
} from '../verdict-engine.js';

// ── Public Context ───────────────────────────────────────────────────────────

export interface WorkflowContext {
  submissionId: string;
  sha256: string;
  storagePath: string;
  pool: pg.Pool;
  logger: Logger;
  /** Optional Redis client for pub/sub status updates. */
  redis?: Redis;
  /** When true, step 5 (dynamic analysis) is skipped. */
  skipDynamicAnalysis?: boolean;
  /** Analysis workflow: 'default' for malware detonation, 'container' for container image analysis. */
  analysisWorkflow?: 'default' | 'container';
}

// ── Internal Types ───────────────────────────────────────────────────────────

interface StepResult {
  jobType: JobType;
  status: JobStatus;
  result: Record<string, unknown>;
  score: number;
}

interface AnalysisJobRow {
  id: string;
}

// ── Redis Pub/Sub Channel ────────────────────────────────────────────────────

const STATUS_CHANNEL = 'scanboy:submission:status';

interface StatusEvent {
  submissionId: string;
  status: string;
  step: string;
  timestamp: string;
}

async function publishStatus(
  ctx: WorkflowContext,
  status: string,
  step: string,
): Promise<void> {
  if (!ctx.redis) return;
  const event: StatusEvent = {
    submissionId: ctx.submissionId,
    status,
    step,
    timestamp: new Date().toISOString(),
  };
  await ctx.redis.publish(STATUS_CHANNEL, JSON.stringify(event)).catch((err: unknown) => {
    ctx.logger.warn({ err }, 'Failed to publish status event');
  });
}

// ── Workflow Entry Point ─────────────────────────────────────────────────────

/**
 * Orchestrates the full analysis pipeline for a single submission.
 *
 * Pipeline order:
 *   1. Hash verification (already computed at upload, but verify integrity)
 *   2. Threat intelligence enrichment
 *   3. Static analysis
 *   4. YARA scan
 *   5. Dynamic analysis (sandbox detonation) -- skippable
 *   6. Detection engine correlation
 *   7. Scoring
 *   8. Report generation
 *
 * Each step creates an analysis_job record in the database and emits
 * status updates over Redis pub/sub.
 */
export async function runSubmissionWorkflow(ctx: WorkflowContext): Promise<void> {
  const { submissionId, pool, logger } = ctx;

  // Validate submissionId format to prevent injection via crafted IDs
  if (!/^[a-f0-9\-]{36}$/i.test(submissionId)) {
    throw new Error(`Invalid submission ID format: ${submissionId.slice(0, 50)}`);
  }

  try {
    await updateSubmissionStatus(pool, submissionId, 'analyzing');
    await publishStatus(ctx, 'analyzing', 'start');

    // Container workflow: different pipeline
    if (ctx.analysisWorkflow === 'container') {
      logger.info({ submissionId }, 'Running CONTAINER analysis workflow');
      await publishStatus(ctx, 'container_analysis', 'start');

      // Step 1: Sandbox analysis (extract layers, SBOM, secrets, setuid)
      logger.info({ submissionId }, 'Step 1/3: Container sandbox analysis');
      await executeStep(ctx, JobType.DynamicAnalysis);

      // Step 2: SBOM vulnerability lookup against local OSV/NVD feeds
      logger.info({ submissionId }, 'Step 2/3: SBOM vulnerability scan');
      await publishStatus(ctx, 'sbom_vuln_scan', 'step-2');
      try {
        const dynRes = await pool.query('SELECT memory_activity FROM dynamic_analysis_results WHERE submission_id = $1', [submissionId]);
        const mem = (dynRes.rows[0] as Record<string, unknown> | undefined)?.['memory_activity'] as Record<string, unknown> | null;
        const sbom = mem?.['containerSbom'] as Record<string, unknown> | null;
        const packages = (sbom?.['packages'] ?? []) as Array<{ name: string; version: string; type: string }>;
        const secrets = (sbom?.['secrets'] ?? []) as Array<Record<string, unknown>>;
        const setuid = (sbom?.['setuid'] ?? []) as string[];
        const suspicious = (sbom?.['suspicious'] ?? []) as Array<Record<string, unknown>>;
        const supplyChain = (sbom?.['supplyChain'] ?? []) as Array<Record<string, unknown>>;
        const forgedKeys = (sbom?.['forgedKeys'] ?? []) as Array<Record<string, unknown>>;
        const unofficialSources = (sbom?.['unofficialSources'] ?? []) as Array<Record<string, unknown>>;
        const unsignedPkgs = Boolean(sbom?.['unsignedPackages']);
        const symlinkEscapes = (sbom?.['symlinkEscapes'] ?? []) as Array<Record<string, unknown>>;
        const trojanLayers = (sbom?.['trojanLayers'] ?? []) as Array<Record<string, unknown>>;

        logger.info({ submissionId, packageCount: packages.length, secretCount: secrets.length, setuidCount: setuid.length, forgedKeys: forgedKeys.length, unofficialSources: unofficialSources.length, supplyChain: supplyChain.length, unsignedPkgs, symlinkEscapes: symlinkEscapes.length, trojanLayers: trojanLayers.length }, 'Container SBOM data');

        // Look up each package against OSV feeds
        let vulnCount = 0;
        let criticalVulns = 0;
        let highVulns = 0;
        let mediumVulnCount = 0;
        let lowVulnCount = 0;
        let hasKev = false;
        let maxCvss = 0;
        let maxEpss = 0;
        const allCveScores: number[] = [];
        for (const pkg of packages.slice(0, 200)) {
          try {
            const lookupRes = await fetch('http://vuln-feeds:9000/feeds/cpe-lookup', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', ...(process.env['INTERNAL_API_KEY'] ? { 'x-internal-api-key': process.env['INTERNAL_API_KEY'] } : {}) },
              body: JSON.stringify({ vendor: pkg.name, product: pkg.name, version: pkg.version }),
              signal: AbortSignal.timeout(5_000),
            });
            if (lookupRes.ok) {
              const data = await lookupRes.json() as { results?: Array<{ cve: string; score: number; severity: string; kev: boolean; epss?: number }> };
              if (data.results && data.results.length > 0) {
                vulnCount += data.results.length;
                for (const v of data.results) {
                  if (v.severity === 'CRITICAL') criticalVulns++;
                  else if (v.severity === 'HIGH') highVulns++;
                  else if (v.severity === 'MEDIUM') mediumVulnCount++;
                  else lowVulnCount++;
                  if (v.kev) hasKev = true;
                  if (v.score > maxCvss) maxCvss = v.score;
                  if (v.epss && v.epss > maxEpss) maxEpss = v.epss;
                  allCveScores.push(v.score);
                  // Store as threat intel
                  await pool.query(
                    `INSERT INTO threat_intel_results (submission_id, provider, verdict, detection_count, total_engines, malware_family, raw_response)
                     VALUES ($1, 'sbom-vuln', $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
                    [submissionId, v.kev ? 'vulnerable-kev' : 'vulnerable', 1, 1, `${pkg.name}@${pkg.version}`,
                     JSON.stringify({ package: pkg.name, version: pkg.version, cve: v.cve, score: v.score, severity: v.severity, kev: v.kev })],
                  );
                }
              }
            }
          } catch { /* continue */ }
        }

        logger.info({ submissionId, vulnCount, criticalVulns, highVulns }, 'SBOM vulnerability scan complete');

        // Clean up false-positive IOCs from container analysis
        // Container images contain legitimate URLs (openssl.org, github.com, etc.) that aren't IOCs
        // Known-good container infrastructure domains (not IOCs)
        const knownGoodDomains = [
          'github.com', 'gitlab.com', 'alpinelinux.org', 'debian.org', 'ubuntu.com',
          'openssl.org', 'musl.libc.org', 'docker.com', 'docker.io', 'hub.docker.com',
          'mobyproject.org', 'npmjs.org', 'npmjs.com', 'pypi.org', 'rubygems.org',
          'golang.org', 'go.dev', 'rust-lang.org', 'crates.io',
          'apache.org', 'nginx.org', 'postgresql.org', 'mysql.com', 'redis.io',
          'kernel.org', 'gnu.org', 'freedesktop.org', 'sourceforge.net',
        ];
        const domainPatterns = knownGoodDomains.map(d => `%${d}%`);
        await pool.query(
          `UPDATE iocs SET confidence = 5, context = 'Container infrastructure (not IOC)'
           WHERE submission_id = $1 AND type IN ('url', 'domain') AND confidence > 10
             AND (${domainPatterns.map((_d, i) => `value ILIKE $${i + 2}`).join(' OR ')})`,
          [submissionId, ...domainPatterns],
        );

        // Step 3: Expert-designed container scoring model
        logger.info({ submissionId }, 'Step 3/3: Container scoring');

        const miners = suspicious.filter(s => String(s['type']) === 'crypto_miner').length;
        const backdoors = suspicious.filter(s => String(s['type']) === 'backdoor' || String(s['type']) === 'reverse_shell').length;
        const beacons = suspicious.filter(s => String(s['type']) === 'beacon').length;
        const normalSetuidPaths = ['/usr/bin/su', '/usr/bin/passwd', '/usr/bin/chfn', '/usr/bin/chsh', '/usr/bin/newgrp', '/bin/mount', '/bin/umount'];
        const abnormalSetuid = setuid.filter(s => !normalSetuidPaths.some(n => s.endsWith(n)));
        const cisFails = ((sbom?.['cisBenchmark'] ?? []) as Array<Record<string, unknown>>).filter(c => c['status'] === 'FAIL').length;
        const cisWarns = ((sbom?.['cisBenchmark'] ?? []) as Array<Record<string, unknown>>).filter(c => c['status'] === 'WARN').length;
        const compilers = ((sbom?.['multiStageLeak'] ?? []) as unknown[]).length;
        const gitDirs = ((sbom?.['multiStageLeak'] ?? []) as Array<Record<string, unknown>>).filter(m => String(m['tool']) === '.git').length;
        const sensitiveFiles = ((sbom?.['sensitiveFiles'] ?? []) as unknown[]).length;
        const certsWithKeys = ((sbom?.['certificates'] ?? []) as Array<Record<string, unknown>>).filter(c => c['hasPrivateKey']).length;
        const capBinaries = ((sbom?.['capBinaries'] ?? []) as unknown[]).length;
        const runsAsRoot = Boolean((sbom?.['userAnalysis'] as Record<string, unknown>)?.['runsAsRoot']);
        // ── Vulnerability sub-score (0-45) ──
        // Quadratic CVSS scaling with gentle decay. A single HIGH vuln (CVSS 7+)
        // should reach ~30-35 pts so the container lands at MEDIUM minimum.
        // A single CRITICAL (CVSS 9+) should saturate or near-saturate at 40-45.
        const BASE_SCALE = 45;
        const perCvePoints = (cvss: number) => Math.pow(cvss / 10.0, 2) * BASE_SCALE;
        // perCvePoints: CVSS 10→45, 9.5→40.6, 8.8→34.8, 8.0→28.8, 5.5→13.6, 2.5→2.8
        let vulnSubScore = 0;
        const cveList: Array<{ cvss: number; isKev: boolean }> = [];
        for (let i = 0; i < criticalVulns; i++) cveList.push({ cvss: Math.max(9.5, maxCvss), isKev: false });
        for (let i = 0; i < highVulns; i++) cveList.push({ cvss: 8.0, isKev: false });
        for (let i = 0; i < mediumVulnCount; i++) cveList.push({ cvss: 5.5, isKev: false });
        for (let i = 0; i < lowVulnCount; i++) cveList.push({ cvss: 2.5, isKev: false });
        if (cveList.length > 0 && maxCvss > 0) cveList[0]!.cvss = Math.max(cveList[0]!.cvss, maxCvss);
        let kevRem = hasKev ? Math.max(1, Math.min(cveList.length, 1)) : 0;
        for (let i = 0; i < kevRem && i < cveList.length; i++) cveList[i]!.isKev = true;
        cveList.sort((a, b) => perCvePoints(b.cvss) * (b.isKev ? 2.5 : 1) - perCvePoints(a.cvss) * (a.isKev ? 2.5 : 1));
        for (let i = 0; i < cveList.length; i++) {
          let pts = perCvePoints(cveList[i]!.cvss);
          if (cveList[i]!.isKev) pts *= 2.5;
          else if (maxEpss >= 0.95) pts *= 2.0;
          else if (maxEpss >= 0.75) pts *= 1.5;
          pts /= (1.0 + 0.08 * i);  // gentle decay: i0=full, i1=/1.08, i2=/1.16
          vulnSubScore += pts;
        }
        vulnSubScore = Math.min(45, vulnSubScore);

        // ── Configuration sub-score (0-20) ──
        let configSubScore = 0;
        if (runsAsRoot) configSubScore += 8;
        configSubScore += Math.min(cisFails * 4, 12);
        configSubScore += Math.min(cisWarns * 2, 6);
        configSubScore = Math.min(20, configSubScore);

        // ── Supply chain sub-score (0-20) ──
        let supplySubScore = 0;
        supplySubScore += Math.min(forgedKeys.length * 12, 15);
        supplySubScore += Math.min(unofficialSources.length * 6, 10);
        if (unsignedPkgs) supplySubScore += 5;
        supplySubScore = Math.min(20, supplySubScore);

        // ── Malicious indicators sub-score (0-30) ──
        let maliciousSubScore = 0;
        if (miners > 0) maliciousSubScore += 25;
        if (backdoors > 0) maliciousSubScore += 30;
        if (beacons > 0) maliciousSubScore += 20;
        maliciousSubScore = Math.min(30, maliciousSubScore);

        // ── Hygiene sub-score (0-15) ──
        let hygieneSubScore = 0;
        hygieneSubScore += Math.min(sensitiveFiles * 3, 8);
        hygieneSubScore += Math.min(compilers * 2, 4);
        if (gitDirs > 0) hygieneSubScore += 2;
        hygieneSubScore += Math.min(capBinaries, 4);
        hygieneSubScore += Math.min(certsWithKeys * 3, 6);
        hygieneSubScore = Math.min(15, hygieneSubScore);

        // ── Structural integrity sub-score (0-30) ──
        let structuralSubScore = 0;
        if (symlinkEscapes.length > 0) structuralSubScore += Math.min(20 + (symlinkEscapes.length - 1) * 5, 25);
        structuralSubScore += Math.min(trojanLayers.length * 12, 25);
        structuralSubScore += Math.min(abnormalSetuid.length * 4, 8);
        structuralSubScore = Math.min(30, structuralSubScore);

        // ── Secrets sub-score (0-25) ──
        const secretsSubScore = Math.min(secrets.length * 8, 25);

        // ── Combine with synergy bonus ──
        const rawTotal = vulnSubScore + configSubScore + supplySubScore + maliciousSubScore + hygieneSubScore + structuralSubScore + secretsSubScore;
        const activeCategories = [vulnSubScore, configSubScore, supplySubScore, maliciousSubScore, hygieneSubScore, structuralSubScore, secretsSubScore].filter(s => s > 0).length;
        const synergyBonus = activeCategories >= 4 ? Math.min((activeCategories - 3) * 3, 10) : 0;
        let containerScore = Math.min(100, Math.round(rawTotal + synergyBonus));

        // ── Floors ──
        // Severity-based: a container with a CRITICAL vuln is at minimum HIGH,
        // a container with a HIGH vuln is at minimum MEDIUM.
        if (criticalVulns > 0) containerScore = Math.max(containerScore, 70);
        if (highVulns > 0) containerScore = Math.max(containerScore, 40);
        if (hasKev) containerScore = Math.max(containerScore, 70);
        if (backdoors > 0) containerScore = Math.max(containerScore, 90);
        if (miners > 0) containerScore = Math.max(containerScore, 90);
        if (trojanLayers.length > 0) containerScore = Math.max(containerScore, 85);
        if (symlinkEscapes.length > 0) containerScore = Math.max(containerScore, 80);
        if (forgedKeys.length > 0) containerScore = Math.max(containerScore, 70);

        containerScore = Math.min(100, containerScore);
        const containerLevel = containerScore >= 90 ? 'critical' : containerScore >= 70 ? 'high' : containerScore >= 40 ? 'medium' : containerScore >= 10 ? 'low' : 'informational';

        await pool.query(
          `UPDATE submissions SET status = 'review', threat_score = $1, threat_level = $2::threat_level, updated_at = NOW() WHERE id = $3`,
          [containerScore, containerLevel, submissionId],
        );

        logger.info({ submissionId, containerScore, containerLevel, vulnSubScore: Math.round(vulnSubScore), configSubScore, supplySubScore, maliciousSubScore, hygieneSubScore, structuralSubScore, secretsSubScore, synergyBonus, vulnCount, hasKev, runsAsRoot }, 'Container scoring complete');
      } catch (err) {
        logger.error({ err }, 'Container SBOM scan failed');
        await pool.query(`UPDATE submissions SET status = 'review', threat_score = 0, threat_level = 'informational'::threat_level WHERE id = $1`, [submissionId]);
      }

      await publishStatus(ctx, 'completed', 'done');
      logger.info({ submissionId }, 'Container workflow completed');
      return;
    }

    // Step 1: Hash verification
    logger.info({ submissionId }, 'Step 1/8: Hash verification');
    await publishStatus(ctx, 'hash_verification', 'step-1');
    const hashResult = await executeStep(ctx, JobType.HashLookup);

    // If the hash is already known with high confidence, fast-track.
    if (hashResult.result['knownMalware'] === true && hashResult.score >= 90) {
      logger.info({ submissionId }, 'Known malware detected via hash -- fast-tracking to scoring');
      await publishStatus(ctx, 'fast_track', 'known-malware');
      await finalize(ctx, [hashResult]);
      return;
    }

    // Step 2: Threat intelligence enrichment
    logger.info({ submissionId }, 'Step 2/8: Threat intelligence enrichment');
    await publishStatus(ctx, 'threat_intel', 'step-2');
    const threatIntelResult = await executeStep(ctx, JobType.ThreatIntel);

    // Step 3: Static analysis
    logger.info({ submissionId }, 'Step 3/8: Static analysis');
    await updateSubmissionStatus(pool, submissionId, 'analyzing');
    await publishStatus(ctx, 'static_analysis', 'step-3');
    const staticResult = await executeStep(ctx, JobType.StaticAnalysis);

    // Step 4: YARA scan
    logger.info({ submissionId }, 'Step 4/8: YARA scan');
    await publishStatus(ctx, 'yara_scan', 'step-4');
    const yaraResult = await executeStep(ctx, JobType.YaraScan);

    // Step 5: Dynamic analysis (sandbox detonation) -- conditionally skipped
    let dynamicResult: StepResult | null = null;
    if (ctx.skipDynamicAnalysis) {
      logger.info({ submissionId }, 'Step 5/8: Dynamic analysis SKIPPED (disabled)');
      await publishStatus(ctx, 'dynamic_analysis_skipped', 'step-5');
    } else {
      logger.info({ submissionId }, 'Step 5/8: Dynamic analysis');
      await updateSubmissionStatus(pool, submissionId, 'analyzing');
      await publishStatus(ctx, 'dynamic_analysis', 'step-5');
      dynamicResult = await executeStep(ctx, JobType.DynamicAnalysis);
    }

    // Step 5b: VT lookup on the REAL executable — extracted from archive or the submitted file itself
    await lookupExtractedFileHashes(ctx);

    // Step 5c: CVE/CISA KEV/EPSS vulnerability lookup from PE version info
    await publishStatus(ctx, 'vuln_lookup', 'step-5c');
    await lookupVulnerabilitiesFromPeMetadata(ctx);

    // Step 5c2: Tech debt / version EOL check via endoflife.date
    await publishStatus(ctx, 'tech_debt_check', 'step-5c2');
    await lookupTechDebtFromPeMetadata(ctx);

    // Step 5c3: CPE classification from product name
    await publishStatus(ctx, 'cpe_classification', 'step-5c3');
    await classifyApplicationFromPeMetadata(ctx);

    // Step 5d: Store YARA pattern match results from dynamic analysis
    await publishStatus(ctx, 'yara_pattern_store', 'step-5d');
    await storeYaraPatternResults(ctx, dynamicResult);

    // Step 5e: Config extraction for known malware families
    await publishStatus(ctx, 'config_extraction', 'step-5e');
    await performConfigExtraction(ctx, dynamicResult);
    await storeConfigExtractionIndicators(ctx);

    // Step 6: Detection engine correlation — send full analysis data for rule generation
    logger.info({ submissionId }, 'Step 6/8: Detection engine');
    await updateSubmissionStatus(pool, submissionId, 'analyzing');
    await publishStatus(ctx, 'detection', 'step-6');
    let detectionResult: StepResult;
    try {
      const [saRow, daRow, tiRows] = await Promise.all([
        pool.query('SELECT * FROM static_analysis_results WHERE submission_id = $1', [submissionId]),
        pool.query('SELECT processes, network_activity, memory_activity, registry_activity, duration_seconds FROM dynamic_analysis_results WHERE submission_id = $1', [submissionId]),
        pool.query('SELECT * FROM threat_intel_results WHERE submission_id = $1', [submissionId]),
      ]);
      // Translate DB jsonb rows → typed interfaces the detection engine expects
      const saRaw = saRow.rows[0] as Record<string, unknown> | undefined;
      const daRaw = daRow.rows[0] as Record<string, unknown> | undefined;
      const fileMeta = (saRaw?.['file_metadata'] ?? {}) as Record<string, unknown>;
      const entropyData = (saRaw?.['entropy_data'] ?? {}) as Record<string, unknown>;
      const peData = (saRaw?.['pe_analysis'] ?? {}) as Record<string, unknown>;
      const memAct = (daRaw?.['memory_activity'] ?? {}) as Record<string, unknown>;
      const netAct = (daRaw?.['network_activity'] ?? {}) as Record<string, unknown>;
      const regAct = (daRaw?.['registry_activity'] ?? {}) as Record<string, unknown>;
      const fileAct = (daRaw?.['file_activity'] ?? {}) as Record<string, unknown>;
      const procData = daRaw?.['processes'] as Record<string, unknown> | undefined;

      const staticTyped = saRaw ? {
        submissionId,
        fileType: String(fileMeta['fileType'] ?? ''),
        magic: String(fileMeta['magic'] ?? ''),
        entropy: Number(entropyData['overallEntropy'] ?? 0),
        isPacked: Boolean(fileMeta['isPacked']),
        packerName: (fileMeta['packerName'] as string) ?? null,
        imports: Array.isArray(peData['imports']) ? peData['imports'] as string[] : [],
        exports: Array.isArray(peData['exports']) ? peData['exports'] as string[] : [],
        sections: Array.isArray(peData['sections']) ? peData['sections'] : [],
        strings: Array.isArray(saRaw['strings']) ? (saRaw['strings'] as Array<Record<string, unknown>>).slice(0, 200).map(s => ({
          value: String(s['value'] ?? ''), encoding: String(s['encoding'] ?? 'ascii') as 'ascii' | 'utf16',
          offset: Number(s['offset'] ?? 0), category: (s['category'] as string) ?? null,
        })) : [],
        certificates: Array.isArray(saRaw['certificates']) ? saRaw['certificates'] : [],
        iocs: [], attackTechniques: [],
      } : null;

      const execveProcs = procData?.['execveProcesses'] as Array<Record<string, unknown>> | undefined;
      const psProcs = procData?.['processes'] as Array<Record<string, unknown>> | undefined;
      const allProcs = (Array.isArray(execveProcs) && execveProcs.length > 0) ? execveProcs : psProcs;
      const connections = (netAct?.['connections'] ?? []) as Array<Record<string, unknown>>;
      const indicators = (memAct?.['suspiciousIndicators'] ?? []) as Array<Record<string, unknown>>;

      const dynamicTyped = daRaw ? {
        submissionId,
        detonationSessionId: String(daRaw['sandbox_id'] ?? ''),
        processesCreated: Array.isArray(allProcs) ? allProcs.map(p => ({
          pid: Number(p['pid'] ?? 0), parentPid: Number(p['parentPid'] ?? p['ppid'] ?? 0),
          name: String(p['name'] ?? ''), commandLine: String(p['commandLine'] ?? p['cmdline'] ?? ''),
          createdAt: String(p['startTime'] ?? p['timestamp'] ?? ''),
        })) : [],
        networkConnections: connections.map(c => ({
          protocol: String(c['protocol'] ?? 'tcp') as 'tcp', sourceAddress: '', sourcePort: 0,
          destinationAddress: String(c['destinationIp'] ?? c['ip'] ?? ''),
          destinationPort: Number(c['destinationPort'] ?? c['port'] ?? 0),
          domain: (c['domain'] as string) ?? null, bytesSent: 0, bytesReceived: 0,
        })),
        filesModified: [
          ...(Array.isArray(fileAct['created']) ? (fileAct['created'] as string[]).map(p => ({ path: p, operation: 'create' as const, newPath: null, sha256: null })) : []),
          ...(Array.isArray(fileAct['modified']) ? (fileAct['modified'] as string[]).map(p => ({ path: p, operation: 'modify' as const, newPath: null, sha256: null })) : []),
          ...(Array.isArray(fileAct['deleted']) ? (fileAct['deleted'] as string[]).map(p => ({ path: p, operation: 'delete' as const, newPath: null, sha256: null })) : []),
        ],
        registryModifications: Array.isArray(regAct['modifications'])
          ? (regAct['modifications'] as Array<Record<string, unknown>>).map(r => ({
              key: String(r['key'] ?? ''), valueName: (r['valueName'] as string) ?? null,
              operation: String(r['operation'] ?? 'create') as 'create' | 'modify' | 'delete',
              valueData: (r['valueData'] as string) ?? null,
            }))
          : Array.isArray(regAct['changes'])
            ? (regAct['changes'] as Array<Record<string, unknown>>).map(r => ({
                key: String(r['key'] ?? r['path'] ?? ''), valueName: (r['name'] as string) ?? null,
                operation: String(r['operation'] ?? r['action'] ?? 'create') as 'create' | 'modify' | 'delete',
                valueData: (r['value'] as string) ?? null,
              }))
            : (() => {
                const mods: Array<{ key: string; valueName: string | null; operation: 'create' | 'modify' | 'delete'; valueData: string | null }> = [];
                const userChanges = Array.isArray(regAct['user']) ? regAct['user'] as string[] : [];
                const systemChanges = Array.isArray(regAct['system']) ? regAct['system'] as string[] : [];
                for (const line of [...systemChanges, ...userChanges]) {
                  if (typeof line !== 'string' || !line.trim()) continue;
                  const trimmed = line.trim();
                  if (trimmed.startsWith('[')) {
                    mods.push({ key: trimmed.replace(/^\[|\]$/g, ''), valueName: null, operation: 'create', valueData: null });
                  } else if (trimmed.includes('=')) {
                    const eqIdx = trimmed.indexOf('=');
                    mods.push({ key: '', valueName: JSON.stringify(trimmed.slice(0, eqIdx)).replace(/^"|"$/g, ''), operation: 'modify', valueData: trimmed.slice(eqIdx + 1).slice(0, 200) });
                  }
                }
                return mods;
              })(),
        mutexesCreated: [],
        iocs: [], attackTechniques: [],
        behaviorTags: indicators.map(i => String(i['description'] ?? '')),
      } : null;

      const detRes = await fetch('http://detection-engine:3004/api/v1/detect/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(process.env['INTERNAL_API_KEY'] ? { 'x-internal-api-key': process.env['INTERNAL_API_KEY'] } : {}) },
        body: JSON.stringify({
          submissionId, sha256: ctx.sha256,
          staticAnalysis: staticTyped,
          dynamicAnalysis: dynamicTyped,
          threatIntelResults: (tiRows.rows ?? []).map((row: Record<string, unknown>) => ({
            submissionId,
            source: String(row['provider'] ?? ''),
            knownMalware: String(row['verdict'] ?? '') === 'malicious',
            malwareFamily: (row['malware_family'] as string) ?? null,
            detectionRatio: row['total_engines']
              ? `${row['detection_count']}/${row['total_engines']}`
              : null,
            communityScore: null,
            tags: [],
            rawResponse: (row['raw_response'] as Record<string, unknown>) ?? {},
            queriedAt: new Date().toISOString(),
            firstSeenAt: null,
            detectionCount: Number(row['detection_count'] ?? 0),
            totalEngines: Number(row['total_engines'] ?? 0),
          })),
        }),
        signal: AbortSignal.timeout(30_000),
      });
      const detBody = await detRes.json() as Record<string, unknown>;
      detectionResult = { jobType: JobType.Detection, status: JobStatus.Completed, result: (detBody['data'] as Record<string, unknown>) ?? detBody, score: 0 };
    } catch (err) {
      logger.warn({ err }, 'Detection engine call failed');
      detectionResult = { jobType: JobType.Detection, status: JobStatus.Completed, result: {}, score: 0 };
    }

    // Store detection results (sigma, suricata, snort, yara recommendations)
    if (detectionResult.status === JobStatus.Completed && Object.keys(detectionResult.result).length > 0) {
      try {
        const dr = detectionResult.result;
        const gr = (dr['generatedRules'] ?? {}) as Record<string, unknown>;
        await pool.query(
          `INSERT INTO detection_results (submission_id, score_breakdown, sigma_rules, suricata_rules, snort_rules, yara_recommendations)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (submission_id) DO UPDATE SET
             score_breakdown = EXCLUDED.score_breakdown, sigma_rules = EXCLUDED.sigma_rules,
             suricata_rules = EXCLUDED.suricata_rules, snort_rules = EXCLUDED.snort_rules,
             yara_recommendations = EXCLUDED.yara_recommendations`,
          [submissionId, JSON.stringify(dr['scoreBreakdown'] ?? null),
           JSON.stringify(gr['sigma'] ?? null), JSON.stringify(gr['suricata'] ?? null),
           JSON.stringify(gr['snort'] ?? null), JSON.stringify(gr['yara'] ?? null)],
        );
      } catch (err) {
        logger.warn({ err }, 'Failed to store detection results');
      }
    }

    // Steps 7 & 8: Scoring and report generation
    logger.info({ submissionId }, 'Step 7-8/8: Scoring and report generation');
    await updateSubmissionStatus(pool, submissionId, 'analyzing');
    await publishStatus(ctx, 'scoring', 'step-7');

    const allResults: StepResult[] = [
      hashResult,
      threatIntelResult,
      staticResult,
      yaraResult,
      ...(dynamicResult ? [dynamicResult] : []),
      detectionResult,
    ];

    await finalize(ctx, allResults);
  } catch (err) {
    logger.error({ submissionId, err }, 'Submission workflow failed');
    await updateSubmissionStatus(pool, submissionId, 'failed');
    await publishStatus(ctx, 'failed', 'error');
    throw err;
  }
}

// ── Step Execution ───────────────────────────────────────────────────────────

// DB analysis_job_type values: static, dynamic, threat_intel, yara, network, memory
type DbJobType = 'static' | 'dynamic' | 'threat_intel' | 'yara' | 'network' | 'memory';

const JOB_TYPE_TO_DB: Record<string, DbJobType> = {
  [JobType.StaticAnalysis]: 'static',
  [JobType.DynamicAnalysis]: 'dynamic',
  [JobType.ThreatIntel]: 'threat_intel',
  [JobType.YaraScan]: 'yara',
  [JobType.Detection]: 'static',
  [JobType.HashLookup]: 'static',
  [JobType.Scoring]: 'static',
  [JobType.ReportGeneration]: 'static',
};

async function executeStep(ctx: WorkflowContext, jobType: JobType): Promise<StepResult> {
  const { submissionId, pool, logger } = ctx;

  const dbJobType = JOB_TYPE_TO_DB[jobType] ?? 'static';

  const insertResult = await pool.query<AnalysisJobRow>(
    `INSERT INTO analysis_jobs (submission_id, job_type, status, started_at)
     VALUES ($1, $2, 'running', NOW())
     RETURNING id`,
    [submissionId, dbJobType],
  );
  const row = insertResult.rows[0];
  if (!row) {
    throw new Error(`Failed to insert analysis_job for ${jobType}`);
  }
  const jobId = row.id;

  try {
    let result: Record<string, unknown> = {};
    let score = 0;

    const serviceUrl = getServiceUrl(jobType);
    if (serviceUrl) {
      try {
        const response = await fetch(serviceUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(process.env['INTERNAL_API_KEY'] ? { 'x-internal-api-key': process.env['INTERNAL_API_KEY'] } : {}),
          },
          body: JSON.stringify({
            submissionId,
            sha256: ctx.sha256,
            hash: ctx.sha256,
            storagePath: ctx.storagePath,
          }),
          signal: AbortSignal.timeout(120_000),
        });
        if (response.ok) {
          const body = await response.json() as Record<string, unknown>;
          result = (body['data'] as Record<string, unknown>) ?? body;
          score = typeof body['score'] === 'number' ? body['score'] : 0;
        } else {
          logger.warn({ jobType, status: response.status }, 'Analysis service returned non-OK');
          result = { serviceStatus: response.status };
        }
      } catch (fetchErr) {
        logger.warn({ jobType, err: fetchErr }, 'Analysis service call failed, recording as completed with no data');
        result = { serviceUnavailable: true };
      }
    }

    // Store static analysis results in DB
    if (jobType === JobType.StaticAnalysis && Object.keys(result).length > 0 && !result['serviceUnavailable']) {
      const metadata = {
        fileType: result['fileType'],
        magic: result['magic'],
        isPacked: result['isPacked'],
        packerName: result['packerName'],
      };
      const peData = result['imports'] || result['sections'] ? {
        isPE: true,
        imports: result['imports'],
        exports: result['exports'],
        sections: result['sections'],
        suspiciousImports: result['suspiciousImports'] ?? [],
        versionInfo: result['versionInfo'] ?? null,
      } : null;

      await pool.query(
        `INSERT INTO static_analysis_results (submission_id, file_metadata, strings, entropy_data, pe_analysis, elf_analysis, office_analysis, pdf_analysis, script_analysis, certificates)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT DO NOTHING`,
        [
          submissionId,
          JSON.stringify(metadata),
          JSON.stringify(result['strings'] ?? []),
          JSON.stringify({ overallEntropy: result['entropy'], isPacked: result['isPacked'] }),
          JSON.stringify(peData),
          JSON.stringify(null),
          JSON.stringify(null),
          JSON.stringify(null),
          JSON.stringify(null),
          JSON.stringify(result['certificates'] ?? null),
        ],
      );

      // Store IOCs from static analysis
      const iocs = result['iocs'];
      if (Array.isArray(iocs)) {
        for (const ioc of iocs as Array<Record<string, unknown>>) {
          await pool.query(
            `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
            [submissionId, ioc['type'] ?? 'domain', ioc['value'], ioc['context'] ?? 'static analysis', Math.round(Number(ioc['confidence'] ?? 70) <= 1 ? Number(ioc['confidence'] ?? 0.7) * 100 : Number(ioc['confidence'] ?? 70))],
          );
        }
      }

      // Store ATT&CK techniques from static analysis
      const techniques = result['attackTechniques'];
      if (Array.isArray(techniques)) {
        for (const t of techniques as Array<Record<string, unknown>>) {
          await pool.query(
            `INSERT INTO attack_techniques (submission_id, tactic_id, technique_id, evidence, confidence) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
            [submissionId, t['tacticId'] ?? '', t['techniqueId'] ?? t['id'] ?? '', JSON.stringify(t['evidence'] ?? {}), Math.round(Number(t['confidence'] ?? 70) <= 1 ? Number(t['confidence'] ?? 0.7) * 100 : Number(t['confidence'] ?? 70))],
          );
        }
      }
    }

    // Store dynamic analysis results and add behavioral score
    if (jobType === JobType.DynamicAnalysis && Object.keys(result).length > 0 && !result['serviceUnavailable']) {
      const riskScore = typeof result['riskScore'] === 'number' ? result['riskScore'] : 0;
      score = riskScore;

      // The dynamic-analysis service already stores results in DB via its /analyze/docker endpoint
      // Extract network IOCs from dynamic analysis
      const netActivity = result['networkActivity'] as Record<string, unknown> | undefined;
      if (netActivity) {
        const connections = netActivity['connections'] as Array<Record<string, unknown>> | undefined;
        if (Array.isArray(connections)) {
          for (const conn of connections) {
            const ip = conn['destinationIp'] as string | undefined;
            if (ip && !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(ip)) {
              await pool.query(
                `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'ip', $2, $3, 80) ON CONFLICT DO NOTHING`,
                [submissionId, ip, `Connection to ${ip}:${String(conn['destinationPort'] ?? '')}`],
              );
            }
          }
        }
        const dnsQueries = netActivity['dnsQueries'] as Array<Record<string, unknown>> | undefined;
        if (Array.isArray(dnsQueries)) {
          const dnsDomains = dnsQueries.map(d => String(d['domain'] ?? '').toLowerCase()).filter(d => d.length > 0);
          const dnsTrancoBatch = dnsDomains.length > 0 ? await fetchTrancoRanks(dnsDomains) : new Map<string, number>();
          for (const dns of dnsQueries) {
            const domain = dns['domain'] as string | undefined;
            if (domain) {
              const conf = trancoConfidence(85, domain, dnsTrancoBatch);
              if (conf < 0) continue;
              await pool.query(
                `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'domain', $2, 'DNS query during detonation', $3) ON CONFLICT DO NOTHING`,
                [submissionId, domain, conf],
              );
            }
          }
        }
      }

      // Extract IOCs from extracted files (jail analysis)
      const dynReport = (result['report'] as Record<string, unknown>) ?? result;
      const extractedFiles = (dynReport['extractedFiles'] ?? result['extractedFiles']) as Array<Record<string, unknown>> | undefined;

      // Build domain trust context from the PE's actual signer/issuer/product
      let localTrustSet: Set<string> | null = null;
      if (Array.isArray(extractedFiles)) {
        for (const ef of extractedFiles) {
          const sig = ef['signature'] as Record<string, unknown> | undefined;
          const vi = ef['versionInfo'] as Record<string, unknown> | undefined;
          if (sig || vi) {
            localTrustSet = buildTrustSet(
              String(sig?.['signer'] ?? vi?.['CompanyName'] ?? ''),
              String(sig?.['issuer'] ?? ''),
              String(vi?.['ProductName'] ?? ''),
            );
            break;
          }
        }
      }

      // DNS-check then Tranco-rank all domains found in extracted files.
      // Step 1: collect all domains, Step 2: discard NXDOMAIN, Step 3: Tranco rank survivors.
      let trancoRanks: Map<string, number> | null = null;
      let resolvedDomains: Set<string> | null = null;
      if (Array.isArray(extractedFiles)) {
        const allDomains: string[] = [];
        for (const ef of extractedFiles) {
          const doms = ef['domains'] as string[] | undefined;
          if (Array.isArray(doms)) allDomains.push(...doms.map(d => d.toLowerCase()));
          const urls = ef['urls'] as string[] | undefined;
          if (Array.isArray(urls)) {
            for (const u of urls) {
              try { allDomains.push(new URL(u).hostname.toLowerCase()); } catch { /* skip */ }
            }
          }
        }
        if (allDomains.length > 0) {
          resolvedDomains = await batchDnsCheck(allDomains);
          // Only Tranco-rank domains that actually resolve
          const liveDomains = allDomains.filter(d => resolvedDomains!.has(d));
          const withParents = [...liveDomains];
          for (const d of liveDomains) {
            const parts = d.split('.');
            if (parts.length > 2) withParents.push(parts.slice(-2).join('.'));
          }
          if (withParents.length > 0) {
            trancoRanks = await fetchTrancoRanks(withParents);
          }
        }
      }

      if (Array.isArray(extractedFiles)) {
        for (const ef of extractedFiles) {
          // Store file hashes as IOCs
          const sha256Hash = ef['sha256'] as string | undefined;
          const sha1Hash = ef['sha1'] as string | undefined;
          const md5Hash = ef['md5'] as string | undefined;
          const filePath = String(ef['path'] ?? '');
          // Correlate hash confidence with threat intel — only high if VT/YARA flagged
          let hashConf = 30;
          if (sha256Hash && sha256Hash.length === 64) {
            const tiRow = await pool.query(
              `SELECT detection_count, total_engines FROM threat_intel_results WHERE submission_id = $1 LIMIT 1`,
              [submissionId],
            );
            if (tiRow.rows.length > 0) {
              const det = Number(tiRow.rows[0]!['detection_count'] ?? 0);
              const total = Number(tiRow.rows[0]!['total_engines'] ?? 0);
              if (det > 0 && total > 0) {
                hashConf = Math.min(95, 30 + Math.round((det / total) * 65));
              }
            }
          }
          if (sha256Hash && sha256Hash.length === 64) {
            await pool.query(
              `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'hash_sha256', $2, $3, $4) ON CONFLICT DO NOTHING`,
              [submissionId, sha256Hash, `Extracted file: ${filePath}`, hashConf],
            );
          }
          if (sha1Hash && sha1Hash.length === 40) {
            await pool.query(
              `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'hash_sha1', $2, $3, $4) ON CONFLICT DO NOTHING`,
              [submissionId, sha1Hash, `Extracted file: ${filePath}`, hashConf],
            );
          }
          if (md5Hash && md5Hash.length === 32) {
            await pool.query(
              `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'hash_md5', $2, $3, $4) ON CONFLICT DO NOTHING`,
              [submissionId, md5Hash, `Extracted file: ${filePath}`, hashConf],
            );
          }

          // URLs found in extracted files — skip if hostname didn't resolve
          const urls = ef['urls'] as string[] | undefined;
          if (Array.isArray(urls)) {
            for (const url of urls.slice(0, 20)) {
              if (resolvedDomains) {
                try {
                  const host = new URL(url).hostname.toLowerCase();
                  if (!resolvedDomains.has(host)) continue;
                } catch { /* skip malformed */ continue; }
              }
              const trusted = isTrustedInfra(url, localTrustSet, trancoRanks);
              let urlConf = trusted ? 10 : 75;
              if (!trusted) {
                try { urlConf = trancoConfidence(urlConf, new URL(url).hostname, trancoRanks); } catch { /* keep base */ }
              }
              if (urlConf < 0) continue;
              await pool.query(
                `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'url', $2, $3, $4) ON CONFLICT DO NOTHING`,
                [submissionId, url, trusted ? `Known infrastructure — ${filePath}` : `Embedded in: ${filePath}`, urlConf],
              );
            }
          }

          // IPs found in extracted files (filter private, reserved, and version-number-like IPs)
          const ips = ef['ips'] as string[] | undefined;
          if (Array.isArray(ips)) {
            for (const ip of ips.slice(0, 20)) {
              if (!/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)/.test(ip)) {
                const firstOctet = parseInt(ip.split('.')[0] ?? '', 10);
                if (firstOctet >= 1 && firstOctet <= 9) continue;
                await pool.query(
                  `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'ip', $2, $3, 70) ON CONFLICT DO NOTHING`,
                  [submissionId, ip, `Embedded in: ${filePath}`],
                );
              }
            }
          }

          // Email addresses found
          const emails = ef['emails'] as string[] | undefined;
          if (Array.isArray(emails)) {
            for (const email of emails.slice(0, 10)) {
              await pool.query(
                `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'email', $2, $3, 65) ON CONFLICT DO NOTHING`,
                [submissionId, email, `Embedded in: ${filePath}`],
              );
            }
          }

          // Domain names found — skip any that didn't resolve (NXDOMAIN)
          const domains = ef['domains'] as string[] | undefined;
          if (Array.isArray(domains)) {
            for (const domain of domains.slice(0, 20)) {
              if (resolvedDomains && !resolvedDomains.has(domain.toLowerCase())) continue;
              const trusted = isTrustedInfra(domain, localTrustSet, trancoRanks);
              let domConf = trusted ? 10 : 65;
              if (!trusted) {
                domConf = trancoConfidence(domConf, domain, trancoRanks);
              }
              if (domConf < 0) continue;
              await pool.query(
                `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'domain', $2, $3, $4) ON CONFLICT DO NOTHING`,
                [submissionId, domain, trusted ? `Known infrastructure — ${filePath}` : `Embedded in: ${filePath}`, domConf],
              );
            }
          }

          // Registry keys found
          const registryKeys = ef['registryKeys'] as string[] | undefined;
          if (Array.isArray(registryKeys)) {
            for (const regKey of registryKeys.slice(0, 15)) {
              await pool.query(
                `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'registry_key', $2, $3, 70) ON CONFLICT DO NOTHING`,
                [submissionId, regKey, `Embedded in: ${filePath}`],
              );
            }
          }

          // Mutex patterns found
          const mutexPatterns = ef['mutexPatterns'] as string[] | undefined;
          if (Array.isArray(mutexPatterns)) {
            for (const mutex of mutexPatterns.slice(0, 10)) {
              await pool.query(
                `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'mutex', $2, $3, 70) ON CONFLICT DO NOTHING`,
                [submissionId, mutex, `Embedded in: ${filePath}`],
              );
            }
          }

          // File paths found
          const filePaths = ef['filePaths'] as string[] | undefined;
          if (Array.isArray(filePaths)) {
            for (const fp of filePaths.slice(0, 15)) {
              await pool.query(
                `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'file_path', $2, $3, 60) ON CONFLICT DO NOTHING`,
                [submissionId, fp, `Embedded in: ${filePath}`],
              );
            }
          }
        }
      }

      // Extract IOCs from strace analysis
      const straceAnalysis = (dynReport['straceAnalysis'] ?? result['straceAnalysis']) as Record<string, unknown> | undefined;
      if (straceAnalysis) {
        const externalIPs = straceAnalysis['externalIPs'] as Array<Record<string, unknown>> | undefined;
        if (Array.isArray(externalIPs)) {
          for (const entry of externalIPs.slice(0, 20)) {
            const ip = String(entry['ip'] ?? '');
            const port = String(entry['port'] ?? '');
            if (ip) {
              await pool.query(
                `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'ip', $2, $3, 85) ON CONFLICT DO NOTHING`,
                [submissionId, ip, `Strace: connection to ${ip}:${port}`],
              );
            }
          }
        }
      }

      // Extract IOCs from wine registry changes
      const wineRegChanges = (dynReport['wineRegistryChanges'] ?? result['wineRegistryChanges']) as Record<string, unknown> | undefined;
      if (wineRegChanges) {
        const allRegChanges = [
          ...(Array.isArray(wineRegChanges['system']) ? wineRegChanges['system'] as string[] : []),
          ...(Array.isArray(wineRegChanges['user']) ? wineRegChanges['user'] as string[] : []),
        ];
        for (const change of allRegChanges.slice(0, 20)) {
          if (typeof change === 'string' && change.length > 3) {
            await pool.query(
              `INSERT INTO iocs (submission_id, type, value, context, confidence) VALUES ($1, 'registry_key', $2, $3, 80) ON CONFLICT DO NOTHING`,
              [submissionId, change, 'Wine registry change during execution'],
            );
          }
        }
      }

      // ── MITRE ATT&CK Technique Mapping from Observed Behavior ──
      await mapAttackTechniques(pool, submissionId, result);

      // Extract suspicious indicators as attack techniques (legacy behavior)
      const indicators = result['suspiciousIndicators'] as Array<Record<string, unknown>> | undefined;
      if (Array.isArray(indicators)) {
        for (const ind of indicators) {
          const category = String(ind['category'] ?? 'unknown');
          const severity = String(ind['severity'] ?? 'medium');
          const confidence = severity === 'critical' ? 90 : severity === 'high' ? 80 : severity === 'medium' ? 65 : 50;
          await pool.query(
            `INSERT INTO attack_techniques (submission_id, tactic_id, technique_id, evidence, confidence)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
            [submissionId, category, `behavioral-${category}`, JSON.stringify({ description: ind['description'], evidence: ind['evidence'] }), confidence],
          );
        }
      }
    }

    // Store threat intel results
    if (jobType === JobType.ThreatIntel && Array.isArray(result['results'])) {
      for (const ti of result['results'] as Array<Record<string, unknown>>) {
        await pool.query(
          `INSERT INTO threat_intel_results (submission_id, provider, verdict, detection_count, total_engines, malware_family, raw_response)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT DO NOTHING`,
          [submissionId, ti['provider'], ti['verdict'], ti['detectionCount'] ?? 0, ti['totalEngines'] ?? 0, ti['malwareFamily'], JSON.stringify(ti)],
        );
      }
    }

    await pool.query(
      `UPDATE analysis_jobs SET status = 'completed', completed_at = NOW() WHERE id = $1`,
      [jobId],
    );

    return { jobType, status: JobStatus.Completed, result, score };
  } catch (err) {
    logger.error({ jobId, jobType, err }, 'Analysis step failed');

    await pool.query(
      `UPDATE analysis_jobs SET status = 'failed', error_message = $1, completed_at = NOW() WHERE id = $2`,
      [err instanceof Error ? err.message : 'Unknown error', jobId],
    );

    return {
      jobType,
      status: JobStatus.Failed,
      result: { error: err instanceof Error ? err.message : 'Unknown error' },
      score: 0,
    };
  }
}

// NOTE: YaraScan has no service URL — YARA scanning happens inside the sandbox
// container during dynamic analysis (step g5 pattern scanner + step g6 community
// rules), NOT as a separate HTTP service call. Step 4's executeStep(YaraScan) is
// intentionally a no-op; results flow through storeYaraPatternResults at step 5d.
function getServiceUrl(jobType: JobType): string | undefined {
  const services: Partial<Record<JobType, string>> = {
    [JobType.StaticAnalysis]: 'http://static-analysis:3002/analyze',
    [JobType.ThreatIntel]: 'http://threat-intel:3003/api/v1/enrich/sync',
    [JobType.Detection]: 'http://detection-engine:3004/api/v1/detect/sync',
    [JobType.DynamicAnalysis]: 'http://dynamic-analysis:3009/analyze/docker',
  };
  return services[jobType];
}

// ── Domain trust (data-driven from extracted PE signer/issuer) ───────────────

const CERT_INFRA_PATTERNS = [
  /^crl\d?\./i, /^ocsp\d?\./i, /^cacerts?\./i, /^pki\./i, /^certs?\./i,
  /^secure\./i, /^timestamp\./i,
];

const KNOWN_CA_DOMAINS = [
  'digicert.com', 'globalsign.com', 'verisign.com', 'symantec.com',
  'letsencrypt.org', 'comodo.com', 'sectigo.com', 'entrust.net',
  'godaddy.com', 'comodoca.com', 'usertrust.com', 'thawte.com',
];

const VENDOR_DOMAIN_MAP: Record<string, string[]> = {
  cisco: ['cisco.com', 'webex.com', 'meraki.com'],
  microsoft: ['microsoft.com', 'windows.com', 'office.com', 'live.com', 'azure.com', 'msn.com', 'bing.com'],
  google: ['google.com', 'googleapis.com', 'gstatic.com', 'youtube.com', 'android.com', 'chromium.org'],
  apple: ['apple.com', 'icloud.com'],
  mozilla: ['mozilla.org', 'mozilla.com', 'firefox.com'],
  adobe: ['adobe.com', 'behance.net'],
  amazon: ['amazonaws.com', 'amazon.com', 'aws.amazon.com'],
  cloudflare: ['cloudflare.com'],
  akamai: ['akamai.net', 'akamaized.net'],
};

const SCHEMA_DOMAINS = ['w3.org', 'xmlsoap.org', 'openxmlformats.org', 'schemas.microsoft.com'];

function buildTrustSet(signer: string, issuer: string, productName: string): Set<string> {
  const trusted = new Set<string>();
  KNOWN_CA_DOMAINS.forEach(d => trusted.add(d));
  SCHEMA_DOMAINS.forEach(d => trusted.add(d));
  const terms = [signer, issuer, productName]
    .join(' ').toLowerCase()
    .replace(/[^a-z0-9 ]/g, ' ')
    .split(/\s+/)
    .filter(t => t.length >= 3);
  for (const [vendor, domains] of Object.entries(VENDOR_DOMAIN_MAP)) {
    if (terms.some(t => t.includes(vendor) || vendor.includes(t))) {
      domains.forEach(d => trusted.add(d));
    }
  }
  return trusted;
}

function isTrustedInfra(urlOrDomain: string, trustSet?: Set<string> | null, trancoRanks?: Map<string, number> | null): boolean {
  try {
    let host = urlOrDomain;
    if (host.includes('://')) host = new URL(host).hostname;
    host = host.split('/')[0]!.split('?')[0]!.split(':')[0]!.toLowerCase();
    if (CERT_INFRA_PATTERNS.some(p => p.test(host))) return true;
    if (trustSet) {
      for (const d of trustSet) {
        if (host === d || host.endsWith('.' + d)) return true;
      }
    }
    if (trancoRanks) {
      const rank = trancoRanks.get(host) ?? trancoRanks.get(host.split('.').slice(-2).join('.'));
      if (rank !== undefined && rank <= 50_000) return true;
    }
    return false;
  } catch { return false; }
}

function trancoConfidence(baseConfidence: number, domain: string, trancoRanks?: Map<string, number> | null): number {
  if (!trancoRanks) return baseConfidence;
  const lower = domain.toLowerCase();
  const rank = trancoRanks.get(lower) ?? trancoRanks.get(lower.split('.').slice(-2).join('.'));
  if (rank === undefined) return baseConfidence;
  if (rank <= 50_000) return -1;
  if (rank <= 200_000) return Math.min(baseConfidence, 25);
  return Math.min(baseConfidence, 40);
}

async function fetchTrancoRanks(domains: string[]): Promise<Map<string, number>> {
  const map = new Map<string, number>();
  if (domains.length === 0) return map;
  try {
    const apiKey = process.env['INTERNAL_API_KEY'] ?? '';
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) headers['x-internal-api-key'] = apiKey;
    const res = await fetch('http://vuln-feeds:9000/feeds/tranco', {
      method: 'POST',
      headers,
      body: JSON.stringify({ domains: [...new Set(domains)].slice(0, 1000) }),
      signal: AbortSignal.timeout(10_000),
    });
    if (res.ok) {
      const data = await res.json() as { results: Record<string, number> };
      for (const [d, rank] of Object.entries(data.results)) {
        map.set(d, rank);
      }
    }
  } catch { /* non-fatal */ }
  return map;
}

async function batchDnsCheck(domains: string[]): Promise<Set<string>> {
  const existing = new Set<string>();
  const unique = [...new Set(domains.map(d => d.toLowerCase()))];
  const BATCH_SIZE = 50;
  for (let i = 0; i < unique.length; i += BATCH_SIZE) {
    const batch = unique.slice(i, i + BATCH_SIZE);
    await Promise.allSettled(
      batch.map(async (domain) => {
        try {
          await dns.resolve(domain);
          existing.add(domain);
        } catch {
          // NXDOMAIN — domain doesn't exist
        }
      }),
    );
  }
  return existing;
}

// ── Finalization ─────────────────────────────────────────────────────────────

async function finalize(ctx: WorkflowContext, _results: StepResult[]): Promise<void> {
  const { submissionId, pool, logger } = ctx;

  // Read static analysis results from DB and score them
  const threatScore = await computeThreatScore(pool, submissionId, logger);
  const threatLevel: ThreatLevel = threatLevelFromScore(threatScore);

  // Compute structured verdict with evidence chains
  const verdict = await buildVerdictFromDb(pool, submissionId, logger);

  // Cross-check: prevent "malicious" verdict when primary score is informational/low.
  // The verdict engine uses its own internal scoring which can disagree with the primary
  // scorer on edge cases (e.g., 1-engine FP detection with family name).
  if (verdict.classification === 'malicious' && threatScore < 30) {
    verdict.classification = threatScore <= 15 ? 'benign' : 'suspicious';
    verdict.confidence = Math.min(verdict.confidence, 50);
    verdict.recommendedAction = threatScore <= 15 ? 'Allow' : 'Monitor';
  } else if (verdict.classification === 'benign' && threatScore >= 70) {
    verdict.classification = 'suspicious';
    verdict.confidence = Math.min(verdict.confidence, 60);
    verdict.recommendedAction = 'Monitor';
  }

  // Record scoring and report generation jobs
  await executeStep(ctx, JobType.Scoring);
  await publishStatus(ctx, 'scoring_complete', 'step-7-done');

  logger.info({ submissionId }, 'Step 8/8: Report generation');
  await publishStatus(ctx, 'report_generation', 'step-8');
  await executeStep(ctx, JobType.ReportGeneration);

  await pool.query(
    `UPDATE submissions
     SET status = 'review', threat_score = $1, threat_level = $2::threat_level
     WHERE id = $3`,
    [threatScore, threatLevel, submissionId],
  );

  await publishStatus(ctx, 'review', 'done');

  logger.info(
    { submissionId, threatScore, threatLevel, verdict: verdict.classification, verdictConfidence: verdict.confidence },
    'Submission workflow completed',
  );

  // SIEM forwarding and EDR push for high/critical threats
  if (shouldAlert(threatScore)) {
    await dispatchAlerts(ctx, threatScore, threatLevel, verdict);
  }
}

/**
 * Build a structured Verdict from database analysis results.
 */
async function buildVerdictFromDb(pool: pg.Pool, submissionId: string, logger: Logger): Promise<Verdict> {
  const evidenceItems: EvidenceItem[] = [];

  try {
    // VT evidence
    const tiRes = await pool.query(
      `SELECT detection_count, total_engines, malware_family FROM threat_intel_results
       WHERE submission_id = $1 AND provider LIKE 'virustotal%'`,
      [submissionId],
    );
    for (const row of tiRes.rows as Array<Record<string, unknown>>) {
      const detections = Number(row['detection_count'] ?? 0);
      const total = Number(row['total_engines'] ?? 0);
      const family = (row['malware_family'] as string) ?? null;
      if (total > 0) {
        evidenceItems.push(buildVtEvidence(detections, total, family));
      }
    }

    // Static analysis evidence
    const saRes = await pool.query(
      'SELECT file_metadata, entropy_data, pe_analysis, script_analysis FROM static_analysis_results WHERE submission_id = $1',
      [submissionId],
    );
    const sa = saRes.rows[0] as Record<string, unknown> | undefined;
    if (sa) {
      const entropy = sa['entropy_data'] as Record<string, unknown> | null;
      const entropyVal = typeof entropy?.['overallEntropy'] === 'number' ? entropy['overallEntropy'] as number : 0;
      const pe = sa['pe_analysis'] as Record<string, unknown> | null;
      const suspImports = (pe?.['suspiciousImports'] as string[]) ?? [];
      const metadata = sa['file_metadata'] as Record<string, unknown> | null;
      const isPacked = Boolean(metadata?.['isPacked']);
      const script = sa['script_analysis'] as Record<string, unknown> | null;
      const isObfuscated = Boolean(script?.['isObfuscated']);

      evidenceItems.push(buildStaticEvidence(isPacked, suspImports, entropyVal, isObfuscated));
    }

    // Sandbox/dynamic evidence
    const dynRes = await pool.query(
      'SELECT memory_activity, network_activity FROM dynamic_analysis_results WHERE submission_id = $1',
      [submissionId],
    );
    const dyn = dynRes.rows[0] as Record<string, unknown> | undefined;
    if (dyn) {
      const memActivity = dyn['memory_activity'] as Record<string, unknown> | null;
      const riskScore = typeof memActivity?.['riskScore'] === 'number' ? memActivity['riskScore'] as number : 0;
      const indicators = (memActivity?.['suspiciousIndicators'] as Array<{ category: string; severity: string; description: string }>) ?? [];
      const droppedFiles = (memActivity?.['droppedFiles'] as unknown[]) ?? [];
      const netActivity = dyn['network_activity'] as Record<string, unknown> | null;
      const connections = (netActivity?.['connections'] as unknown[]) ?? [];

      evidenceItems.push(buildSandboxEvidence(riskScore, indicators, droppedFiles.length, connections.length));

      // Network evidence
      const dnsQueries = (netActivity?.['dnsQueries'] as unknown[]) ?? [];
      evidenceItems.push(buildNetworkEvidence(connections.length, dnsQueries.length, []));

      // Certificate evidence
      const extractedFiles = memActivity?.['extractedFiles'] as Array<Record<string, unknown>> | undefined;
      if (extractedFiles) {
        for (const ef of extractedFiles) {
          const sig = ef['signature'] as Record<string, unknown> | undefined;
          if (sig) {
            evidenceItems.push(buildCertificateEvidence(
              Boolean(sig['hasCertificate']),
              Boolean(sig['isValidVendor']),
              String(sig['signer'] ?? 'unknown'),
            ));
            break; // Only first cert
          }
        }
      }
    }

    // YARA evidence
    const yaraRes = await pool.query(
      `SELECT yr.name, yr.category, ysr.match_details
       FROM yara_scan_results ysr
       JOIN yara_rules yr ON yr.id = ysr.rule_id
       WHERE ysr.submission_id = $1 AND ysr.matched = TRUE`,
      [submissionId],
    );
    const yaraMatches = (yaraRes.rows as Array<Record<string, unknown>>).map(row => ({
      name: String(row['name'] ?? ''),
      category: String(row['category'] ?? ''),
      severity: (() => {
        const details = row['match_details'] as Record<string, unknown> | null;
        return String(details?.['severity'] ?? 'medium');
      })(),
    }));
    evidenceItems.push(buildYaraEvidence(yaraMatches));

  } catch (err) {
    logger.warn({ err }, 'Error building verdict evidence');
  }

  return computeVerdict(evidenceItems);
}

/**
 * Dispatch SIEM alerts, webhook notifications, and EDR hash blocks
 * for high/critical threat submissions.
 */
async function dispatchAlerts(
  ctx: WorkflowContext,
  threatScore: number,
  threatLevel: ThreatLevel,
  verdict: Verdict,
): Promise<void> {
  const { submissionId, pool, logger } = ctx;

  try {
    // Gather data needed for alerts
    const subRes = await pool.query(
      'SELECT filename, sha256 FROM submissions WHERE id = $1',
      [submissionId],
    );
    const sub = subRes.rows[0] as Record<string, unknown> | undefined;
    if (!sub) return;

    const filename = String(sub['filename'] ?? 'unknown');
    const sha256 = String(sub['sha256'] ?? '');

    // Get IOCs
    const iocRes = await pool.query(
      'SELECT type, value FROM iocs WHERE submission_id = $1 LIMIT 20',
      [submissionId],
    );
    const iocs = (iocRes.rows as Array<Record<string, string>>).map(r => ({
      type: r['type'] ?? '',
      value: r['value'] ?? '',
    }));

    // Get attack techniques
    const techRes = await pool.query(
      'SELECT technique_id FROM attack_techniques WHERE submission_id = $1',
      [submissionId],
    );
    const attackTechniques = (techRes.rows as Array<Record<string, string>>).map(r => r['technique_id'] ?? '');

    // Get VT data
    const vtRes = await pool.query(
      `SELECT detection_count, total_engines, malware_family FROM threat_intel_results
       WHERE submission_id = $1 AND provider LIKE 'virustotal%' LIMIT 1`,
      [submissionId],
    );
    const vtRow = vtRes.rows[0] as Record<string, unknown> | undefined;
    const vtDetections = Number(vtRow?.['detection_count'] ?? 0);
    const vtTotal = Number(vtRow?.['total_engines'] ?? 0);
    const malwareFamily = (vtRow?.['malware_family'] as string) ?? null;

    const baseUrl = process.env['SCANBOY_BASE_URL'] ?? 'https://app.scanboy.io';

    const alertPayload = buildAlertPayload({
      submissionId,
      filename,
      threatScore,
      threatLevel,
      malwareFamily,
      iocs,
      attackTechniques,
      vtDetections,
      vtTotal,
      baseUrl,
    });

    // Send SIEM alerts (configured via environment variables)
    await sendConfiguredSiemAlerts(alertPayload, logger);

    // Send webhook alerts
    const webhookUrl = process.env['SCANBOY_WEBHOOK_URL'];
    if (webhookUrl) {
      await sendWebhookAlert(webhookUrl, alertPayload).catch((err: unknown) => {
        logger.warn({ err }, 'Webhook alert failed');
      });
    }

    // Push to EDR if configured and meets threshold
    if (shouldPushToEdr(threatScore, vtDetections, vtTotal) && isValidSha256(sha256)) {
      await sendConfiguredEdrPush(sha256, malwareFamily ?? 'unknown', threatScore, logger);
    }

    logger.info({ submissionId, verdict: verdict.classification }, 'Alert dispatch completed');
  } catch (err) {
    logger.warn({ err }, 'Alert dispatch failed (non-fatal)');
  }
}

async function sendConfiguredSiemAlerts(payload: AlertPayload, logger: Logger): Promise<void> {
  const siemType = process.env['SCANBOY_SIEM_TYPE'] as SiemConfig['type'] | undefined;
  const siemEndpoint = process.env['SCANBOY_SIEM_ENDPOINT'];

  if (!siemType || !siemEndpoint) return;

  const config: SiemConfig = {
    type: siemType,
    endpoint: siemEndpoint,
    apiKey: process.env['SCANBOY_SIEM_API_KEY'],
    index: process.env['SCANBOY_SIEM_INDEX'],
    workspaceId: process.env['SCANBOY_SIEM_WORKSPACE_ID'],
    sharedKey: process.env['SCANBOY_SIEM_SHARED_KEY'],
    logType: process.env['SCANBOY_SIEM_LOG_TYPE'],
  };

  await forwardToSiem(config, payload).catch((err: unknown) => {
    logger.warn({ err, siemType }, 'SIEM forwarding failed');
  });
}

async function sendConfiguredEdrPush(
  sha256: string,
  family: string,
  score: number,
  logger: Logger,
): Promise<void> {
  const edrType = process.env['SCANBOY_EDR_TYPE'] as EdrConfig['type'] | undefined;
  const edrEndpoint = process.env['SCANBOY_EDR_ENDPOINT'];
  const edrApiKey = process.env['SCANBOY_EDR_API_KEY'];

  if (!edrType || !edrEndpoint || !edrApiKey) return;

  const config: EdrConfig = {
    type: edrType,
    endpoint: edrEndpoint,
    apiKey: edrApiKey,
    clientId: process.env['SCANBOY_EDR_CLIENT_ID'],
    clientSecret: process.env['SCANBOY_EDR_CLIENT_SECRET'],
    tenantId: process.env['SCANBOY_EDR_TENANT_ID'],
    siteToken: process.env['SCANBOY_EDR_SITE_TOKEN'],
  };

  await pushHashToEdr(config, sha256, family, score).catch((err: unknown) => {
    logger.warn({ err, edrType }, 'EDR hash push failed');
  });
}

async function computeThreatScore(pool: pg.Pool, submissionId: string, logger: Logger): Promise<number> {
  // Gather all evidence, then compute a single score at the end.
  // Priority: VT > YARA > Sandbox behavior > Static indicators > Vuln/tech-debt
  // Signature + clean VT = hard cap at 15.

  let vtScore = 0;     // -20 (clean) to +60 (confirmed malware)
  let yaraScore = 0;   // 0 to 40
  let sandboxScore = 0; // 0 to 50
  let staticScore = 0;  // 0 to 25
  let vulnScore = 0;    // 0 to 10
  let hasValidVendorSig = false;
  let vtClean = false;  // true if VT scanned with 40+ engines and <5% detections
  let vtScanned = false;
  let hasFamily = false;
  let behavioralSandboxScore = 0;

  try {
    // ── 1. VirusTotal ────────────────────────────────────────────────────
    const vtRes = await pool.query(
      `SELECT detection_count, total_engines, malware_family FROM threat_intel_results
       WHERE submission_id = $1 AND provider LIKE 'virustotal%'`,
      [submissionId],
    );
    let vtMalwareFamily: string | null = null;
    for (const row of vtRes.rows as Array<Record<string, unknown>>) {
      const det = Number(row['detection_count'] ?? 0);
      const tot = Number(row['total_engines'] ?? 0);
      if (tot >= 40) vtScanned = true;
      if (row['malware_family']) { hasFamily = true; vtMalwareFamily = String(row['malware_family']); }
      if (tot > 0) {
        const ratio = det / tot;
        // [P1-R4] Three tiers above 50% for better granularity
        if (ratio >= 0.75)       vtScore = Math.max(vtScore, 70);
        else if (ratio >= 0.5)   vtScore = Math.max(vtScore, 60);
        else if (ratio >= 0.25)  vtScore = Math.max(vtScore, 50);
        else if (ratio >= 0.1)   vtScore = Math.max(vtScore, 35);
        else if (ratio >= 0.05)  vtScore = Math.max(vtScore, 15);
        else if (det > 0 && ratio >= 0.02) vtScore = Math.max(vtScore, 5);
        else if (det > 0)        { vtScore = Math.max(vtScore, 2); }
        else                     { if (vtScore <= 0) vtScore = -15; vtClean = true; }
      }
    }
    // [P1] Family severity: ransomware/trojan families get more weight than PUP/adware
    // Gate: only apply family bonus when detection ratio is meaningful (≥5%, i.e. vtScore ≥ 15).
    // Single-engine FPs (1/71 "Trojan.Shelm") must not trigger +15 amplification.
    if (hasFamily && vtMalwareFamily && vtScore >= 15) {
      const fam = vtMalwareFamily.toLowerCase();
      const isHighThreatFamily = /ransom|trojan|rat|stealer|loader|backdoor|rootkit|wiper|botnet/.test(fam);
      const isLowThreatFamily = /adware|pup|pua|toolbar|bundler|grayware/.test(fam);
      vtScore += isHighThreatFamily ? 15 : isLowThreatFamily ? 3 : 10;
    }

    // ── 2. YARA rules ────────────────────────────────────────────────────
    const yaraRes = await pool.query(
      `SELECT yr.name, yr.category, ysr.match_details
       FROM yara_scan_results ysr
       JOIN yara_rules yr ON yr.id = ysr.rule_id
       WHERE ysr.submission_id = $1 AND ysr.matched = TRUE`,
      [submissionId],
    );
    for (const row of yaraRes.rows as Array<Record<string, unknown>>) {
      const details = row['match_details'] as Record<string, unknown> | null;
      const sev = String(details?.['severity'] ?? row['category'] ?? 'medium');
      if (sev === 'critical') yaraScore += 20;
      else if (sev === 'high') yaraScore += 12;
      else if (sev === 'medium') yaraScore += 5;
      else yaraScore += 2;
    }
    yaraScore = Math.min(yaraScore, 40);

    // ── 3. Sandbox / Dynamic analysis ────────────────────────────────────
    const dynRes = await pool.query(
      'SELECT memory_activity, network_activity, processes, duration_seconds FROM dynamic_analysis_results WHERE submission_id = $1',
      [submissionId],
    );
    const dyn = dynRes.rows[0] as Record<string, unknown> | undefined;
    if (dyn) {
      const mem = dyn['memory_activity'] as Record<string, unknown> | null;
      const riskScore = typeof mem?.['riskScore'] === 'number' ? mem['riskScore'] as number : 0;
      const indicators = (mem?.['suspiciousIndicators'] as Array<Record<string, unknown>>) ?? [];
      const droppedFiles = (mem?.['droppedFiles'] as unknown[]) ?? [];

      // Filter out false positives from sandbox infrastructure
      const realIndicators = indicators.filter(i => {
        const evidence = String(i['evidence'] ?? '');
        const desc = String(i['description'] ?? '');
        if (evidence.includes('scanboy-exec') || evidence.includes('scanboy-deep')) return false;
        if (desc.includes('scanboy-exec') || desc.includes('scanboy-deep')) return false;
        const benignDlls = ['SHELL32.dll', 'ADVAPI32.dll', 'KERNEL32.dll', 'USER32.dll', 'GDI32.dll', 'ole32.dll', 'COMCTL32.dll'];
        if (i['category'] === 'imports' && benignDlls.some(d => evidence.includes(d))) {
          const suspParts = evidence.split(',').map((s: string) => s.trim()).filter((s: string) => !benignDlls.includes(s));
          if (suspParts.length === 0) return false;
        }
        return true;
      });
      // Separate YARA-sourced indicators from genuine behavioral indicators
      const isYaraIndicator = (i: Record<string, unknown>) => {
        const desc = String(i['description'] ?? '');
        const cat = String(i['category'] ?? '');
        return desc.startsWith('YARA:') || cat === 'yara-binary';
      };
      const behavioralIndicators = realIndicators.filter(i => !isYaraIndicator(i));
      const realDropped = droppedFiles.filter((f: unknown) => {
        const path = String((f as Record<string, unknown>)['path'] ?? '');
        return !path.includes('scanboy-');
      });
      const criticals = realIndicators.filter(i => i['severity'] === 'critical').length;
      const highs = realIndicators.filter(i => i['severity'] === 'high').length;
      sandboxScore += Math.min(Math.round(riskScore * 0.6), 40);
      sandboxScore += criticals * 20 + highs * 10 + realIndicators.filter(i => i['severity'] === 'medium').length * 4;
      sandboxScore += Math.min(realDropped.length * 5, 15);
      // Behavioral-only sandbox score for vendor cap decisions (excludes YARA-sourced indicators)
      const behCriticals = behavioralIndicators.filter(i => i['severity'] === 'critical').length;
      const behHighs = behavioralIndicators.filter(i => i['severity'] === 'high').length;
      const behMediums = behavioralIndicators.filter(i => i['severity'] === 'medium').length;
      behavioralSandboxScore = Math.min(Math.round(riskScore * 0.6), 40)
        + behCriticals * 20 + behHighs * 10 + behMediums * 4
        + Math.min(realDropped.length * 5, 15);

      // VT-corroborated boost: if VT confirms malware and sandbox found ANY indicators,
      // the sandbox evidence is more meaningful than its raw score suggests
      if (vtScore >= 50 && realIndicators.length > 0) {
        sandboxScore = Math.max(sandboxScore, 30);
      } else if (vtScore >= 35 && realIndicators.length > 0) {
        sandboxScore = Math.max(sandboxScore, 20);
      }

      sandboxScore = Math.min(sandboxScore, 60);

      // Check signature
      const extractedFiles = (mem?.['extractedFiles'] as Array<Record<string, unknown>>) ?? [];
      for (const ef of extractedFiles) {
        const sig = ef['signature'] as Record<string, unknown> | undefined;
        if (sig?.['hasCertificate'] && sig?.['isValidVendor']) {
          hasValidVendorSig = true;
        }
      }

      // For vendor-signed binaries with clean/near-clean VT, use behavioral-only sandbox
      // score and further suppress benign indicators (packing, embedded URLs, generic strings)
      // that are normal for legitimate packed/signed software.
      if (hasValidVendorSig && (vtClean || (vtScanned && vtScore <= 5))) {
        const signedBenignCategories = new Set(['packing', 'suspicious_strings', 'network']);
        const genuineBehavioral = behavioralIndicators.filter(i => !signedBenignCategories.has(String(i['category'] ?? '')));
        const genCriticals = genuineBehavioral.filter(i => i['severity'] === 'critical').length;
        const genHighs = genuineBehavioral.filter(i => i['severity'] === 'high').length;
        const genMediums = genuineBehavioral.filter(i => i['severity'] === 'medium').length;
        const genuineScore = genCriticals * 20 + genHighs * 10 + genMediums * 4
          + Math.min(realDropped.length * 5, 15);
        sandboxScore = Math.min(genuineScore, 60);
        behavioralSandboxScore = genuineScore;
        logger.info({ submissionId, genuineScore, originalSandboxScore: sandboxScore }, 'Vendor-signed binary — suppressed benign indicators');
      }
    }

    // ── 4. Static analysis ───────────────────────────────────────────────
    const saRes = await pool.query(
      'SELECT file_metadata, strings, entropy_data, pe_analysis, script_analysis FROM static_analysis_results WHERE submission_id = $1',
      [submissionId],
    );
    const sa = saRes.rows[0] as Record<string, unknown> | undefined;
    if (sa) {
      const metadata = sa['file_metadata'] as Record<string, unknown> | null;
      const isPacked = Boolean(metadata?.['isPacked']);
      // Packing and high entropy are normal for legitimate signed software (UPX, Electron, etc.)
      const suppressPackingSignals = hasValidVendorSig && (vtClean || (vtScanned && vtScore <= 5));
      if (isPacked && !suppressPackingSignals) staticScore += 5;

      // Entropy thresholds: normal PE files with compressed resources sit at 7.0-7.7.
      // Only >7.9 (near-random) reliably indicates encryption/packing. Using >7.5 FP'd
      // on all legitimate software (WinZip, Notepad++, WinRAR all exceeded 7.5).
      const entropy = sa['entropy_data'] as Record<string, unknown> | null;
      const entropyVal = typeof entropy?.['overallEntropy'] === 'number' ? entropy['overallEntropy'] as number : 0;
      if (!suppressPackingSignals) {
        if (entropyVal > 7.9) staticScore += 6;
        else if (entropyVal > 7.7) staticScore += 3;
      }

      const pe = sa['pe_analysis'] as Record<string, unknown> | null;
      const suspImports = (pe?.['suspiciousImports'] as string[]) ?? [];
      staticScore += Math.min(suspImports.length * 2, 8);

      const script = sa['script_analysis'] as Record<string, unknown> | null;
      if (script?.['isObfuscated'] === true) staticScore += 10;
      const scriptIndicators = (script?.['indicators'] as Array<Record<string, unknown>>) ?? [];
      const scriptCriticals = scriptIndicators.filter(i => i['severity'] === 'critical').length;
      staticScore += scriptCriticals * 5;

      // High-confidence malicious string patterns (not generic API names)
      const strings = sa['strings'];
      if (Array.isArray(strings)) {
        const vals = strings.map((s: Record<string, unknown>) => String(s['value'] ?? '').toLowerCase());
        const malwareKeywords = [
          'ransom', 'encrypt', 'decrypt', 'bitcoin', 'wallet', 'payment',
          'shadowcopy', 'vssadmin', 'bcdedit', 'recoveryenabled',
          '.onion', 'tor2web', 'torproject',
          'createremotethread', 'writeprocessmemory', 'ntunmapviewofsection',
        ];
        let kwHits = 0;
        for (const kw of malwareKeywords) {
          if (vals.some((v: string) => v.includes(kw))) kwHits++;
        }
        staticScore += Math.min(kwHits * 4, 12);
      }

      staticScore = Math.min(staticScore, 25);
    }

    // ── 5. CVE / KEV / Tech debt — scored AFTER vendor cap (vuln risk persists regardless of signature)
    let hasKev = false;
    let maxEpss = 0;
    const cveRes = await pool.query(
      `SELECT raw_response FROM threat_intel_results WHERE submission_id = $1 AND provider = 'cve-lookup'`,
      [submissionId],
    );
    if (cveRes.rows.length > 0) {
      const raw = (cveRes.rows[0] as Record<string, unknown>)['raw_response'] as Record<string, unknown> | null;
      const cves = (raw?.['cves'] as Array<Record<string, unknown>>) ?? [];
      hasKev = cves.some(c => c['isKev'] === true);
      const maxCvss = Math.max(0, ...cves.map(c => { const n = Number(c['cvssScore'] ?? 0); return Number.isFinite(n) ? n : 0; }));
      maxEpss = Math.max(0, ...cves.map(c => { const n = Number(c['epssScore'] ?? 0); return Number.isFinite(n) ? n : 0; }));
      if (hasKev) vulnScore += 25;
      else if (maxCvss >= 9.0) vulnScore += 18;
      else if (maxCvss >= 8.0) vulnScore += 15;
      else if (maxCvss >= 7.0) vulnScore += 12;
      else if (maxCvss >= 4.0) vulnScore += 6;
      else if (cves.length > 0) vulnScore += 3;
      // EPSS: 4 tiers to avoid cliff at 10% (NPP's 9.1% was falling through)
      if (maxEpss >= 0.5) vulnScore += 5;
      else if (maxEpss >= 0.25) vulnScore += 4;
      else if (maxEpss >= 0.05) vulnScore += 3;
      else if (maxEpss >= 0.01) vulnScore += 1;
    }
    const tdRes = await pool.query(
      `SELECT raw_response FROM threat_intel_results WHERE submission_id = $1 AND provider = 'tech-debt'`,
      [submissionId],
    );
    if (tdRes.rows.length > 0) {
      const raw = (tdRes.rows[0] as Record<string, unknown>)['raw_response'] as Record<string, unknown> | null;
      if (raw?.['isEol'] === true) vulnScore += 5;
      else if (Number(raw?.['majorsBehind'] ?? 0) >= 2) vulnScore += 3;
      else if (Number(raw?.['majorsBehind'] ?? 0) >= 1) vulnScore += 1;
    }
    vulnScore = Math.min(vulnScore, 35);
    if (hasValidVendorSig && vtClean) {
      // Raised from 25 → 30 so EPSS bonus differentiates KEV from non-KEV
      vulnScore = Math.min(vulnScore, 30);
    }

    // ── 6. Domain trust scoring ─────────────────────────────────────────
    let trustedDomainRatio = 0;
    let untrustedIocCount = 0;
    try {
      const iocRes = await pool.query(
        `SELECT count(*) FILTER (WHERE confidence <= 15) AS trusted,
                count(*) AS total
         FROM iocs WHERE submission_id = $1 AND type IN ('url', 'domain')`,
        [submissionId],
      );
      const r = iocRes.rows[0] as Record<string, unknown> | undefined;
      const trusted = Number(r?.['trusted'] ?? 0);
      const total = Number(r?.['total'] ?? 0);
      trustedDomainRatio = total > 0 ? trusted / total : 0;
      untrustedIocCount = total - trusted;
    } catch { /* ignore */ }

    // ── [P1-R5] Novelty multiplier ─
    // VT clean across 40+ engines is strong consensus — dampen sandbox/YARA noise.
    // Only amplify when VT was never scanned (true unknowns).
    const noveltyMultiplier = !vtScanned ? 1.3 : 1.0;
    const vtCleanDampener = (vtScanned && vtClean) ? 0.5 : 1.0;
    const adjustedSandbox = Math.min(Math.round(sandboxScore * noveltyMultiplier * vtCleanDampener), 65);
    const adjustedYara = Math.min(Math.round(yaraScore * noveltyMultiplier), 50);

    let score = vtScore + adjustedYara + adjustedSandbox + staticScore;

    // [P0-R2] Neutralize VT clean penalty only when sandbox shows genuinely
    // dangerous behavioral categories (not just packing/entropy/filename noise)
    if (vtClean && behavioralSandboxScore >= 40) {
      score += 15;
      logger.info({ submissionId, behavioralSandboxScore }, 'VT clean but high genuine behavioral risk — neutralizing VT penalty');
    }

    // [P0-R1] Vendor signature cap — tiered based on genuine behavioral severity
    // Use behavioralSandboxScore (excludes YARA-sourced indicators) so that YARA FPs
    // on signed binaries don't bypass the vendor trust cap.
    // Include vtScore ≤ 5 so 1-2 engine FP detections on signed binaries still get capped.
    const behScore = behavioralSandboxScore;
    if (hasValidVendorSig && (vtClean || (vtScanned && vtScore <= 5))) {
      if (behScore >= 35) {
        logger.warn({ submissionId, sandboxScore, behavioralSandboxScore: behScore }, 'Signed binary with critical behavioral signals — vendor cap bypassed');
      } else if (behScore >= 15) {
        const capped = Math.min(score, 30);
        logger.info({ submissionId, originalScore: score, cappedScore: capped, behavioralSandboxScore: behScore }, 'Valid vendor signature with moderate behavior — soft cap at 30');
        score = capped;
      } else {
        const capped = Math.min(score, 10);
        logger.info({ submissionId, originalScore: score, cappedScore: capped, behavioralSandboxScore: behScore }, 'Valid vendor signature — capping malware score');
        score = capped;
      }
    }

    // [P0-R2] Clean VT pull-down — VT consensus of 0 detections across 40+ engines
    // is very strong signal. Cap unsigned binaries with clean VT unless sandbox
    // found genuinely critical behavioral evidence.
    if (vtClean && !hasValidVendorSig) {
      if (behavioralSandboxScore < 15) {
        const capped = Math.min(score, 15);
        logger.info({ submissionId, originalScore: score, cappedScore: capped, behavioralSandboxScore: behScore }, 'Unsigned but VT clean with low behavioral risk — capping at 15');
        score = capped;
      } else if (behavioralSandboxScore < 35) {
        const capped = Math.min(score, 35);
        logger.info({ submissionId, originalScore: score, cappedScore: capped, behavioralSandboxScore: behScore }, 'Unsigned but VT clean with moderate behavioral risk — capping at 35');
        score = capped;
      }
    }

    // Domain trust reduction — doesn't apply when KEV or when untrusted IOC count is high
    if (trustedDomainRatio >= 0.7 && !hasKev && untrustedIocCount <= 3) {
      score = Math.round(score * 0.6);
    } else if (trustedDomainRatio >= 0.4 && !hasKev && untrustedIocCount <= 5) {
      score = Math.round(score * 0.8);
    }

    // Add vuln score AFTER trust reductions
    score += vulnScore;

    // [P0-R3] Behavioral override floor: critical sandbox categories guarantee MEDIUM minimum
    // Only count categories from genuine behavioral indicators, not YARA-sourced ones.
    if (sandboxScore >= 35 && dyn) {
      const mem = dyn['memory_activity'] as Record<string, unknown> | null;
      const allInds = (mem?.['suspiciousIndicators'] as Array<Record<string, unknown>>) ?? [];
      const behInds = allInds.filter(i => {
        const desc = String(i['description'] ?? '');
        const cat = String(i['category'] ?? '');
        return !desc.startsWith('YARA:') && cat !== 'yara-binary';
      });
      const behCats = new Set(behInds.map(i => String(i['category'] ?? '')));
      if ((behCats.has('ransomware') || behCats.has('c2_communication') || behCats.has('reverse_shell')) && score < 55) {
        logger.info({ submissionId, categories: [...behCats], score }, 'Critical behavioral category — applying MEDIUM floor at 55');
        score = 55;
      }
    }

    // [P1-R6] KEV + EPSS stacking floor
    // Gate: only enforce the hard HIGH floor when there is corroborating malicious
    // evidence. Vendor-signed + VT-clean software with KEV CVEs is outdated legit
    // software, not malware — the vuln score already accounts for the risk.
    const kevHasCorroboration = !(hasValidVendorSig && vtClean);
    if (hasKev && kevHasCorroboration && maxEpss >= 0.5 && score < 75) {
      score = 75;
    } else if (hasKev && kevHasCorroboration && score < 70) {
      logger.info({ submissionId, preKevFloor: score }, 'KEV vulnerability — automatic HIGH floor at 70');
      score = 70;
    } else if (hasKev && !kevHasCorroboration) {
      // KEV on signed+clean: not malware, but CISA BOD 22-01 mandates remediation.
      // EPSS ≥ 5% (e.g. NPP's 9.1%) = confirmed active exploitation → solid MEDIUM.
      if (maxEpss >= 0.05 && score < 50) {
        logger.info({ submissionId, preKevFloor: score, maxEpss }, 'KEV + high EPSS on signed+clean — MEDIUM floor at 50');
        score = 50;
      } else if (score < 40) {
        logger.info({ submissionId, preKevFloor: score }, 'KEV on signed+clean software — MEDIUM floor at 40');
        score = 40;
      }
    } else if (maxEpss >= 0.9 && score < 50) {
      score = 50;
    }

    logger.info(
      { submissionId, vtScore, adjustedSandbox, adjustedYara, staticScore, vulnScore, hasKev, maxEpss, hasValidVendorSig, vtClean, sandboxScore, noveltyMultiplier, finalScore: Math.min(100, Math.max(0, score)) },
      'Threat score breakdown',
    );

    return Math.min(100, Math.max(0, score));
  } catch (err) {
    logger.error({ err }, 'Error computing threat score');
    return 0;
  }
}

// ── MITRE ATT&CK Mapping ────────────────────────────────────────────────────

interface TechniqueMapping {
  readonly tacticId: string;
  readonly techniqueId: string;
  readonly evidence: string;
  readonly confidence: number;
}

async function mapAttackTechniques(
  pool: pg.Pool,
  submissionId: string,
  result: Record<string, unknown>,
): Promise<void> {
  const techniques: TechniqueMapping[] = [];

  // The dynamic analysis result may be wrapped in a 'report' field
  const report = (result['report'] as Record<string, unknown>) ?? result;
  const extractedFiles = (report['extractedFiles'] ?? result['extractedFiles']) as Array<Record<string, unknown>> | undefined;
  const straceAnalysis = (report['straceAnalysis'] ?? result['straceAnalysis']) as Record<string, unknown> | undefined;
  const wineRegChanges = (report['wineRegistryChanges'] ?? result['wineRegistryChanges']) as Record<string, unknown> | undefined;
  const indicators = (report['suspiciousIndicators'] ?? result['suspiciousIndicators']) as Array<Record<string, unknown>> | undefined;
  const sampleType = String(report['sampleType'] ?? result['sampleType'] ?? '');

  // ── Archive with PE inside → T1036.008 (Masquerading: Masquerade File Type)
  if (sampleType.toLowerCase().includes('archive') && Array.isArray(extractedFiles)) {
    const hasPE = extractedFiles.some(f => f['isPE'] === true);
    if (hasPE) {
      techniques.push({
        tacticId: 'defense-evasion',
        techniqueId: 'T1036.008',
        evidence: 'PE executable found inside archive file — masquerading file type',
        confidence: 75,
      });
    }
  }

  if (Array.isArray(extractedFiles)) {
    for (const ef of extractedFiles) {
      const sections = ef['sections'] as Array<Record<string, unknown>> | undefined;
      const fileEntropy = typeof ef['entropy'] === 'number' ? ef['entropy'] : 0;
      const suspStrings = ef['suspiciousStrings'] as string[] | undefined;

      // ── UPX packing → T1027.002 (Software Packing)
      if (Array.isArray(sections)) {
        const upxSections = sections.filter(s => /UPX/i.test(String(s['name'] ?? '')));
        if (upxSections.length > 0) {
          techniques.push({
            tacticId: 'defense-evasion',
            techniqueId: 'T1027.002',
            evidence: `UPX packer sections detected: ${upxSections.map(s => String(s['name'])).join(', ')}`,
            confidence: 90,
          });
        }
        // Other packers
        const otherPackers = sections.filter(s => /aspack|themida|vmprotect|pecompact|mpress/i.test(String(s['name'] ?? '')));
        if (otherPackers.length > 0) {
          techniques.push({
            tacticId: 'defense-evasion',
            techniqueId: 'T1027.002',
            evidence: `Packer sections detected: ${otherPackers.map(s => String(s['name'])).join(', ')}`,
            confidence: 85,
          });
        }
      }

      // ── High entropy sections → T1027 (Obfuscated Files or Information)
      // Threshold raised to 7.7: normal PE files with compressed resources are 7.0-7.7
      if (fileEntropy > 7.7) {
        techniques.push({
          tacticId: 'defense-evasion',
          techniqueId: 'T1027',
          evidence: `High file entropy (${fileEntropy.toFixed(2)}) indicates obfuscation or encryption`,
          confidence: fileEntropy > 7.9 ? 85 : 70,
        });
      }

      // ── Credential file access → T1003 (OS Credential Dumping)
      if (Array.isArray(suspStrings)) {
        const credStrings = suspStrings.filter(s => {
          const sl = s.toLowerCase();
          return sl.includes('/etc/passwd') || sl.includes('/etc/shadow') || sl.includes('sam') ||
                 sl.includes('credential') || sl.includes('lsass') || sl.includes('mimikatz') ||
                 sl.includes('sekurlsa') || sl.includes('logonpasswords');
        });
        if (credStrings.length > 0) {
          techniques.push({
            tacticId: 'credential-access',
            techniqueId: 'T1003',
            evidence: `Credential access strings found: ${credStrings.slice(0, 3).join(', ')}`,
            confidence: 75,
          });
        }

        // ── Shadow copy deletion → T1490 (Inhibit System Recovery)
        const recoveryStrings = suspStrings.filter(s => {
          const sl = s.toLowerCase();
          return sl.includes('vssadmin') || sl.includes('delete shadows') || sl.includes('bcdedit') ||
                 sl.includes('recoveryenabled') || sl.includes('wbadmin');
        });
        if (recoveryStrings.length > 0) {
          techniques.push({
            tacticId: 'impact',
            techniqueId: 'T1490',
            evidence: `System recovery inhibition strings: ${recoveryStrings.slice(0, 3).join(', ')}`,
            confidence: 85,
          });
        }

        // ── Encryption indicators → T1486 (Data Encrypted for Impact)
        const encryptStrings = suspStrings.filter(s => {
          const sl = s.toLowerCase();
          return sl.includes('ransom') || sl.includes('your files') || sl.includes('locked') ||
                 sl.includes('payment') || sl.includes('bitcoin') || sl.includes('wallet') ||
                 sl.includes('decrypt');
        });
        if (encryptStrings.length >= 2) {
          techniques.push({
            tacticId: 'impact',
            techniqueId: 'T1486',
            evidence: `Encryption/ransom indicators: ${encryptStrings.slice(0, 5).join(', ')}`,
            confidence: 80,
          });
        }

        // ── Process injection indicators → T1055 (Process Injection)
        const injectionStrings = suspStrings.filter(s => {
          const sl = s.toLowerCase();
          return sl.includes('createremotethread') || sl.includes('virtualalloc') ||
                 sl.includes('writeprocessmemory') || sl.includes('ntunmapviewofsection') ||
                 sl.includes('openprocess') || sl.includes('injection');
        });
        if (injectionStrings.length > 0) {
          techniques.push({
            tacticId: 'defense-evasion',
            techniqueId: 'T1055',
            evidence: `Process injection API calls: ${injectionStrings.slice(0, 3).join(', ')}`,
            confidence: 80,
          });
        }
      }

      // ── Registry Run key strings → T1547.001 (Registry Run Keys)
      const regKeys = ef['registryKeys'] as string[] | undefined;
      if (Array.isArray(regKeys)) {
        const runKeys = regKeys.filter(k => /CurrentVersion\\\\Run|RunOnce|Startup/i.test(k));
        if (runKeys.length > 0) {
          techniques.push({
            tacticId: 'persistence',
            techniqueId: 'T1547.001',
            evidence: `Registry Run key references: ${runKeys.slice(0, 3).join(', ')}`,
            confidence: 80,
          });
        }
      }
    }
  }

  // ── Network connection attempts → T1071 (Application Layer Protocol)
  const netActivity = result['networkActivity'] as Record<string, unknown> | undefined;
  const connections = netActivity?.['connections'] as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(connections) && connections.length > 0) {
    const externalConns = connections.filter(c => {
      const ip = String(c['destinationAddress'] ?? c['destinationIp'] ?? '');
      return ip && !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)/.test(ip);
    });
    if (externalConns.length > 0) {
      techniques.push({
        tacticId: 'command-and-control',
        techniqueId: 'T1071',
        evidence: `${externalConns.length} external network connections detected`,
        confidence: 70,
      });
    }
  }

  // ── DNS queries → T1071.004 (DNS)
  const dnsQueries = netActivity?.['dnsQueries'] as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(dnsQueries) && dnsQueries.length > 0) {
    techniques.push({
      tacticId: 'command-and-control',
      techniqueId: 'T1071.004',
      evidence: `${dnsQueries.length} DNS queries during execution: ${dnsQueries.slice(0, 3).map(d => String(d['domain'])).join(', ')}`,
      confidence: 65,
    });
  }

  // ── Strace-detected external connections → T1071
  if (straceAnalysis) {
    const straceExternalIPs = straceAnalysis['externalIPs'] as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(straceExternalIPs) && straceExternalIPs.length > 0) {
      techniques.push({
        tacticId: 'command-and-control',
        techniqueId: 'T1071',
        evidence: `Strace detected ${straceExternalIPs.length} external IP connections: ${straceExternalIPs.slice(0, 3).map(e => `${String(e['ip'])}:${String(e['port'])}`).join(', ')}`,
        confidence: 80,
      });
    }

    // ── Strace execve calls → T1059 (Command and Scripting Interpreter)
    const execCmds = straceAnalysis['execCommands'] as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(execCmds) && execCmds.length > 2) {
      const shellCmds = execCmds.filter(c => {
        const exe = String(c['executable'] ?? '').toLowerCase();
        return exe.includes('sh') || exe.includes('bash') || exe.includes('cmd') ||
               exe.includes('powershell') || exe.includes('python') || exe.includes('wscript');
      });
      if (shellCmds.length > 0) {
        techniques.push({
          tacticId: 'execution',
          techniqueId: 'T1059',
          evidence: `${shellCmds.length} scripting interpreter invocations: ${shellCmds.slice(0, 3).map(c => String(c['executable'])).join(', ')}`,
          confidence: 70,
        });
      }
    }
  }

  // ── File drops → T1105 (Ingress Tool Transfer)
  const droppedFiles = result['droppedFiles'] as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(droppedFiles) && droppedFiles.length > 0) {
    const suspiciousDrops = droppedFiles.filter(d => d['isSuspiciousLocation'] === true);
    if (suspiciousDrops.length > 0) {
      techniques.push({
        tacticId: 'command-and-control',
        techniqueId: 'T1105',
        evidence: `${suspiciousDrops.length} files dropped in suspicious locations: ${suspiciousDrops.slice(0, 3).map(d => String(d['path'])).join(', ')}`,
        confidence: 75,
      });
    }
  }

  // ── Wine registry Run key modifications → T1547.001
  if (wineRegChanges) {
    const allChanges = [
      ...(Array.isArray(wineRegChanges['system']) ? wineRegChanges['system'] as string[] : []),
      ...(Array.isArray(wineRegChanges['user']) ? wineRegChanges['user'] as string[] : []),
    ];
    const runKeyMods = allChanges.filter(c => typeof c === 'string' && /Run|RunOnce|Startup/i.test(c));
    if (runKeyMods.length > 0) {
      techniques.push({
        tacticId: 'persistence',
        techniqueId: 'T1547.001',
        evidence: `Wine registry Run key modifications: ${runKeyMods.slice(0, 3).join('; ')}`,
        confidence: 85,
      });
    }
  }

  // ── Cron/scheduled task indicators → T1053.003
  if (Array.isArray(indicators)) {
    const cronIndicators = indicators.filter(ind => {
      const desc = String(ind['description'] ?? '').toLowerCase();
      return desc.includes('cron') || desc.includes('scheduled') || desc.includes('crontab');
    });
    if (cronIndicators.length > 0) {
      techniques.push({
        tacticId: 'persistence',
        techniqueId: 'T1053.003',
        evidence: `Cron/scheduled task modification: ${cronIndicators.slice(0, 2).map(i => String(i['description'])).join('; ')}`,
        confidence: 80,
      });
    }
  }

  // Deduplicate by technique ID and insert
  const seenTechniques = new Set<string>();
  for (const tech of techniques) {
    if (seenTechniques.has(tech.techniqueId)) continue;
    seenTechniques.add(tech.techniqueId);
    await pool.query(
      `INSERT INTO attack_techniques (submission_id, tactic_id, technique_id, evidence, confidence)
       VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
      [submissionId, tech.tacticId, tech.techniqueId, JSON.stringify({ description: tech.evidence }), tech.confidence],
    );
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async function updateSubmissionStatus(
  pool: pg.Pool,
  submissionId: string,
  status: string,
): Promise<void> {
  await pool.query(
    `UPDATE submissions SET status = $1::submission_status WHERE id = $2`,
    [status, submissionId],
  );
}

// ── CVE/CISA KEV/EPSS Vulnerability Lookup ──────────────────────────────────

/**
 * After sandbox extraction, reads PE version info (ProductName, FileVersion)
 * from the extracted files and queries NVD, CISA KEV, and EPSS APIs for
 * known vulnerabilities. Stores results in threat_intel_results with
 * provider='cve-lookup'.
 */
async function lookupVulnerabilitiesFromPeMetadata(ctx: WorkflowContext): Promise<void> {
  const { submissionId, pool, logger } = ctx;

  try {
    // Read extracted file analysis from dynamic_analysis_results
    const dynRes = await pool.query(
      'SELECT memory_activity FROM dynamic_analysis_results WHERE submission_id = $1',
      [submissionId],
    );
    const dynRow = dynRes.rows[0] as Record<string, unknown> | undefined;
    if (!dynRow) return;

    const memActivity = dynRow?.['memory_activity'] as Record<string, unknown> | null;
    const extractedFiles = memActivity?.['extractedFiles'] as Array<Record<string, unknown>> | undefined;

    // Collect version info from PE files
    const versionInfoEntries: PeVersionInfo[] = [];
    if (extractedFiles) {
      for (const ef of extractedFiles) {
        const versionInfo = ef['versionInfo'] as Record<string, string> | undefined;
        if (versionInfo && (versionInfo['ProductName'] || versionInfo['FileDescription'])) {
          versionInfoEntries.push(versionInfo as PeVersionInfo);
        }
      }
    }

    // Fallback: read version info from static analysis PE parsing
    if (versionInfoEntries.length === 0) {
      const saRes = await pool.query(
        'SELECT pe_analysis FROM static_analysis_results WHERE submission_id = $1',
        [submissionId],
      );
      const saRow = saRes.rows[0] as Record<string, unknown> | undefined;
      const peAnalysis = saRow?.['pe_analysis'] as Record<string, unknown> | null;
      const vi = peAnalysis?.['versionInfo'] as Record<string, string> | undefined;
      if (vi && (vi['ProductName'] || vi['FileDescription'])) {
        versionInfoEntries.push(vi as PeVersionInfo);
      }
    }

    if (versionInfoEntries.length === 0) return;

    logger.info(
      { submissionId, count: versionInfoEntries.length },
      'Looking up CVEs for PE version info',
    );

    // Process each unique product (deduplicate by product name + version)
    const seen = new Set<string>();
    for (const vInfo of versionInfoEntries.slice(0, 3)) {
      const product = vInfo.ProductName ?? vInfo.FileDescription ?? '';
      const version = vInfo.FileVersion ?? vInfo.ProductVersion ?? '';
      const key = `${product}|${version}`.toLowerCase();
      if (seen.has(key) || !product) continue;
      seen.add(key);

      try {
        const vulnResult: VulnResult = await lookupVulnerabilities(vInfo);

        if (vulnResult.cves.length > 0) {
          logger.info(
            { submissionId, product, version, cveCount: vulnResult.cves.length },
            'Found CVEs for software',
          );

          // Store in threat_intel_results with provider='cve-lookup'
          await pool.query(
            `INSERT INTO threat_intel_results (submission_id, provider, verdict, detection_count, total_engines, malware_family, raw_response)
             VALUES ($1, 'cve-lookup', $2, $3, $4, $5, $6)
             ON CONFLICT DO NOTHING`,
            [
              submissionId,
              vulnResult.cves.some(c => c.isKev) ? 'vulnerable-kev' : 'vulnerable',
              vulnResult.cves.length,
              vulnResult.cves.length,
              vulnResult.softwareName,
              JSON.stringify(vulnResult),
            ],
          );
        }
      } catch (err) {
        logger.warn({ err, product, version }, 'CVE lookup failed for product');
      }

      // Rate limit: NVD API allows ~5 requests per 30 seconds without a key
      await new Promise(resolve => setTimeout(resolve, 6_500));
    }
  } catch (err) {
    logger.warn({ err }, 'lookupVulnerabilitiesFromPeMetadata failed');
  }
}

// ── Tech Debt / End-of-Life Version Check ─────────────────────────────────────

/**
 * After CVE lookup, checks if the software version is outdated by querying
 * endoflife.date. Stores results in threat_intel_results with provider='tech-debt'.
 */
async function lookupTechDebtFromPeMetadata(ctx: WorkflowContext): Promise<void> {
  const { submissionId, pool, logger } = ctx;

  try {
    let versionInfo: Record<string, string> | undefined;

    const dynRes = await pool.query(
      'SELECT memory_activity FROM dynamic_analysis_results WHERE submission_id = $1',
      [submissionId],
    );
    const dynRow = dynRes.rows[0] as Record<string, unknown> | undefined;
    const memActivity = dynRow?.['memory_activity'] as Record<string, unknown> | null;
    const extractedFiles = memActivity?.['extractedFiles'] as Array<Record<string, unknown>> | undefined;
    if (extractedFiles) {
      for (const ef of extractedFiles) {
        const vi = ef['versionInfo'] as Record<string, string> | undefined;
        if (vi && (vi['ProductName'] || vi['FileDescription'])) {
          versionInfo = vi;
          break;
        }
      }
    }

    // Fallback: read version info from static analysis PE parsing
    if (!versionInfo) {
      const saRes = await pool.query(
        'SELECT pe_analysis FROM static_analysis_results WHERE submission_id = $1',
        [submissionId],
      );
      const saRow = saRes.rows[0] as Record<string, unknown> | undefined;
      const peAnalysis = saRow?.['pe_analysis'] as Record<string, unknown> | null;
      const vi = peAnalysis?.['versionInfo'] as Record<string, string> | undefined;
      if (vi && (vi['ProductName'] || vi['FileDescription'])) {
        versionInfo = vi;
      }
    }

    if (versionInfo) {
      const productName = versionInfo['ProductName'] ?? versionInfo['FileDescription'] ?? '';
      const version = versionInfo['FileVersion'] ?? versionInfo['ProductVersion'] ?? '';
      if (!productName || !version) return;

      // Clean version
      const cleanVersion = version.replace(/[,\s]+/g, '.').replace(/\.+/g, '.').split('.').slice(0, 3).join('.');

      logger.info({ submissionId, productName, cleanVersion }, 'Checking tech debt for product');

      const result: TechDebtResult | null = await lookupTechDebt(productName, cleanVersion);
      if (!result) {
        logger.info({ submissionId, productName }, 'No endoflife.date data found for product');
      } else {
        logger.info(
          { submissionId, productName, installedVersion: result.installedVersion, latestVersion: result.latestVersion, majorsBehind: result.majorsBehind, isEol: result.isEol },
          'Tech debt check result',
        );

        const verdict = result.isEol ? 'eol'
          : result.majorsBehind != null && result.majorsBehind >= 2 ? 'outdated-critical'
          : result.majorsBehind === 1 ? 'outdated'
          : 'current';

        await pool.query(
          `INSERT INTO threat_intel_results (submission_id, provider, verdict, detection_count, total_engines, malware_family, raw_response)
           VALUES ($1, 'tech-debt', $2, $3, $4, $5, $6)
           ON CONFLICT DO NOTHING`,
          [
            submissionId,
            verdict,
            0,
            0,
            result.productName,
            JSON.stringify(result),
          ],
        );
      }
    }
  } catch (err) {
    logger.warn({ err }, 'lookupTechDebtFromPeMetadata failed');
  }
}

// ── Config Extraction Indicators ──────────────────────────────────────────────

/**
 * After YARA matches and threat intel, if a known malware family is detected,
 * store a config_extraction IOC indicator to flag the sample for manual analysis.
 */
async function storeConfigExtractionIndicators(ctx: WorkflowContext): Promise<void> {
  const { submissionId, pool, logger } = ctx;

  const knownFamilies = [
    'cobalt strike', 'cobaltstrike', 'beacon',
    'emotet', 'trickbot', 'qakbot', 'qbot',
    'icedid', 'bazarloader', 'bazar',
    'dridex', 'agenttesla', 'agent tesla',
    'formbook', 'lokibot', 'remcos',
    'njrat', 'asyncrat', 'darkcomet',
    'metasploit', 'meterpreter',
  ];

  try {
    // Check threat_intel_results for known families
    const tiRes = await pool.query(
      'SELECT malware_family FROM threat_intel_results WHERE submission_id = $1 AND malware_family IS NOT NULL',
      [submissionId],
    );

    let detectedFamily: string | null = null;
    for (const row of tiRes.rows as Array<Record<string, string>>) {
      const family = (row['malware_family'] ?? '').toLowerCase();
      const match = knownFamilies.find(kf => family.includes(kf));
      if (match) {
        detectedFamily = row['malware_family'] ?? null;
        break;
      }
    }

    if (!detectedFamily) return;

    logger.info({ submissionId, detectedFamily }, 'Known malware family detected, storing config extraction indicator');

    await pool.query(
      `INSERT INTO iocs (submission_id, type, value, context, confidence)
       VALUES ($1, 'config_extraction', $2, $3, $4)
       ON CONFLICT DO NOTHING`,
      [
        submissionId,
        `${detectedFamily} - Configuration data likely embedded`,
        `Known malware family "${detectedFamily}" detected. Manual config extraction recommended using CAPE sandbox or family-specific tools.`,
        75,
      ],
    );
  } catch (err) {
    logger.warn({ err }, 'storeConfigExtractionIndicators failed');
  }
}

// ── CPE Classification from PE Metadata ──────────────────────────────────────

/**
 * Queries the NVD CPE API to classify the software from its PE metadata,
 * storing the classification in threat_intel_results.
 */
async function classifyApplicationFromPeMetadata(ctx: WorkflowContext): Promise<void> {
  const { submissionId, pool, logger } = ctx;

  try {
    let versionInfo: Record<string, string> | undefined;

    // Try dynamic analysis extractedFiles first
    const dynRes = await pool.query(
      'SELECT memory_activity FROM dynamic_analysis_results WHERE submission_id = $1',
      [submissionId],
    );
    const dynRow = dynRes.rows[0] as Record<string, unknown> | undefined;
    const memActivity = dynRow?.['memory_activity'] as Record<string, unknown> | null;
    const extractedFiles = memActivity?.['extractedFiles'] as Array<Record<string, unknown>> | undefined;
    if (extractedFiles) {
      const peFile = extractedFiles.find(f => f['isPE'] === true);
      versionInfo = peFile?.['versionInfo'] as Record<string, string> | undefined;
    }

    // Fallback: read version info from static analysis PE parsing
    if (!versionInfo) {
      const saRes = await pool.query(
        'SELECT pe_analysis FROM static_analysis_results WHERE submission_id = $1',
        [submissionId],
      );
      const saRow = saRes.rows[0] as Record<string, unknown> | undefined;
      const peAnalysis = saRow?.['pe_analysis'] as Record<string, unknown> | null;
      versionInfo = peAnalysis?.['versionInfo'] as Record<string, string> | undefined;
    }

    const productName = versionInfo?.['ProductName'] ?? versionInfo?.['InternalName'] ?? '';
    const version = versionInfo?.['FileVersion'] ?? versionInfo?.['ProductVersion'] ?? '';

    if (!productName || productName.length < 2) return;

    const classification = await classifyApplicationFromCpe(productName, version);
    if (!classification) return;

    await storeCpeClassification(pool, submissionId, classification);

    logger.info(
      { submissionId, product: productName, classification: classification.classification },
      'CPE classification stored',
    );
  } catch (err) {
    logger.warn({ err }, 'classifyApplicationFromPeMetadata failed');
  }
}

// ── Config Extraction (Real) ─────────────────────────────────────────────────

/**
 * After family identification, attempts real config extraction using the
 * Python script from config-extractor module. If dynamic analysis produced
 * configExtractionOutput, parse and store it. Otherwise, attempt host-side
 * extraction from suspicious strings.
 */
async function performConfigExtraction(
  ctx: WorkflowContext,
  dynamicResult: StepResult | null,
): Promise<void> {
  const { submissionId, pool, logger } = ctx;

  try {
    // Check if dynamic analysis produced config extraction output
    if (dynamicResult && dynamicResult.status === JobStatus.Completed) {
      const configOutput = dynamicResult.result['configExtractionOutput'] as string | undefined;
      if (configOutput) {
        const parsed = parseConfigExtractionOutput(configOutput);
        if (parsed.success && parsed.config) {
          await storeExtractedConfig(pool, submissionId, parsed.config, logger);
          return;
        }
      }
    }

    // Fallback: host-side string-based extraction
    // Get the detected family
    const tiRes = await pool.query(
      'SELECT malware_family FROM threat_intel_results WHERE submission_id = $1 AND malware_family IS NOT NULL',
      [submissionId],
    );

    let detectedFamily = '';
    for (const row of tiRes.rows as Array<Record<string, string>>) {
      const family = row['malware_family'] ?? '';
      if (family) { detectedFamily = family; break; }
    }

    if (!detectedFamily) return;

    // Get suspicious strings from static analysis
    const stringsRes = await pool.query(
      'SELECT strings FROM static_analysis_results WHERE submission_id = $1',
      [submissionId],
    );
    const stringsRow = stringsRes.rows[0] as Record<string, unknown> | undefined;
    if (!stringsRow) return;

    const rawStrings = stringsRow['strings'] as Array<{ value: string }> | null;
    if (!rawStrings || rawStrings.length === 0) return;

    const suspiciousStrings = rawStrings.map(s => s.value);

    // Attempt host-side extraction (from string analysis only)
    const config = await extractMalwareConfig(
      Buffer.alloc(0), // We don't have the file buffer here; string-based extraction only
      detectedFamily,
      suspiciousStrings,
    );

    if (config) {
      await storeExtractedConfig(pool, submissionId, config, logger);
    }
  } catch (err) {
    logger.warn({ err }, 'performConfigExtraction failed');
  }
}

// ── YARA Pattern Match Results Storage ──────────────────────────────────────

/**
 * After dynamic analysis, extracts YARA scan results from the detonation
 * report and stores them in yara_scan_results. Three data sources, tried in order:
 *   1. memory_activity.yaraPatternOutput — raw JSON from the built-in pattern scanner (step g5)
 *   2. memory_activity.yaraPatternMatches / report.yaraPatternMatches — parsed pattern matches
 *   3. memory_activity.yaraBinaryMatches / report.yaraBinaryMatches — community YARA binary hits (step g6)
 * All three are populated by the dynamic-analysis executor, stored in DB at index.ts:578.
 */
async function storeYaraPatternResults(
  ctx: WorkflowContext,
  dynamicResult: StepResult | null,
): Promise<void> {
  const { submissionId, pool, logger } = ctx;

  if (!dynamicResult || dynamicResult.status !== JobStatus.Completed) return;

  try {
    // Read the dynamic analysis results to get yaraPatternMatches
    const dynRes = await pool.query(
      'SELECT memory_activity FROM dynamic_analysis_results WHERE submission_id = $1',
      [submissionId],
    );
    const dynRow = dynRes.rows[0] as Record<string, unknown> | undefined;
    if (!dynRow) return;

    const memActivity = dynRow['memory_activity'] as Record<string, unknown> | null;
    const yaraPatternMatches = memActivity?.['yaraPatternMatches'] as Array<Record<string, unknown>> | undefined;

    // Also check the dynamicResult directly (the report from the executor)
    const report = dynamicResult.result;
    const reportMatches = report['yaraPatternMatches'] as Array<Record<string, unknown>> | undefined;

    // Try to find YARA results in memory_activity or the raw report
    // The executor writes a full JSON output that we may have stored
    const rawYaraOutput = memActivity?.['yaraPatternOutput'] as string | undefined;

    if (rawYaraOutput) {
      // Parse the raw scanner output and store
      const scanOutputs = parseYaraScanOutput(rawYaraOutput);
      if (scanOutputs.length > 0) {
        await storeYaraResults(pool, submissionId, scanOutputs, logger);
        return;
      }
    }

    // Fallback: store from the parsed matches already in the report
    const matches = yaraPatternMatches ?? reportMatches ?? [];
    if (matches.length === 0) return;

    logger.info({ submissionId, matchCount: matches.length }, 'Storing YARA pattern matches');

    for (const match of matches) {
      const ruleName = String(match['ruleName'] ?? 'unknown');
      const category = String(match['category'] ?? 'unknown');
      const description = String(match['description'] ?? '');
      const severity = String(match['severity'] ?? 'medium');
      const matchedStrings = match['matchedStrings'] as string[] | undefined;

      try {
        // Upsert the rule into yara_rules
        const ruleResult = await pool.query<{ id: string }>(
          `INSERT INTO yara_rules (name, description, content, category, author, is_active)
           VALUES ($1, $2, $3, $4, 'scanboy-builtin', TRUE)
           ON CONFLICT ON CONSTRAINT uq_yara_rules_name DO UPDATE SET match_count = yara_rules.match_count + 1
           RETURNING id`,
          [
            ruleName,
            description,
            `rule ${ruleName} { /* built-in pattern rule */ }`,
            category,
          ],
        );

        const ruleRow = ruleResult.rows[0];
        if (!ruleRow) continue;

        await pool.query(
          `INSERT INTO yara_scan_results (submission_id, rule_id, matched, match_details)
           VALUES ($1, $2, TRUE, $3)
           ON CONFLICT DO NOTHING`,
          [
            submissionId,
            ruleRow.id,
            JSON.stringify({
              severity,
              matchedStrings: matchedStrings ?? [],
              matchOffset: match['matchOffset'] ?? null,
            }),
          ],
        );
      } catch (err) {
        logger.warn({ err, ruleName }, 'Failed to store YARA pattern result');
      }
    }
    // Also store binary YARA matches (from the real yara binary scanner)
    const binaryMatches = (memActivity?.['yaraBinaryMatches'] ?? report['yaraBinaryMatches']) as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(binaryMatches) && binaryMatches.length > 0) {
      logger.info({ submissionId, binaryMatchCount: binaryMatches.length }, 'Storing YARA binary matches');
      for (const bm of binaryMatches) {
        const ruleName = String(bm['ruleName'] ?? 'unknown');
        const filePath = String(bm['filePath'] ?? '');
        const matchedStrings = (bm['matchedStrings'] as string[]) ?? [];
        const isRansomware = /ransom|crypt|lock|wanna|revil|ryuk|conti|hive|akira|phobos|dharma|maze|clop|medusa|redboot|wiper/i.test(ruleName);
        const isRat = /rat|backdoor|trojan|remote|shell|c2|beacon|cobalt|sliver|havoc|meterpreter|inject/i.test(ruleName);
        const severity = isRansomware ? 'critical' : isRat ? 'high' : 'medium';
        const category = isRansomware ? 'ransomware' : isRat ? 'technique' : 'packer';

        try {
          const ruleResult = await pool.query<{ id: string }>(
            `INSERT INTO yara_rules (name, description, content, category, author, is_active)
             VALUES ($1, $2, $3, $4, 'yara-binary', TRUE)
             ON CONFLICT ON CONSTRAINT uq_yara_rules_name DO UPDATE SET match_count = yara_rules.match_count + 1
             RETURNING id`,
            [ruleName, `Binary YARA match on ${filePath}`, `rule ${ruleName} { /* binary scanner */ }`, category],
          );
          const ruleRow = ruleResult.rows[0];
          if (!ruleRow) continue;

          await pool.query(
            `INSERT INTO yara_scan_results (submission_id, rule_id, matched, match_details)
             VALUES ($1, $2, TRUE, $3) ON CONFLICT DO NOTHING`,
            [submissionId, ruleRow.id, JSON.stringify({ severity, matchedStrings, filePath })],
          );
        } catch (err) {
          logger.warn({ err, ruleName }, 'Failed to store binary YARA result');
        }
      }
    }

  } catch (err) {
    logger.warn({ err }, 'storeYaraPatternResults failed');
  }
}

// ── VT Lookup on Extracted File Hashes ──────────────────────────────────────

async function lookupExtractedFileHashes(ctx: WorkflowContext): Promise<void> {
  const { submissionId, pool, logger } = ctx;
  const vtKey = process.env['VIRUSTOTAL_API_KEY'];
  if (!vtKey || vtKey.length < 10) return;

  try {
    const dynRes = await pool.query(
      'SELECT memory_activity FROM dynamic_analysis_results WHERE submission_id = $1',
      [submissionId],
    );
    const dynRow = dynRes.rows[0] as Record<string, unknown> | undefined;
    if (!dynRow) return;

    const memActivity = dynRow['memory_activity'] as Record<string, unknown> | null;
    const hashesToCheck: Array<{ hash: string; source: string }> = [];

    const extractedFiles = memActivity?.['extractedFiles'] as Array<Record<string, unknown>> | undefined;
    if (extractedFiles) {
      for (const f of extractedFiles) {
        const isPE = f['isPE'] === true;
        const isELF = f['isELF'] === true;
        if (isPE || isELF) {
          const sha256 = String(f['sha256'] ?? '');
          const sha1 = String(f['sha1'] ?? '');
          if (sha256.length === 64) hashesToCheck.push({ hash: sha256, source: 'extracted-sha256' });
          if (sha1.length === 40) hashesToCheck.push({ hash: sha1, source: 'extracted-sha1' });
          logger.info({ sha256, sha1, isPE, fileType: f['fileType'] }, 'Found extracted executable hash');
        }
      }
    }

    if (hashesToCheck.length === 0) {
      const subRes = await pool.query('SELECT sha256, mime_type FROM submissions WHERE id = $1', [submissionId]);
      const sub = subRes.rows[0] as Record<string, unknown> | undefined;
      const mimeType = String(sub?.['mime_type'] ?? '');
      const isArchive = mimeType.includes('zip') || mimeType.includes('rar') || mimeType.includes('compressed');
      if (!isArchive) {
        const sha256 = String(sub?.['sha256'] ?? '').trim();
        if (sha256.length === 64) hashesToCheck.push({ hash: sha256, source: 'submission' });
      } else {
        logger.info({ submissionId }, 'Archive but no extracted file hashes found');
        return;
      }
    }

    logger.info({ submissionId, hashes: hashesToCheck.length }, 'Looking up extracted file hashes on VT');

    const seen = new Set<string>();
    const unique = hashesToCheck.filter(h => { if (seen.has(h.hash)) return false; seen.add(h.hash); return true; });

    for (const { hash, source } of unique.slice(0, 3)) {
      try {
        logger.info({ hash, source }, 'VT lookup for extracted file');
        const resp = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
          headers: { 'x-apikey': vtKey },
          signal: AbortSignal.timeout(15000),
        });
        if (resp.ok) {
          const data = await resp.json() as Record<string, unknown>;
          const attrs = (data['data'] as Record<string, unknown>)?.['attributes'] as Record<string, unknown> | undefined;
          if (attrs) {
            const stats = attrs['last_analysis_stats'] as Record<string, number> | undefined;
            const malicious = stats?.['malicious'] ?? 0;
            const total = (stats?.['malicious'] ?? 0) + (stats?.['undetected'] ?? 0);
            const familyInfo = attrs['popular_threat_classification'] as Record<string, unknown> | undefined;
            const family = (familyInfo?.['suggested_threat_label'] as string) ?? null;
            const names = attrs['names'] as string[] | undefined;
            const tags = attrs['tags'] as string[] | undefined;
            const firstSeen = attrs['first_submission_date'] as number | undefined;
            const lastSeen = attrs['last_analysis_date'] as number | undefined;
            const typeDescription = attrs['type_description'] as string | undefined;
            const lastAnalysisResults = attrs['last_analysis_results'] as Record<string, Record<string, unknown>> | undefined;

            // Build list of engines that detected it
            const detectionEngines: Array<{ engine: string; result: string }> = [];
            if (lastAnalysisResults) {
              for (const [engine, engineResult] of Object.entries(lastAnalysisResults)) {
                if (engineResult['category'] === 'malicious' || engineResult['category'] === 'suspicious') {
                  detectionEngines.push({ engine, result: String(engineResult['result'] ?? '') });
                }
              }
            }

            logger.info({ hash, malicious, total, family, source, names: names?.slice(0, 3), detections: detectionEngines.length }, 'VT result for extracted file');

            await pool.query(
              `INSERT INTO threat_intel_results (submission_id, provider, verdict, detection_count, total_engines, malware_family, first_seen, last_seen, raw_response)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING`,
              [
                submissionId,
                `virustotal-${source}`,
                malicious > 0 ? 'malicious' : 'clean',
                malicious, total, family,
                firstSeen ? new Date(firstSeen * 1000).toISOString() : null,
                lastSeen ? new Date(lastSeen * 1000).toISOString() : null,
                JSON.stringify({
                  hash, malicious, total, family, source,
                  names: names?.slice(0, 20),
                  tags: tags?.slice(0, 20),
                  typeDescription,
                  vtLink: `https://www.virustotal.com/gui/file/${hash}`,
                  detectionEngines: detectionEngines.slice(0, 30),
                }),
              ],
            );
            if (malicious > 0) break;
          }
        }
        await new Promise(resolve => setTimeout(resolve, 16000));
      } catch (err) {
        // Log only the error message, not the full error object, to prevent
        // VT API key leakage via serialized request headers in error objects
        const errMsg = err instanceof Error ? err.message : 'Unknown error';
        logger.warn({ error: errMsg, hash }, 'VT lookup failed');
      }
    }
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : 'Unknown error';
    logger.warn({ error: errMsg }, 'lookupExtractedFileHashes failed');
  }
}
