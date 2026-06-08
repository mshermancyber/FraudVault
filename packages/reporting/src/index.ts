import express from 'express';
import pg from 'pg';
import pino from 'pino';
import Redis from 'ioredis';
import { loadConfig } from './config.js';
import { generateJsonReport } from './generators/jsonReport.js';
import { exportIOCsToCSV } from './generators/csvExporter.js';
import { exportToSTIX } from './generators/stixExporter.js';
import { generateExecutiveSummary } from './generators/executiveSummary.js';
import { getConfiguredProvider } from './ai/provider.js';
import { AIAnalyzer, AIAnalysisError, AIRateLimitError } from './ai/analyzer.js';
import type { AIProvider } from './ai/provider.js';
import type { AnalysisReport, StaticAnalysisResult, DynamicAnalysisResult } from '@scanboy/shared';

const { Pool } = pg;

async function main(): Promise<void> {
  const config = loadConfig();

  const logger = pino({
    level: config.logLevel,
    transport:
      config.nodeEnv === 'development'
        ? { target: 'pino-pretty', options: { colorize: true } }
        : undefined,
  });

  const app = express();
  app.use(express.json({ limit: '1mb' }));

  const INTERNAL_KEY = process.env['INTERNAL_API_KEY'];
  app.use((req, res, next) => {
    if (req.path === '/health') return next();
    if (!INTERNAL_KEY || req.headers['x-internal-api-key'] !== INTERNAL_KEY) {
      res.status(401).json({ success: false, error: 'Unauthorized' });
      return;
    }
    next();
  });

  app.param('submissionId', (_req, res, next, value) => {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
      res.status(400).json({ success: false, data: null, error: { code: 'BAD_REQUEST', message: 'Invalid submission ID format' } });
      return;
    }
    next();
  });

  const pool = new Pool({
    host: config.postgres.host,
    port: config.postgres.port,
    database: config.postgres.database,
    user: config.postgres.user,
    password: config.postgres.password,
    max: config.postgres.poolMax,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });

  pool.on('error', (err) => {
    logger.error({ err }, 'Unexpected PostgreSQL pool error');
  });

  // ── Redis connection (used for AI result caching) ─────────────────────

  let redis: Redis | undefined;
  try {
    redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
      password: config.redis.password,
      maxRetriesPerRequest: 3,
      lazyConnect: true,
    });
    await redis.connect();
    logger.info('Redis connected for AI result caching');
  } catch (err) {
    logger.warn({ err }, 'Redis unavailable - AI results will not be cached');
    redis = undefined;
  }

  // ── AI provider setup ─────────────────────────────────────────────────

  const aiProvider: AIProvider | null = getConfiguredProvider();
  const aiAnalyzer: AIAnalyzer | null = aiProvider
    ? new AIAnalyzer(aiProvider, redis)
    : null;

  if (aiProvider) {
    logger.info({ provider: aiProvider.name }, 'AI analysis provider configured');
  } else {
    logger.info('No AI provider configured - AI endpoints will return 503');
  }

  // ── Helper: Fetch analysis report from database ────────────────────────

  async function fetchReport(submissionId: string): Promise<AnalysisReport | null> {
    // Fetch submission
    const submissionResult = await pool.query(
      'SELECT * FROM submissions WHERE id = $1',
      [submissionId],
    );
    const submissionRow = submissionResult.rows[0] as Record<string, unknown> | undefined;
    if (!submissionRow) return null;

    // Fetch related data in parallel
    const [threatIntelResult, iocsResult, techniquesResult, yaraResult, staticResult, dynamicResult] =
      await Promise.all([
        pool.query('SELECT * FROM threat_intel_results WHERE submission_id = $1', [submissionId]),
        pool.query('SELECT * FROM iocs WHERE submission_id = $1', [submissionId]),
        pool.query('SELECT * FROM attack_techniques WHERE submission_id = $1', [submissionId]),
        pool.query('SELECT ysr.*, yr.name as rule_name, yr.category as rule_category FROM yara_scan_results ysr LEFT JOIN yara_rules yr ON yr.id = ysr.rule_id WHERE ysr.submission_id = $1 AND ysr.matched = true', [submissionId]),
        pool.query('SELECT * FROM static_analysis_results WHERE submission_id = $1', [submissionId]),
        pool.query('SELECT * FROM dynamic_analysis_results WHERE submission_id = $1', [submissionId]),
      ]);

    const submission = {
      id: submissionRow['id'] as string,
      userId: submissionRow['user_id'] as string,
      fileName: submissionRow['filename'] as string,
      fileSize: submissionRow['file_size'] as number,
      mimeType: submissionRow['mime_type'] as string,
      md5: submissionRow['md5'] as string,
      sha1: submissionRow['sha1'] as string,
      sha256: submissionRow['sha256'] as string,
      ssdeep: (submissionRow['ssdeep'] as string) ?? null,
      status: submissionRow['status'] as AnalysisReport['submission']['status'],
      threatLevel: (submissionRow['threat_level'] as AnalysisReport['submission']['threatLevel']) ?? null,
      threatScore: (submissionRow['threat_score'] as number) ?? null,
      storagePath: (submissionRow['storage_path'] ?? '') as string,
      tags: ((submissionRow['tags'] ?? []) as string[]) ?? [],
      submittedAt: String(submissionRow['created_at'] ?? new Date().toISOString()),
      completedAt: submissionRow['completed_at']
        ? (submissionRow['completed_at'] as Date).toISOString()
        : null,
      createdAt: String(submissionRow['created_at'] ?? new Date().toISOString()),
      updatedAt: String(submissionRow['updated_at'] ?? new Date().toISOString()),
    };

    const threatIntel = threatIntelResult.rows.map((row: Record<string, unknown>) => ({
      submissionId: row['submission_id'] as string,
      source: String(row['provider'] ?? ''),
      knownMalware: Number(row['detection_count'] ?? 0) > 0 && Number(row['total_engines'] ?? 0) > 0 && (Number(row['detection_count']) / Number(row['total_engines'])) > 0.05,
      malwareFamily: (row['malware_family'] as string) ?? null,
      firstSeenAt: row['first_seen']
        ? String(row['first_seen'])
        : null,
      detectionRatio: Number(row['total_engines'] ?? 0) > 0 ? `${row['detection_count']}/${row['total_engines']}` : null,
      communityScore: null,
      tags: [],
      rawResponse: (row['raw_response'] as Record<string, unknown>) ?? {},
      queriedAt: String(row['created_at'] ?? new Date().toISOString()),
    }));

    const iocs = iocsResult.rows.map((row: Record<string, unknown>) => ({
      id: row['id'] as string,
      submissionId: String(row['submission_id'] ?? ''),
      type: String(row['type'] ?? 'domain') as AnalysisReport['iocs'][number]['type'],
      value: String(row['value'] ?? ''),
      context: (row['context'] as string) ?? null,
      confidence: Number(row['confidence'] ?? 0),
      source: 'analysis',
      firstSeenAt: String(row['created_at'] ?? new Date().toISOString()),
      createdAt: String(row['created_at'] ?? new Date().toISOString()),
    }));

    const attackTechniques = techniquesResult.rows.map((row: Record<string, unknown>) => ({
      id: String(row['technique_id'] ?? ''),
      techniqueId: String(row['technique_id'] ?? ''),
      name: String(row['technique_id'] ?? ''),
      tactic: String(row['tactic_id'] ?? ''),
      description: String(row['evidence'] ?? ''),
      dataSource: 'dynamic',
      confidence: Number(row['confidence'] ?? 0),
    }));

    const yaraMatches = yaraResult.rows.map((row: Record<string, unknown>) => ({
      ruleId: String(row['rule_id'] ?? ''),
      ruleName: String(row['rule_name'] ?? ''),
      category: String(row['rule_category'] ?? ''),
      matchedStrings: [],
    }));

    // Parse static analysis result (columns are jsonb: file_metadata, pe_analysis, entropy_data, strings, certificates)
    const staticRow = staticResult.rows[0] as Record<string, unknown> | undefined;
    const fileMeta = (staticRow?.['file_metadata'] ?? {}) as Record<string, unknown>;
    const entropyData = (staticRow?.['entropy_data'] ?? {}) as Record<string, unknown>;
    const peAnalysis = (staticRow?.['pe_analysis'] ?? {}) as Record<string, unknown>;
    const staticAnalysis = staticRow
      ? {
          submissionId: String(staticRow['submission_id'] ?? ''),
          fileType: String(fileMeta['fileType'] ?? ''),
          magic: String(fileMeta['magic'] ?? ''),
          entropy: Number(entropyData['overallEntropy'] ?? 0),
          isPacked: Boolean(fileMeta['isPacked']),
          packerName: (fileMeta['packerName'] as string) ?? null,
          imports: (peAnalysis['imports'] as string[]) ?? [],
          exports: (peAnalysis['exports'] as string[]) ?? [],
          sections: (peAnalysis['sections'] ?? []) as StaticAnalysisResult['sections'],
          strings: ((staticRow['strings'] ?? []) as StaticAnalysisResult['strings']).slice(0, 100),
          certificates: ((staticRow['certificates'] ?? []) as StaticAnalysisResult['certificates']),
          iocs,
          attackTechniques,
        }
      : null;

    // Parse dynamic analysis result (columns: processes, network_activity, memory_activity)
    const dynamicRow = dynamicResult.rows[0] as Record<string, unknown> | undefined;
    const memActivity = (dynamicRow?.['memory_activity'] ?? {}) as Record<string, unknown>;
    const dynamicAnalysis = dynamicRow
      ? {
          submissionId: String(dynamicRow['submission_id'] ?? ''),
          detonationSessionId: String(dynamicRow['sandbox_id'] ?? ''),
          processesCreated: Array.isArray(dynamicRow['processes']) ? dynamicRow['processes'] as DynamicAnalysisResult['processesCreated'] : [],
          networkConnections: Array.isArray((dynamicRow['network_activity'] as Record<string, unknown>)?.['connections']) ? (dynamicRow['network_activity'] as Record<string, unknown>)['connections'] as DynamicAnalysisResult['networkConnections'] : [],
          filesModified: [],
          registryModifications: [],
          mutexesCreated: [],
          iocs,
          attackTechniques,
          behaviorTags: ((memActivity['suspiciousIndicators'] as Array<Record<string, unknown>>) ?? []).map(i => String(i['description'] ?? '')),
        }
      : null;

    return {
      id: `report-${submissionId}`,
      submissionId,
      submission,
      threatLevel: submission.threatLevel!,
      threatScore: submission.threatScore ?? 0,
      summary: buildSummary(submission.fileName, submission.threatLevel, threatIntel),
      staticAnalysis,
      dynamicAnalysis,
      threatIntel,
      yaraMatches,
      iocs,
      attackTechniques,
      generatedAt: new Date().toISOString(),
    };
  }

  function buildSummary(
    _fileName: string,
    threatLevel: string | null,
    threatIntel: Array<{ knownMalware: boolean; malwareFamily: string | null }>,
  ): string {
    const families = threatIntel
      .map((ti) => ti.malwareFamily)
      .filter((f): f is string => f !== null);
    const isKnown = threatIntel.some((ti) => ti.knownMalware);

    if (isKnown && families.length > 0) {
      return `Known malware belonging to ${[...new Set(families)].join(', ')} family. Threat level: ${threatLevel ?? 'unknown'}.`;
    }
    if (isKnown) {
      return `Known malware detected. Threat level: ${threatLevel ?? 'unknown'}.`;
    }
    return `Analysis complete. Threat level: ${threatLevel ?? 'unknown'}.`;
  }

  // ── AI Error Handler ───────────────────────────────────────────────────

  function handleAIError(
    err: unknown,
    req: express.Request,
    res: express.Response,
    log: typeof logger,
  ): void {
    const requestId = req.headers['x-request-id'] ?? crypto.randomUUID();
    const submissionId = req.params['submissionId'];

    if (err instanceof AIRateLimitError) {
      log.warn({ submissionId }, 'AI rate limit exceeded');
      res.status(429).json({
        success: false,
        data: null,
        error: { code: 'AI_RATE_LIMIT', message: err.message },
        requestId,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    if (err instanceof AIAnalysisError) {
      log.error({ err, submissionId }, 'AI analysis failed');
      res.status(502).json({
        success: false,
        data: null,
        error: { code: 'AI_PROVIDER_ERROR', message: 'AI analysis failed. Please try again later.' },
        requestId,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    log.error({ err, submissionId }, 'Unexpected error in AI endpoint');
    res.status(500).json({
      success: false,
      data: null,
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' },
      requestId,
      timestamp: new Date().toISOString(),
    });
  }

  // ── Routes ─────────────────────────────────────────────────────────────

  app.get('/health', async (_req, res) => {
    try {
      await pool.query('SELECT 1');
      res.json({ status: 'healthy', service: 'reporting', timestamp: new Date().toISOString() });
    } catch {
      res.status(503).json({
        status: 'unhealthy',
        service: 'reporting',
        timestamp: new Date().toISOString(),
      });
    }
  });

  app.get('/reports/:submissionId', async (req, res) => {
    try {
      const submissionId = req.params['submissionId']!;
      const report = await fetchReport(submissionId);

      if (!report) {
        res.status(404).json({
          success: false,
          data: null,
          error: { code: 'NOT_FOUND', message: 'Submission not found' },
          requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const jsonReport = generateJsonReport(report);
      const executiveSummary = generateExecutiveSummary(report);

      res.json({
        success: true,
        data: {
          report: jsonReport,
          executiveSummary,
        },
        error: null,
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      logger.error({ err, submissionId: req.params['submissionId'] }, 'Report generation failed');
      res.status(500).json({
        success: false,
        data: null,
        error: { code: 'REPORT_ERROR', message: 'Failed to generate report' },
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    }
  });

  app.get('/reports/:submissionId/export/:format', async (req, res) => {
    try {
      const submissionId = req.params['submissionId']!;
      const format = req.params['format']!;
      const report = await fetchReport(submissionId);

      if (!report) {
        res.status(404).json({
          success: false,
          data: null,
          error: { code: 'NOT_FOUND', message: 'Submission not found' },
          requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
          timestamp: new Date().toISOString(),
        });
        return;
      }

      switch (format) {
        case 'json': {
          const jsonReport = generateJsonReport(report);
          res.setHeader('Content-Type', 'application/json');
          res.setHeader(
            'Content-Disposition',
            `attachment; filename="fraudvault-report-${submissionId}.json"`,
          );
          res.json(jsonReport);
          break;
        }

        case 'csv': {
          const csv = exportIOCsToCSV(report.iocs, submissionId);
          res.setHeader('Content-Type', 'text/csv');
          res.setHeader(
            'Content-Disposition',
            `attachment; filename="fraudvault-iocs-${submissionId}.csv"`,
          );
          res.send(csv);
          break;
        }

        case 'stix': {
          const stixBundle = exportToSTIX(report);
          res.setHeader('Content-Type', 'application/json');
          res.setHeader(
            'Content-Disposition',
            `attachment; filename="fraudvault-stix-${submissionId}.json"`,
          );
          res.json(stixBundle);
          break;
        }

        default:
          res.status(400).json({
            success: false,
            data: null,
            error: {
              code: 'INVALID_FORMAT',
              message: 'Unsupported export format. Supported: json, csv, stix',
            },
            requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
            timestamp: new Date().toISOString(),
          });
      }
    } catch (err) {
      logger.error(
        { err, submissionId: req.params['submissionId'], format: req.params['format'] },
        'Report export failed',
      );
      res.status(500).json({
        success: false,
        data: null,
        error: { code: 'EXPORT_ERROR', message: 'Failed to export report' },
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    }
  });

  // ── PDF (HTML) Report Endpoint ──────────────────────────────────────────

  app.get('/reports/:submissionId/pdf', async (req, res) => {
    try {
      const submissionId = req.params['submissionId']!;
      const report = await fetchReport(submissionId);

      if (!report) {
        res.status(404).json({
          success: false,
          data: null,
          error: { code: 'NOT_FOUND', message: 'Submission not found' },
          requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const html = generateHtmlReport(report);

      // Convert HTML to PDF using WeasyPrint
      try {
        const { execFileSync } = await import('node:child_process');
        const { writeFileSync, readFileSync, unlinkSync } = await import('node:fs');
        const { randomUUID: tmpUUID } = await import('node:crypto');
        const tmpSuffix = tmpUUID();
        const tmpHtml = `/tmp/report-${tmpSuffix}.html`;
        const tmpPdf = `/tmp/report-${tmpSuffix}.pdf`;
        writeFileSync(tmpHtml, html);
        execFileSync('weasyprint', [tmpHtml, tmpPdf], { timeout: 30_000 });
        const pdfBuffer = readFileSync(tmpPdf);
        unlinkSync(tmpHtml);
        unlinkSync(tmpPdf);
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="fraudvault-report-${submissionId}.pdf"`);
        res.send(pdfBuffer);
      } catch (pdfErr) {
        // Fallback to HTML if PDF conversion fails
        logger.warn({ err: pdfErr }, 'PDF conversion failed, serving HTML');
        res.setHeader('Content-Type', 'text/html');
        res.setHeader('Content-Disposition', `attachment; filename="fraudvault-report-${submissionId}.html"`);
        res.send(html);
      }
    } catch (err) {
      logger.error({ err, submissionId: req.params['submissionId'] }, 'PDF report generation failed');
      res.status(500).json({
        success: false,
        data: null,
        error: { code: 'REPORT_ERROR', message: 'Failed to generate PDF report' },
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    }
  });

  // ── AI-Assisted Analysis Endpoints ──────────────────────────────────────
  // These endpoints are optional - they return 503 if no AI provider is configured.
  // AI receives ONLY sanitized analysis artifacts, NEVER the actual malware sample.

  app.get('/reports/:submissionId/ai/summary', async (req, res) => {
    if (!aiAnalyzer) {
      res.status(503).json({
        success: false,
        data: null,
        error: { code: 'AI_UNAVAILABLE', message: 'No AI provider is configured' },
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
      return;
    }

    try {
      const submissionId = req.params['submissionId']!;
      const report = await fetchReport(submissionId);

      if (!report) {
        res.status(404).json({
          success: false,
          data: null,
          error: { code: 'NOT_FOUND', message: 'Submission not found' },
          requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
          timestamp: new Date().toISOString(),
        });
        return;
      }

      if (!report.dynamicAnalysis) {
        res.status(422).json({
          success: false,
          data: null,
          error: { code: 'NO_DYNAMIC_ANALYSIS', message: 'No dynamic analysis results available for behavior summary' },
          requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const summary = await aiAnalyzer.summarizeBehavior(report.dynamicAnalysis);

      res.setHeader('Cache-Control', 'private, max-age=3600');
      res.json({
        success: true,
        data: { submissionId, type: 'behavior_summary', content: summary, provider: aiProvider!.name },
        error: null,
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      handleAIError(err, req, res, logger);
    }
  });

  app.get('/reports/:submissionId/ai/technical', async (req, res) => {
    if (!aiAnalyzer) {
      res.status(503).json({
        success: false,
        data: null,
        error: { code: 'AI_UNAVAILABLE', message: 'No AI provider is configured' },
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
      return;
    }

    try {
      const submissionId = req.params['submissionId']!;
      const report = await fetchReport(submissionId);

      if (!report) {
        res.status(404).json({
          success: false,
          data: null,
          error: { code: 'NOT_FOUND', message: 'Submission not found' },
          requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const analysis = await aiAnalyzer.generateTechnicalAnalysis(report);

      res.setHeader('Cache-Control', 'private, max-age=3600');
      res.json({
        success: true,
        data: { submissionId, type: 'technical_analysis', content: analysis, provider: aiProvider!.name },
        error: null,
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      handleAIError(err, req, res, logger);
    }
  });

  app.get('/reports/:submissionId/ai/executive', async (req, res) => {
    if (!aiAnalyzer) {
      res.status(503).json({
        success: false,
        data: null,
        error: { code: 'AI_UNAVAILABLE', message: 'No AI provider is configured' },
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
      return;
    }

    try {
      const submissionId = req.params['submissionId']!;
      const report = await fetchReport(submissionId);

      if (!report) {
        res.status(404).json({
          success: false,
          data: null,
          error: { code: 'NOT_FOUND', message: 'Submission not found' },
          requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const executiveSummary = await aiAnalyzer.generateExecutiveSummary(report);

      res.setHeader('Cache-Control', 'private, max-age=3600');
      res.json({
        success: true,
        data: { submissionId, type: 'executive_summary', content: executiveSummary, provider: aiProvider!.name },
        error: null,
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      handleAIError(err, req, res, logger);
    }
  });

  app.get('/reports/:submissionId/ai/threat-assessment', async (req, res) => {
    if (!aiAnalyzer) {
      res.status(503).json({
        success: false,
        data: null,
        error: { code: 'AI_UNAVAILABLE', message: 'No AI provider is configured' },
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
      return;
    }

    try {
      const submissionId = req.params['submissionId']!;
      const report = await fetchReport(submissionId);

      if (!report) {
        res.status(404).json({
          success: false,
          data: null,
          error: { code: 'NOT_FOUND', message: 'Submission not found' },
          requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const assessment = await aiAnalyzer.assessThreat(report);

      res.setHeader('Cache-Control', 'private, max-age=3600');
      res.json({
        success: true,
        data: { submissionId, type: 'threat_assessment', ...assessment, provider: aiProvider!.name },
        error: null,
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      handleAIError(err, req, res, logger);
    }
  });

  // ── Start server ───────────────────────────────────────────────────────

  const server = app.listen(config.port, config.host, () => {
    logger.info(
      { port: config.port, host: config.host, env: config.nodeEnv },
      'FraudVault Reporting Service is running',
    );
  });

  // ── Graceful shutdown ──────────────────────────────────────────────────

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Received shutdown signal, closing gracefully...');

    server.close(async () => {
      await pool.end();
      if (redis) {
        await redis.quit();
      }
      logger.info('All connections closed. Goodbye.');
      process.exit(0);
    });

    setTimeout(() => {
      logger.error('Graceful shutdown timed out, forcing exit');
      process.exit(1);
    }, 10_000);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

// ── HTML Report Generator ──────────────────────────────────────────────────

function generateHtmlReport(report: AnalysisReport): string {
  const esc = (s: string | null | undefined): string =>
    (s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

  const threatColor = (level: string | null): string => {
    switch (level) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      case 'low': return '#3b82f6';
      default: return '#6b7280';
    }
  };

  const severityBadge = (severity: string): string => {
    const color = threatColor(severity);
    return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;color:#fff;background:${color};">${esc(severity.toUpperCase())}</span>`;
  };

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const formatDate = (iso: string | null): string => {
    if (!iso) return 'N/A';
    try {
      return new Date(iso).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
    } catch {
      return iso;
    }
  };

  // Build malware family info
  const families = report.threatIntel
    .map(ti => ti.malwareFamily)
    .filter((f): f is string => f !== null);
  const uniqueFamilies = [...new Set(families)];
  const isKnownMalware = report.threatIntel.some(ti => ti.knownMalware);

  // Executive summary verdict
  const verdictText = isKnownMalware
    ? `MALICIOUS - Known malware${uniqueFamilies.length > 0 ? ` (${uniqueFamilies.join(', ')})` : ''}`
    : report.threatScore >= 70
      ? 'SUSPICIOUS - High threat indicators detected'
      : report.threatScore >= 40
        ? 'POTENTIALLY UNWANTED - Moderate risk indicators'
        : 'LIKELY BENIGN - No significant threats detected';

  // IOCs grouped by type
  const iocsByType = new Map<string, typeof report.iocs>();
  for (const ioc of report.iocs) {
    const existing = iocsByType.get(ioc.type) ?? [];
    existing.push(ioc);
    iocsByType.set(ioc.type, existing);
  }

  const iocSections = Array.from(iocsByType.entries()).map(([type, iocs]) => {
    const rows = iocs.slice(0, 50).map(ioc =>
      `<tr><td><code>${esc(ioc.value)}</code></td><td>${ioc.confidence}%</td><td>${esc(ioc.source)}</td><td>${esc(ioc.context)}</td></tr>`
    ).join('\n');
    return `<h3 style="color:#94a3b8;font-size:14px;margin:16px 0 8px;text-transform:uppercase;">${esc(type)} (${iocs.length})</h3>
      <table>
        <tr><th>Value</th><th>Confidence</th><th>Source</th><th>Context</th></tr>
        ${rows}
      </table>`;
  }).join('\n');

  // MITRE ATT&CK organized by tactic (kill chain phase)
  const tacticOrder = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact',
  ];
  const techniquesByTactic = new Map<string, typeof report.attackTechniques>();
  for (const t of report.attackTechniques) {
    const existing = techniquesByTactic.get(t.tactic) ?? [];
    existing.push(t);
    techniquesByTactic.set(t.tactic, existing);
  }
  const sortedTactics = [...techniquesByTactic.entries()].sort((a, b) => {
    const aIdx = tacticOrder.indexOf(a[0].toLowerCase());
    const bIdx = tacticOrder.indexOf(b[0].toLowerCase());
    return (aIdx === -1 ? 99 : aIdx) - (bIdx === -1 ? 99 : bIdx);
  });
  const attackSection = sortedTactics.map(([tactic, techniques]) => {
    const rows = techniques.map(t =>
      `<tr><td><a href="https://attack.mitre.org/techniques/${esc(t.techniqueId.replace('.', '/'))}/">${esc(t.techniqueId)}</a></td><td>${esc(t.name)}</td><td>${t.confidence}%</td></tr>`
    ).join('\n');
    return `<h3 style="color:#94a3b8;font-size:14px;margin:16px 0 8px;text-transform:capitalize;">${esc(tactic)}</h3>
      <table><tr><th>ID</th><th>Technique</th><th>Confidence</th></tr>${rows}</table>`;
  }).join('\n');

  // Threat intel details
  const threatIntelRows = report.threatIntel.map(ti => {
    const tags = Array.isArray(ti.tags) ? ti.tags.slice(0, 10).join(', ') : '';
    return `<tr>
      <td>${esc(ti.source)}</td>
      <td>${ti.knownMalware ? severityBadge('critical') : '<span style="color:#22c55e;">Clean</span>'}</td>
      <td>${esc(ti.malwareFamily) || '-'}</td>
      <td>${esc(ti.detectionRatio) || '-'}</td>
      <td>${esc(tags) || '-'}</td>
    </tr>`;
  }).join('\n');

  // YARA matches section
  const yaraRows = report.yaraMatches.map(ym =>
    `<tr><td><strong>${esc(ym.ruleName)}</strong></td><td>${esc(ym.category)}</td><td>${esc(ym.matchedStrings.slice(0, 5).join(', '))}</td></tr>`
  ).join('\n');

  // Dynamic analysis details
  let dynamicSection = '';
  if (report.dynamicAnalysis) {
    const da = report.dynamicAnalysis;
    const processRows = da.processesCreated.slice(0, 20).map(p =>
      `<tr><td>${p.pid}</td><td>${p.parentPid}</td><td>${esc(p.name)}</td><td><code>${esc(p.commandLine.slice(0, 120))}</code></td></tr>`
    ).join('\n');

    const networkRows = da.networkConnections.slice(0, 20).map(n =>
      `<tr><td>${esc(n.protocol)}</td><td>${esc(n.destinationAddress)}</td><td>${n.destinationPort}</td><td>${esc(n.domain) || '-'}</td><td>${n.bytesSent + n.bytesReceived}</td></tr>`
    ).join('\n');

    const fileRows = da.filesModified.slice(0, 20).map(f =>
      `<tr><td>${esc(f.operation)}</td><td><code>${esc(f.path.slice(0, 100))}</code></td><td>${f.sha256 ? `<code>${esc(f.sha256.slice(0, 16))}...</code>` : '-'}</td></tr>`
    ).join('\n');

    const regRows = da.registryModifications.slice(0, 20).map(r =>
      `<tr><td>${esc(r.operation)}</td><td><code>${esc(r.key.slice(0, 80))}</code></td><td>${esc(r.valueName) || '-'}</td><td>${esc((r.valueData ?? '').slice(0, 60))}</td></tr>`
    ).join('\n');

    dynamicSection = `<div class="section">
      <h2>Dynamic Analysis Summary</h2>
      <div class="meta-grid">
        <div class="meta-item"><span class="meta-label">Processes Created</span><span class="meta-value">${da.processesCreated.length}</span></div>
        <div class="meta-item"><span class="meta-label">Network Connections</span><span class="meta-value">${da.networkConnections.length}</span></div>
        <div class="meta-item"><span class="meta-label">Files Modified</span><span class="meta-value">${da.filesModified.length}</span></div>
        <div class="meta-item"><span class="meta-label">Registry Modifications</span><span class="meta-value">${da.registryModifications.length}</span></div>
        <div class="meta-item"><span class="meta-label">Mutexes Created</span><span class="meta-value">${da.mutexesCreated.length}</span></div>
        <div class="meta-item"><span class="meta-label">Behavior Tags</span><span class="meta-value">${da.behaviorTags.map(t => esc(t)).join(', ') || 'None'}</span></div>
      </div>

      ${processRows ? `<h3 style="color:#94a3b8;font-size:14px;margin:16px 0 8px;">Process Tree</h3>
        <table><tr><th>PID</th><th>PPID</th><th>Name</th><th>Command Line</th></tr>${processRows}</table>` : ''}

      ${networkRows ? `<h3 style="color:#94a3b8;font-size:14px;margin:16px 0 8px;">Network Connections</h3>
        <table><tr><th>Protocol</th><th>Destination</th><th>Port</th><th>Domain</th><th>Bytes</th></tr>${networkRows}</table>` : ''}

      ${fileRows ? `<h3 style="color:#94a3b8;font-size:14px;margin:16px 0 8px;">File Modifications</h3>
        <table><tr><th>Operation</th><th>Path</th><th>Hash</th></tr>${fileRows}</table>` : ''}

      ${regRows ? `<h3 style="color:#94a3b8;font-size:14px;margin:16px 0 8px;">Registry Modifications</h3>
        <table><tr><th>Operation</th><th>Key</th><th>Value Name</th><th>Data</th></tr>${regRows}</table>` : ''}

      ${da.mutexesCreated.length > 0 ? `<h3 style="color:#94a3b8;font-size:14px;margin:16px 0 8px;">Mutexes</h3>
        <ul style="list-style:none;padding:0;">${da.mutexesCreated.slice(0, 20).map(m => `<li style="padding:4px 0;"><code>${esc(m)}</code></li>`).join('')}</ul>` : ''}
    </div>`;
  }

  // PE Metadata (from static analysis if available)
  let peMetadataSection = '';
  if (report.staticAnalysis) {
    const sa = report.staticAnalysis;
    const sectionRows = sa.sections.slice(0, 20).map(s =>
      `<tr><td>${esc(s.name)}</td><td>${s.virtualSize}</td><td>${s.rawSize}</td><td>${s.entropy.toFixed(2)}</td><td><code>${esc(s.md5)}</code></td></tr>`
    ).join('\n');

    peMetadataSection = `<div class="section">
      <h2>Static Analysis / PE Metadata</h2>
      <div class="meta-grid">
        <div class="meta-item"><span class="meta-label">File Type</span><span class="meta-value">${esc(sa.fileType)}</span></div>
        <div class="meta-item"><span class="meta-label">Magic</span><span class="meta-value">${esc(sa.magic)}</span></div>
        <div class="meta-item"><span class="meta-label">Entropy</span><span class="meta-value">${sa.entropy.toFixed(4)}</span></div>
        <div class="meta-item"><span class="meta-label">Packed</span><span class="meta-value">${sa.isPacked ? severityBadge('high') + ' Yes' : 'No'}${sa.packerName ? ` (${esc(sa.packerName)})` : ''}</span></div>
        <div class="meta-item"><span class="meta-label">Imports</span><span class="meta-value">${sa.imports.length} APIs</span></div>
        <div class="meta-item"><span class="meta-label">Exports</span><span class="meta-value">${sa.exports.length}</span></div>
      </div>

      ${sa.certificates.length > 0 ? `<h3 style="color:#94a3b8;font-size:14px;margin:16px 0 8px;">Digital Signatures</h3>
        <table><tr><th>Subject</th><th>Issuer</th><th>Valid From</th><th>Valid To</th><th>Status</th></tr>
        ${sa.certificates.map(c => `<tr><td>${esc(c.subject)}</td><td>${esc(c.issuer)}</td><td>${esc(c.validFrom)}</td><td>${esc(c.validTo)}</td><td>${c.isValid ? '<span style="color:#22c55e;">Valid</span>' : severityBadge('high')}</td></tr>`).join('\n')}
        </table>` : ''}

      ${sectionRows ? `<h3 style="color:#94a3b8;font-size:14px;margin:16px 0 8px;">PE Sections</h3>
        <table><tr><th>Name</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th><th>MD5</th></tr>${sectionRows}</table>` : ''}
    </div>`;
  }

  // Scoring breakdown
  const scoringSection = `<div class="section">
    <h2>Scoring Breakdown</h2>
    <div style="display:flex;align-items:center;gap:32px;">
      <div class="score-ring" style="border-color: ${threatColor(report.threatLevel)}">
        <span class="score-value">${report.threatScore}</span>
        <span class="score-label">${(report.threatLevel ?? 'unknown').toUpperCase()}</span>
      </div>
      <div>
        <p style="font-size:14px;color:#cbd5e1;margin-bottom:8px;"><strong>Verdict:</strong> ${esc(verdictText)}</p>
        <p style="font-size:13px;color:#94a3b8;">Score ranges: 0-9 Informational, 10-39 Low, 40-69 Medium, 70-89 High, 90-100 Critical</p>
      </div>
    </div>
  </div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FraudVault Malware Analysis Report - ${esc(report.submission.fileName)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; background: #0f172a; color: #e2e8f0; padding: 0; line-height: 1.6; font-size: 13px; }
    .page { max-width: 900px; margin: 0 auto; padding: 40px; }
    .report-header { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border-bottom: 3px solid #38bdf8; padding: 32px 40px; margin-bottom: 32px; }
    .report-header h1 { font-size: 26px; color: #38bdf8; margin-bottom: 4px; letter-spacing: -0.5px; }
    .report-header .logo { font-size: 32px; font-weight: 800; color: #38bdf8; margin-bottom: 8px; }
    .report-header .subtitle { color: #94a3b8; font-size: 13px; }
    .report-header .meta-line { color: #64748b; font-size: 12px; margin-top: 8px; }
    .section { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 24px; margin-bottom: 20px; page-break-inside: avoid; }
    .section h2 { color: #38bdf8; font-size: 16px; margin-bottom: 14px; border-bottom: 1px solid #334155; padding-bottom: 8px; letter-spacing: -0.3px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 8px; }
    th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 10px; letter-spacing: 0.5px; background: #0f172a; }
    td { color: #cbd5e1; }
    code { background: #0f172a; padding: 2px 5px; border-radius: 3px; font-size: 11px; color: #67e8f9; word-break: break-all; font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace; }
    a { color: #38bdf8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .score-ring { width: 90px; height: 90px; border: 4px solid; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; }
    .score-value { font-size: 26px; font-weight: bold; }
    .score-label { font-size: 11px; text-transform: uppercase; color: #94a3b8; }
    .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
    .meta-item { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid rgba(51,65,85,0.5); }
    .meta-label { color: #94a3b8; font-size: 12px; }
    .meta-value { color: #e2e8f0; font-size: 12px; font-family: monospace; text-align: right; max-width: 60%; overflow: hidden; text-overflow: ellipsis; }
    .executive-summary { font-size: 14px; color: #cbd5e1; line-height: 1.7; }
    .verdict-banner { padding: 12px 20px; border-radius: 6px; font-weight: 600; font-size: 14px; margin-bottom: 12px; }
    .footer { text-align: center; color: #475569; font-size: 11px; padding: 24px 0; border-top: 1px solid #334155; margin-top: 32px; }
    .footer p { margin: 4px 0; }
    .classification-banner { background: #7c2d12; color: #fed7aa; text-align: center; padding: 6px; font-size: 11px; font-weight: 600; letter-spacing: 1px; }

    @media print {
      body { background: #ffffff; color: #1e293b; font-size: 11px; }
      .page { padding: 20px; }
      .report-header { background: #f8fafc; border-bottom-color: #0284c7; }
      .report-header h1, .report-header .logo { color: #0284c7; }
      .report-header .subtitle, .report-header .meta-line { color: #475569; }
      .section { background: #ffffff; border-color: #e2e8f0; box-shadow: none; }
      .section h2 { color: #0284c7; border-bottom-color: #e2e8f0; }
      th { color: #475569; background: #f8fafc; }
      td { color: #1e293b; }
      code { background: #f1f5f9; color: #0f172a; }
      a { color: #0284c7; }
      .meta-label { color: #475569; }
      .meta-value { color: #1e293b; }
      .score-label { color: #475569; }
      .classification-banner { background: #fef3c7; color: #92400e; }
      .footer { color: #64748b; }
    }
  </style>
  <script>
    // Auto-trigger print dialog when opened in browser for PDF generation
    window.addEventListener('load', function() {
      if (window.location.search.includes('print=1')) {
        setTimeout(function() { window.print(); }, 500);
      }
    });
  </script>
</head>
<body>
  <div class="classification-banner">TLP:AMBER - FOR AUTHORIZED RECIPIENTS ONLY</div>

  <div class="report-header">
    <div class="logo">FRAUDVAULT</div>
    <h1>Malware Analysis Report</h1>
    <p class="subtitle">${esc(report.submission.fileName)}</p>
    <p class="meta-line">Report ID: ${esc(report.id)} | Generated: ${new Date().toISOString()} | Submission: ${esc(report.submissionId)}</p>
  </div>

  <div class="page">

  <!-- Executive Summary -->
  <div class="section">
    <h2>Executive Summary</h2>
    <div class="verdict-banner" style="background:${threatColor(report.threatLevel)}22;border-left:4px solid ${threatColor(report.threatLevel)};">
      ${esc(verdictText)}
    </div>
    <p class="executive-summary">${esc(report.summary)}</p>
    ${uniqueFamilies.length > 0 ? `<p style="margin-top:8px;font-size:13px;"><strong>Identified Families:</strong> ${uniqueFamilies.map(f => `<code>${esc(f)}</code>`).join(', ')}</p>` : ''}
  </div>

  <!-- Scoring -->
  ${scoringSection}

  <!-- File Information -->
  <div class="section">
    <h2>File Information</h2>
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">File Name</span><span class="meta-value">${esc(report.submission.fileName)}</span></div>
      <div class="meta-item"><span class="meta-label">File Size</span><span class="meta-value">${formatBytes(report.submission.fileSize)}</span></div>
      <div class="meta-item"><span class="meta-label">MIME Type</span><span class="meta-value">${esc(report.submission.mimeType)}</span></div>
      <div class="meta-item"><span class="meta-label">Status</span><span class="meta-value">${esc(report.submission.status)}</span></div>
      <div class="meta-item"><span class="meta-label">Submitted</span><span class="meta-value">${formatDate(report.submission.submittedAt)}</span></div>
      <div class="meta-item"><span class="meta-label">Completed</span><span class="meta-value">${formatDate(report.submission.completedAt)}</span></div>
    </div>
    <h3 style="color:#94a3b8;font-size:14px;margin:16px 0 8px;">Cryptographic Hashes</h3>
    <table>
      <tr><th>Algorithm</th><th>Hash</th></tr>
      <tr><td>MD5</td><td><code>${esc(report.submission.md5)}</code></td></tr>
      <tr><td>SHA-1</td><td><code>${esc(report.submission.sha1)}</code></td></tr>
      <tr><td>SHA-256</td><td><code>${esc(report.submission.sha256)}</code></td></tr>
      ${report.submission.ssdeep ? `<tr><td>ssdeep</td><td><code>${esc(report.submission.ssdeep)}</code></td></tr>` : ''}
    </table>
  </div>

  <!-- PE Metadata / Static Analysis -->
  ${peMetadataSection}

  <!-- Threat Intelligence -->
  ${threatIntelRows.length > 0 ? `<div class="section">
    <h2>Threat Intelligence</h2>
    <table>
      <tr><th>Source</th><th>Verdict</th><th>Family</th><th>Detection</th><th>Tags</th></tr>
      ${threatIntelRows}
    </table>
  </div>` : ''}

  <!-- YARA Matches -->
  ${yaraRows.length > 0 ? `<div class="section">
    <h2>YARA Matches</h2>
    <table>
      <tr><th>Rule Name</th><th>Category</th><th>Matched Strings</th></tr>
      ${yaraRows}
    </table>
  </div>` : ''}

  <!-- MITRE ATT&CK Techniques -->
  ${attackSection.length > 0 ? `<div class="section">
    <h2>MITRE ATT&CK Techniques (${report.attackTechniques.length})</h2>
    ${attackSection}
  </div>` : ''}

  <!-- IOCs -->
  ${report.iocs.length > 0 ? `<div class="section">
    <h2>Indicators of Compromise (${report.iocs.length})</h2>
    ${iocSections}
  </div>` : ''}

  <!-- Dynamic Analysis -->
  ${dynamicSection}

  <!-- Footer -->
  <div class="footer">
    <p><strong>FraudVault Malware Analysis Platform</strong></p>
    <p>This report is generated automatically. Classification: TLP:AMBER</p>
    <p>Do not share outside of authorized recipients. Handle according to organizational security policies.</p>
    <p style="margin-top:8px;color:#64748b;">Report generated ${new Date().toISOString()}</p>
  </div>

  </div><!-- .page -->

  <div class="classification-banner">TLP:AMBER - FOR AUTHORIZED RECIPIENTS ONLY</div>
</body>
</html>`;
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
