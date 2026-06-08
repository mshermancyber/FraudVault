import express from 'express';
import { Pool } from 'pg';
import { Worker, Queue } from 'bullmq';
import pino from 'pino';
import pinoHttp from 'pino-http';
import type {
  StaticAnalysisResult,
  DynamicAnalysisResult,
  ThreatIntelResult,
} from '@scanboy/shared';
import { IOCType, QUEUE_NAMES } from '@scanboy/shared';
import { config } from './config.js';
import { mapToAttackTechniques, getMappingRuleCount } from './attack-mapping/mapper.js';
import { generateSigmaRules } from './rule-generation/sigma.js';
import { generateSuricataRules } from './rule-generation/suricata.js';
import { generateSnortRules } from './rule-generation/snort.js';
import { generateYaraRecommendations } from './rule-generation/yara.js';
import { calculateThreatScore, type ScoringInput } from './scoring/threatScorer.js';
import { extractIOCs } from './ioc/extractor.js';
import { loadTrancoData, isTrancoLoaded, getTrancoSize } from './domainReputation.js';

// ── Logger ──────────────────────────────────────────────────────────────────
const log = pino({ name: 'detection-engine', level: process.env['LOG_LEVEL'] ?? 'info' });

// ── PostgreSQL ──────────────────────────────────────────────────────────────
const db = new Pool({
  host: config.database.host,
  port: config.database.port,
  database: config.database.name,
  user: config.database.user,
  password: config.database.password,
  max: config.database.maxConnections,
});

// ── Redis / BullMQ ──────────────────────────────────────────────────────────
const redisOpts = {
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password || undefined,
  maxRetriesPerRequest: null as null,
};

const detectionQueue = new Queue(QUEUE_NAMES.DETECTION, { connection: redisOpts });

// ── BullMQ Worker ───────────────────────────────────────────────────────────
const worker = new Worker(
  QUEUE_NAMES.DETECTION,
  async (job) => {
    const {
      submissionId,
      sha256,
      staticAnalysis,
      dynamicAnalysis,
      threatIntelResults,
    } = job.data as {
      submissionId: string;
      sha256: string;
      staticAnalysis: StaticAnalysisResult | null;
      dynamicAnalysis: DynamicAnalysisResult | null;
      threatIntelResults: ThreatIntelResult[];
    };

    log.info({ jobId: job.id, submissionId }, 'Processing detection job');

    try {
      // 1. ATT&CK Technique Mapping
      const attackTechniques = mapToAttackTechniques(staticAnalysis, dynamicAnalysis);
      log.info({ submissionId, techniqueCount: attackTechniques.length }, 'ATT&CK mapping complete');

      // 2. IOC Extraction
      const extractedIOCs = extractIOCs(staticAnalysis, dynamicAnalysis, submissionId);
      log.info({ submissionId, iocCount: extractedIOCs.total }, 'IOC extraction complete');

      // 3. Threat Scoring
      const scoringInput: ScoringInput = {
        threatIntelResults,
        staticAnalysis,
        dynamicAnalysis,
        attackTechniques,
      };
      const scoreBreakdown = calculateThreatScore(scoringInput);
      log.info(
        { submissionId, score: scoreBreakdown.totalScore, level: scoreBreakdown.threatLevel },
        'Threat scoring complete',
      );

      // 4. Rule Generation (only if dynamic analysis is available)
      let sigmaRules: ReturnType<typeof generateSigmaRules> = [];
      let suricataRules: ReturnType<typeof generateSuricataRules> = [];
      let snortRules: ReturnType<typeof generateSnortRules> = [];

      if (dynamicAnalysis) {
        sigmaRules = generateSigmaRules(dynamicAnalysis, submissionId);
        suricataRules = generateSuricataRules(dynamicAnalysis, submissionId, config.suricataBaseSid);
        snortRules = generateSnortRules(dynamicAnalysis, submissionId, config.snortBaseSid);
        log.info(
          { submissionId, sigma: sigmaRules.length, suricata: suricataRules.length, snort: snortRules.length },
          'Rule generation complete',
        );
      }

      // 5. YARA Recommendations (only if static analysis is available)
      let yaraRecommendations: ReturnType<typeof generateYaraRecommendations> = [];
      if (staticAnalysis) {
        yaraRecommendations = generateYaraRecommendations(staticAnalysis, submissionId, sha256);
        log.info({ submissionId, yaraRules: yaraRecommendations.length }, 'YARA recommendations complete');
      }

      // 6. Store results in database
      await storeDetectionResults(submissionId, {
        attackTechniques,
        iocs: extractedIOCs,
        scoreBreakdown,
        sigmaRules,
        suricataRules,
        snortRules,
        yaraRecommendations,
      });

      // 7. Update submission status
      await db.query(
        `UPDATE submissions
         SET threat_score = $1, threat_level = $2,
             status = 'completed', completed_at = NOW(), updated_at = NOW()
         WHERE id = $3`,
        [scoreBreakdown.totalScore, scoreBreakdown.threatLevel, submissionId],
      );

      log.info({ submissionId, score: scoreBreakdown.totalScore }, 'Detection processing complete');

      return {
        attackTechniques,
        iocs: extractedIOCs,
        scoreBreakdown,
        generatedRules: {
          sigma: sigmaRules.length,
          suricata: suricataRules.length,
          snort: snortRules.length,
          yara: yaraRecommendations.length,
        },
      };
    } catch (err: unknown) {
      log.error({ jobId: job.id, submissionId, err }, 'Detection job failed');
      throw err;
    }
  },
  {
    connection: redisOpts,
    concurrency: config.workerConcurrency,
  },
);

worker.on('failed', (job, err) => {
  log.error({ jobId: job?.id, err }, 'Worker job failed');
});

worker.on('completed', (job) => {
  log.info({ jobId: job.id }, 'Worker job completed');
});

// ── Database storage ────────────────────────────────────────────────────────

interface DetectionResults {
  attackTechniques: ReturnType<typeof mapToAttackTechniques>;
  iocs: ReturnType<typeof extractIOCs>;
  scoreBreakdown: ReturnType<typeof calculateThreatScore>;
  sigmaRules: ReturnType<typeof generateSigmaRules>;
  suricataRules: ReturnType<typeof generateSuricataRules>;
  snortRules: ReturnType<typeof generateSnortRules>;
  yaraRecommendations: ReturnType<typeof generateYaraRecommendations>;
}

async function storeDetectionResults(
  submissionId: string,
  results: DetectionResults,
): Promise<void> {
  const client = await db.connect();
  try {
    await client.query('BEGIN');

    // Store ATT&CK techniques
    for (const technique of results.attackTechniques) {
      await client.query(
        `INSERT INTO attack_techniques (submission_id, technique_id, name, tactic, description, data_source, confidence)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (submission_id, technique_id) DO UPDATE SET confidence = GREATEST(attack_techniques.confidence, EXCLUDED.confidence)`,
        [submissionId, technique.techniqueId, technique.name, technique.tactic, technique.description, technique.dataSource, technique.confidence],
      );
    }

    // Store IOCs
    for (const ioc of results.iocs.iocs) {
      await client.query(
        `INSERT INTO iocs (submission_id, type, value, context, confidence, source, first_seen_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (submission_id, type, value) DO UPDATE SET confidence = GREATEST(iocs.confidence, EXCLUDED.confidence)`,
        [submissionId, ioc.type, ioc.value, ioc.context, ioc.confidence, ioc.source, ioc.firstSeenAt],
      );
    }

    // Store generated rules
    await client.query(
      `INSERT INTO detection_results (submission_id, score_breakdown, sigma_rules, suricata_rules, snort_rules, yara_recommendations, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())
       ON CONFLICT (submission_id) DO UPDATE SET
         score_breakdown = EXCLUDED.score_breakdown,
         sigma_rules = EXCLUDED.sigma_rules,
         suricata_rules = EXCLUDED.suricata_rules,
         snort_rules = EXCLUDED.snort_rules,
         yara_recommendations = EXCLUDED.yara_recommendations`,
      [
        submissionId,
        JSON.stringify(results.scoreBreakdown),
        JSON.stringify(results.sigmaRules),
        JSON.stringify(results.suricataRules),
        JSON.stringify(results.snortRules),
        JSON.stringify(results.yaraRecommendations),
      ],
    );

    await client.query('COMMIT');
  } catch (err: unknown) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ── Express App ─────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(pinoHttp({ logger: log }));

const INTERNAL_KEY = process.env['INTERNAL_API_KEY'];
app.use((req, res, next) => {
  if (req.path === '/health' || req.path === '/ready') return next();
  if (!INTERNAL_KEY || req.headers['x-internal-api-key'] !== INTERNAL_KEY) {
    res.status(401).json({ success: false, error: 'Unauthorized' });
    return;
  }
  next();
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'detection-engine', timestamp: new Date().toISOString() });
});

// Readiness probe
app.get('/ready', async (_req, res) => {
  try {
    await db.query('SELECT 1');
    await detectionQueue.getJobCounts();
    res.json({ status: 'ready' });
  } catch {
    res.status(503).json({ status: 'not ready' });
  }
});

// Engine capabilities
app.get('/api/v1/capabilities', (_req, res) => {
  res.json({
    data: {
      attackMappingRules: getMappingRuleCount(),
      ruleFormats: ['sigma', 'suricata', 'snort', 'yara'],
      scoringCategories: ['threat_intel', 'static_indicators', 'dynamic_behaviors', 'network_activity', 'evasion'],
      iocTypes: Object.values(IOCType),
    },
  });
});

// Enqueue a detection job
app.post('/api/v1/detect', async (req, res) => {
  const { submissionId, sha256, staticAnalysis, dynamicAnalysis, threatIntelResults } = req.body as {
    submissionId: string;
    sha256: string;
    staticAnalysis: StaticAnalysisResult | null;
    dynamicAnalysis: DynamicAnalysisResult | null;
    threatIntelResults: ThreatIntelResult[];
  };

  if (!submissionId) {
    res.status(400).json({ error: 'submissionId is required' });
    return;
  }

  const job = await detectionQueue.add('detect', {
    submissionId, sha256, staticAnalysis, dynamicAnalysis, threatIntelResults,
  }, {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
  });

  res.status(202).json({ jobId: job.id, submissionId });
});

// Synchronous detection (for on-demand analysis)
app.post('/api/v1/detect/sync', async (req, res) => {
  const { submissionId, sha256, staticAnalysis, dynamicAnalysis, threatIntelResults } = req.body as {
    submissionId: string;
    sha256: string;
    staticAnalysis: StaticAnalysisResult | null;
    dynamicAnalysis: DynamicAnalysisResult | null;
    threatIntelResults: ThreatIntelResult[];
  };

  if (!submissionId) {
    res.status(400).json({ error: 'submissionId is required' });
    return;
  }

  try {
    const attackTechniques = mapToAttackTechniques(staticAnalysis, dynamicAnalysis);
    const extractedIOCs = extractIOCs(staticAnalysis, dynamicAnalysis, submissionId);

    const scoringInput: ScoringInput = {
      threatIntelResults: threatIntelResults ?? [],
      staticAnalysis,
      dynamicAnalysis,
      attackTechniques,
    };
    const scoreBreakdown = calculateThreatScore(scoringInput);

    let sigmaRules: ReturnType<typeof generateSigmaRules> = [];
    let suricataRules: ReturnType<typeof generateSuricataRules> = [];
    let snortRules: ReturnType<typeof generateSnortRules> = [];
    if (dynamicAnalysis) {
      sigmaRules = generateSigmaRules(dynamicAnalysis, submissionId);
      suricataRules = generateSuricataRules(dynamicAnalysis, submissionId, config.suricataBaseSid);
      snortRules = generateSnortRules(dynamicAnalysis, submissionId, config.snortBaseSid);
    }

    let yaraRecommendations: ReturnType<typeof generateYaraRecommendations> = [];
    if (staticAnalysis) {
      yaraRecommendations = generateYaraRecommendations(staticAnalysis, submissionId, sha256);
    }

    res.json({
      data: {
        attackTechniques,
        iocs: extractedIOCs,
        scoreBreakdown,
        generatedRules: { sigma: sigmaRules, suricata: suricataRules, snort: snortRules, yara: yaraRecommendations },
      },
    });
  } catch (err: unknown) {
    log.error({ err }, 'Synchronous detection failed');
    res.status(500).json({ error: 'Detection failed' });
  }
});

// Get ATT&CK mapping for analysis data (stateless)
app.post('/api/v1/attack-map', (req, res) => {
  const { staticAnalysis, dynamicAnalysis } = req.body as {
    staticAnalysis: StaticAnalysisResult | null;
    dynamicAnalysis: DynamicAnalysisResult | null;
  };

  const techniques = mapToAttackTechniques(staticAnalysis, dynamicAnalysis);
  res.json({ data: techniques });
});

// Calculate threat score (stateless)
app.post('/api/v1/score', (req, res) => {
  const input = req.body as ScoringInput;
  const breakdown = calculateThreatScore(input);
  res.json({ data: breakdown });
});

// Extract IOCs (stateless)
app.post('/api/v1/iocs/extract', (req, res) => {
  const { staticAnalysis, dynamicAnalysis, submissionId } = req.body as {
    staticAnalysis: StaticAnalysisResult | null;
    dynamicAnalysis: DynamicAnalysisResult | null;
    submissionId: string;
  };

  const iocs = extractIOCs(staticAnalysis, dynamicAnalysis, submissionId);
  res.json({ data: iocs });
});

// Generate rules (stateless)
app.post('/api/v1/rules/generate', (req, res) => {
  const { submissionId, sha256, staticAnalysis, dynamicAnalysis } = req.body as {
    submissionId: string;
    sha256: string;
    staticAnalysis: StaticAnalysisResult | null;
    dynamicAnalysis: DynamicAnalysisResult | null;
  };

  const result: Record<string, unknown> = {};

  if (dynamicAnalysis) {
    result['sigma'] = generateSigmaRules(dynamicAnalysis, submissionId);
    result['suricata'] = generateSuricataRules(dynamicAnalysis, submissionId, config.suricataBaseSid);
    result['snort'] = generateSnortRules(dynamicAnalysis, submissionId, config.snortBaseSid);
  }

  if (staticAnalysis) {
    result['yara'] = generateYaraRecommendations(staticAnalysis, submissionId, sha256);
  }

  res.json({ data: result });
});

// Get detection results for a submission
app.get('/api/v1/results/:submissionId', async (req, res) => {
  const submissionId = req.params['submissionId'] ?? '';
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(submissionId)) {
    res.status(400).json({ error: 'Invalid submissionId format' });
    return;
  }
  try {
    const { rows } = await db.query(
      `SELECT score_breakdown, sigma_rules, suricata_rules, snort_rules, yara_recommendations, created_at
       FROM detection_results WHERE submission_id = $1`,
      [submissionId],
    );

    if (rows.length === 0) {
      res.status(404).json({ error: 'Detection results not found' });
      return;
    }

    const row = rows[0]!;
    const safeParse = (val: unknown): unknown => {
      if (typeof val !== 'string') return val;
      try { return JSON.parse(val); } catch { return null; }
    };
    res.json({
      data: {
        scoreBreakdown: safeParse(row.score_breakdown),
        sigmaRules: safeParse(row.sigma_rules),
        suricataRules: safeParse(row.suricata_rules),
        snortRules: safeParse(row.snort_rules),
        yaraRecommendations: safeParse(row.yara_recommendations),
        createdAt: row.created_at,
      },
    });
  } catch (err: unknown) {
    log.error({ err }, 'Failed to fetch detection results');
    res.status(500).json({ error: 'Failed to fetch results' });
  }
});

// ── Start ───────────────────────────────────────────────────────────────────
app.listen(config.port, config.host, () => {
  log.info({ port: config.port, host: config.host }, 'Detection engine service started');
  log.info({ mappingRules: getMappingRuleCount() }, 'ATT&CK mapping rules loaded');

  // Load Tranco domain reputation data (non-blocking)
  loadTrancoData().then(() => {
    if (isTrancoLoaded()) {
      log.info({ domains: getTrancoSize() }, 'Tranco domain reputation data loaded');
    }
  }).catch(err => {
    log.warn({ err }, 'Tranco data load failed — domain reputation scoring will use defaults');
  });
});

// ── Graceful shutdown ───────────────────────────────────────────────────────
async function shutdown(): Promise<void> {
  log.info('Shutting down detection engine');
  await worker.close();
  await detectionQueue.close();
  await db.end();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
