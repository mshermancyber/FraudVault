import { Queue, type ConnectionOptions, type JobsOptions } from 'bullmq';
import { QUEUE_NAMES } from '@scanboy/shared';
import type { OrchestratorConfig } from './config.js';

// ── Job Data Types ───────────────────────────────────────────────────────────

export interface SubmissionIntakeJobData {
  submissionId: string;
  sha256: string;
  storagePath: string;
  userId: string;
}

export interface StaticAnalysisJobData {
  submissionId: string;
  sha256: string;
  storagePath: string;
}

export interface DynamicAnalysisJobData {
  submissionId: string;
  sha256: string;
  storagePath: string;
  sandboxTimeout: number;
}

export interface ThreatIntelJobData {
  submissionId: string;
  sha256: string;
  md5: string;
  sha1: string;
}

export interface YaraScanJobData {
  submissionId: string;
  sha256: string;
  storagePath: string;
}

export interface DetectionJobData {
  submissionId: string;
  sha256: string;
}

export interface ScoringJobData {
  submissionId: string;
  sha256: string;
}

export interface ReportingJobData {
  submissionId: string;
  sha256: string;
}

// ── Queue Name Constants ─────────────────────────────────────────────────────

/**
 * All orchestrator queue names. Extends shared QUEUE_NAMES with
 * additional queues specific to the orchestrator pipeline.
 */
export const ORCHESTRATOR_QUEUE_NAMES = {
  SUBMISSION_INTAKE: 'submission-intake',
  STATIC_ANALYSIS: QUEUE_NAMES.STATIC_ANALYSIS,
  DYNAMIC_ANALYSIS: QUEUE_NAMES.DYNAMIC_ANALYSIS,
  THREAT_INTEL: QUEUE_NAMES.THREAT_INTEL,
  YARA_SCAN: 'yara-scan',
  DETECTION: QUEUE_NAMES.DETECTION,
  SCORING: 'scoring',
  REPORTING: QUEUE_NAMES.REPORTING,
} as const;

export type OrchestratorQueueName =
  (typeof ORCHESTRATOR_QUEUE_NAMES)[keyof typeof ORCHESTRATOR_QUEUE_NAMES];

// ── Queue Registry ───────────────────────────────────────────────────────────

interface QueueRegistry {
  submissionIntake: Queue<SubmissionIntakeJobData>;
  staticAnalysis: Queue<StaticAnalysisJobData>;
  dynamicAnalysis: Queue<DynamicAnalysisJobData>;
  threatIntel: Queue<ThreatIntelJobData>;
  yaraScan: Queue<YaraScanJobData>;
  detection: Queue<DetectionJobData>;
  scoring: Queue<ScoringJobData>;
  reporting: Queue<ReportingJobData>;
}

let registry: QueueRegistry | null = null;

function getConnection(config: OrchestratorConfig): ConnectionOptions {
  return {
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password,
  };
}

function defaultJobOptions(config: OrchestratorConfig): JobsOptions {
  return {
    attempts: config.worker.maxRetries,
    backoff: { type: 'exponential', delay: 5_000 },
    removeOnComplete: { age: 7 * 24 * 3600, count: 10_000 },
    removeOnFail: { age: 30 * 24 * 3600, count: 50_000 },
  };
}

function createQueue<T>(name: string, config: OrchestratorConfig): Queue<T> {
  return new Queue<T>(name, {
    connection: getConnection(config),
    defaultJobOptions: defaultJobOptions(config),
  });
}

/**
 * Returns (and lazily creates) all orchestrator queues.
 */
export function getQueues(config: OrchestratorConfig): QueueRegistry {
  if (!registry) {
    registry = {
      submissionIntake: createQueue<SubmissionIntakeJobData>(
        ORCHESTRATOR_QUEUE_NAMES.SUBMISSION_INTAKE,
        config,
      ),
      staticAnalysis: createQueue<StaticAnalysisJobData>(
        ORCHESTRATOR_QUEUE_NAMES.STATIC_ANALYSIS,
        config,
      ),
      dynamicAnalysis: createQueue<DynamicAnalysisJobData>(
        ORCHESTRATOR_QUEUE_NAMES.DYNAMIC_ANALYSIS,
        config,
      ),
      threatIntel: createQueue<ThreatIntelJobData>(
        ORCHESTRATOR_QUEUE_NAMES.THREAT_INTEL,
        config,
      ),
      yaraScan: createQueue<YaraScanJobData>(
        ORCHESTRATOR_QUEUE_NAMES.YARA_SCAN,
        config,
      ),
      detection: createQueue<DetectionJobData>(
        ORCHESTRATOR_QUEUE_NAMES.DETECTION,
        config,
      ),
      scoring: createQueue<ScoringJobData>(
        ORCHESTRATOR_QUEUE_NAMES.SCORING,
        config,
      ),
      reporting: createQueue<ReportingJobData>(
        ORCHESTRATOR_QUEUE_NAMES.REPORTING,
        config,
      ),
    };
  }
  return registry;
}

// ── Job Addition Helpers ─────────────────────────────────────────────────────

export async function enqueueSubmissionIntake(
  config: OrchestratorConfig,
  data: SubmissionIntakeJobData,
  priority = 0,
): Promise<string> {
  const queues = getQueues(config);
  const job = await queues.submissionIntake.add('intake', data, {
    priority,
    jobId: `intake-${data.submissionId}`,
  });
  return job.id ?? data.submissionId;
}

export async function enqueueStaticAnalysis(
  config: OrchestratorConfig,
  data: StaticAnalysisJobData,
): Promise<string> {
  const queues = getQueues(config);
  const job = await queues.staticAnalysis.add('static', data, {
    jobId: `static-${data.submissionId}`,
  });
  return job.id ?? data.submissionId;
}

export async function enqueueDynamicAnalysis(
  config: OrchestratorConfig,
  data: DynamicAnalysisJobData,
): Promise<string> {
  const queues = getQueues(config);
  const job = await queues.dynamicAnalysis.add('dynamic', data, {
    jobId: `dynamic-${data.submissionId}`,
  });
  return job.id ?? data.submissionId;
}

export async function enqueueThreatIntel(
  config: OrchestratorConfig,
  data: ThreatIntelJobData,
): Promise<string> {
  const queues = getQueues(config);
  const job = await queues.threatIntel.add('threat-intel', data, {
    jobId: `threat-intel-${data.submissionId}`,
  });
  return job.id ?? data.submissionId;
}

export async function enqueueYaraScan(
  config: OrchestratorConfig,
  data: YaraScanJobData,
): Promise<string> {
  const queues = getQueues(config);
  const job = await queues.yaraScan.add('yara', data, {
    jobId: `yara-${data.submissionId}`,
  });
  return job.id ?? data.submissionId;
}

export async function enqueueDetection(
  config: OrchestratorConfig,
  data: DetectionJobData,
): Promise<string> {
  const queues = getQueues(config);
  const job = await queues.detection.add('detection', data, {
    jobId: `detection-${data.submissionId}`,
  });
  return job.id ?? data.submissionId;
}

export async function enqueueScoring(
  config: OrchestratorConfig,
  data: ScoringJobData,
): Promise<string> {
  const queues = getQueues(config);
  const job = await queues.scoring.add('scoring', data, {
    jobId: `scoring-${data.submissionId}`,
  });
  return job.id ?? data.submissionId;
}

export async function enqueueReporting(
  config: OrchestratorConfig,
  data: ReportingJobData,
): Promise<string> {
  const queues = getQueues(config);
  const job = await queues.reporting.add('reporting', data, {
    jobId: `reporting-${data.submissionId}`,
  });
  return job.id ?? data.submissionId;
}

// ── Queue Health Monitoring ──────────────────────────────────────────────────

export interface QueueHealthStatus {
  name: string;
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  delayed: number;
  paused: number;
}

export interface OverallHealthReport {
  healthy: boolean;
  queues: QueueHealthStatus[];
  totalWaiting: number;
  totalActive: number;
  totalFailed: number;
  checkedAt: string;
}

async function getQueueHealth(queue: Queue): Promise<QueueHealthStatus> {
  const counts = await queue.getJobCounts(
    'waiting',
    'active',
    'completed',
    'failed',
    'delayed',
    'paused',
  );
  return {
    name: queue.name,
    waiting: counts['waiting'] ?? 0,
    active: counts['active'] ?? 0,
    completed: counts['completed'] ?? 0,
    failed: counts['failed'] ?? 0,
    delayed: counts['delayed'] ?? 0,
    paused: counts['paused'] ?? 0,
  };
}

/**
 * Collects health metrics from all queues. The report is considered
 * unhealthy when any queue has more than 1 000 waiting jobs or more
 * than 100 failed jobs.
 */
export async function getHealthReport(config: OrchestratorConfig): Promise<OverallHealthReport> {
  const queues = getQueues(config);

  const allQueues: Queue[] = [
    queues.submissionIntake,
    queues.staticAnalysis,
    queues.dynamicAnalysis,
    queues.threatIntel,
    queues.yaraScan,
    queues.detection,
    queues.scoring,
    queues.reporting,
  ];

  const statuses = await Promise.all(allQueues.map(getQueueHealth));

  const totalWaiting = statuses.reduce((sum, s) => sum + s.waiting, 0);
  const totalActive = statuses.reduce((sum, s) => sum + s.active, 0);
  const totalFailed = statuses.reduce((sum, s) => sum + s.failed, 0);

  const healthy = statuses.every((s) => s.waiting <= 1_000 && s.failed <= 100);

  return {
    healthy,
    queues: statuses,
    totalWaiting,
    totalActive,
    totalFailed,
    checkedAt: new Date().toISOString(),
  };
}

// ── Cleanup ──────────────────────────────────────────────────────────────────

/**
 * Close all queues gracefully.
 */
export async function closeQueues(): Promise<void> {
  if (registry) {
    await Promise.all([
      registry.submissionIntake.close(),
      registry.staticAnalysis.close(),
      registry.dynamicAnalysis.close(),
      registry.threatIntel.close(),
      registry.yaraScan.close(),
      registry.detection.close(),
      registry.scoring.close(),
      registry.reporting.close(),
    ]);
    registry = null;
  }
}
