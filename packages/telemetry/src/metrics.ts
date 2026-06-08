import {
  Registry,
  Counter,
  Histogram,
  Gauge,
  collectDefaultMetrics,
} from 'prom-client';

// ── Registry ───────────────────────────────────────────────────────────────

export const registry = new Registry();

registry.setDefaultLabels({ service: 'scanboy' });

collectDefaultMetrics({ register: registry });

// ── Application Metrics ────────────────────────────────────────────────────

/**
 * Total number of submissions processed.
 * Labels: type (file, url, hash), status (completed, failed, cancelled)
 */
export const submissionsTotal = new Counter({
  name: 'submissions_total',
  help: 'Total number of submissions processed',
  labelNames: ['type', 'status'] as const,
  registers: [registry],
});

/**
 * Duration of analysis jobs in seconds.
 * Labels: job_type (hash_lookup, threat_intel, static_analysis, yara_scan,
 *         dynamic_analysis, detection, scoring, report_generation)
 */
export const analysisDurationSeconds = new Histogram({
  name: 'analysis_duration_seconds',
  help: 'Duration of analysis jobs in seconds',
  labelNames: ['job_type'] as const,
  buckets: [0.5, 1, 5, 10, 30, 60, 120, 300, 600],
  registers: [registry],
});

/**
 * Number of analyses currently in progress.
 */
export const activeAnalyses = new Gauge({
  name: 'active_analyses',
  help: 'Number of analyses currently in progress',
  registers: [registry],
});

/**
 * Sandbox utilization (0.0 to 1.0).
 */
export const sandboxUtilization = new Gauge({
  name: 'sandbox_utilization',
  help: 'Sandbox utilization ratio (0.0 to 1.0)',
  registers: [registry],
});

/**
 * Total number of threat intelligence API requests.
 * Labels: provider (virustotal, malwarebazaar, etc.), status (success, error, timeout)
 */
export const threatIntelRequestsTotal = new Counter({
  name: 'threat_intel_requests_total',
  help: 'Total number of threat intelligence API requests',
  labelNames: ['provider', 'status'] as const,
  registers: [registry],
});

/**
 * HTTP API request duration in seconds.
 * Labels: method (GET, POST, etc.), route, status (HTTP status code)
 */
export const apiRequestDurationSeconds = new Histogram({
  name: 'api_request_duration_seconds',
  help: 'HTTP API request duration in seconds',
  labelNames: ['method', 'route', 'status'] as const,
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [registry],
});

/**
 * Current depth of processing queues.
 * Labels: queue_name (analysis, detection, scoring, reporting)
 */
export const queueDepth = new Gauge({
  name: 'queue_depth',
  help: 'Current depth of processing queues',
  labelNames: ['queue_name'] as const,
  registers: [registry],
});
