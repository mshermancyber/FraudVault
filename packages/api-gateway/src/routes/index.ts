import { Router } from 'express';
import { readFileSync } from 'fs';
import { join } from 'path';

import type pg from 'pg';
import type Redis from 'ioredis';
import type { AppConfig } from '../config.js';
import { createHealthRouter } from './health.js';
import { createAuthRouter } from './auth.js';
import { createSubmissionsRouter } from './submissions.js';
import { createAnalysisRouter } from './analysis.js';
import { createSearchRouter } from './search.js';
import { createAdminRouter } from './admin.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { UserRole } from '@scanboy/shared';
import { AuthService } from '../services/authService.js';
import { UserService } from '../services/userService.js';
import { SubmissionService } from '../services/submissionService.js';

/**
 * Aggregates all route modules into a single router.
 */
export function createRoutes(pool: pg.Pool, redis: Redis, config: AppConfig): Router {
  const router = Router();

  // Services
  const authService = new AuthService(pool, redis, config);
  const userService = new UserService(pool, config);
  const submissionService = new SubmissionService(pool, redis);

  // Mount routes
  router.use('/health', createHealthRouter(pool, redis));
  router.use('/auth', createAuthRouter(authService));
  router.use('/submissions', createSubmissionsRouter(submissionService, config, redis));
  router.use('/analysis', createAnalysisRouter(pool, config, redis));
  router.use('/search', createSearchRouter(pool, config, redis));
  router.use('/admin', createAdminRouter(userService, config, redis));

  const auth = createAuthMiddleware(config, redis);

  // Proxy feeds endpoints to the vuln-feeds service
  const feedsServiceUrl = process.env['VULN_FEEDS_URL'] ?? 'http://vuln-feeds:9000';
  const FEEDS_ALLOWED_ROLES = new Set<string>([UserRole.Analyst, UserRole.Admin, UserRole.SuperAdmin]);
  router.use('/feeds', auth, async (req, res) => {
    if (!req.user || !FEEDS_ALLOWED_ROLES.has(req.user.role)) {
      res.status(403).json({
        success: false,
        data: null,
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
        requestId: res.getHeader('x-request-id') as string,
        timestamp: new Date().toISOString(),
      });
      return;
    }
    try {
      const parsed = new URL(req.url, 'http://placeholder');
      const pathSegments = parsed.pathname.split('/').filter(Boolean);
      if (pathSegments.some(s => s === '..' || s === '.')) {
        res.status(400).json({ success: false, error: { code: 'BAD_REQUEST', message: 'Invalid path' } });
        return;
      }
      const targetUrl = `${feedsServiceUrl}/feeds${parsed.pathname}${parsed.search}`;
      const proxyRes = await fetch(targetUrl, {
        method: req.method,
        headers: {
          'Content-Type': req.headers['content-type'] ?? 'application/json',
          ...(process.env['INTERNAL_API_KEY'] ? { 'x-internal-api-key': process.env['INTERNAL_API_KEY'] } : {}),
        },
        body: ['POST', 'PUT', 'PATCH'].includes(req.method) ? JSON.stringify(req.body) : undefined,
        signal: AbortSignal.timeout(300_000),
      });
      const PROXY_HEADER_ALLOW = new Set(['content-type', 'content-length', 'content-disposition', 'cache-control', 'etag', 'last-modified']);
      for (const [key, value] of proxyRes.headers.entries()) {
        if (PROXY_HEADER_ALLOW.has(key.toLowerCase())) res.setHeader(key, value);
      }
      res.status(proxyRes.status);
      const buffer = Buffer.from(await proxyRes.arrayBuffer());
      res.send(buffer);
    } catch {
      res.status(502).json({
        success: false,
        error: { code: 'FEEDS_SERVICE_UNAVAILABLE', message: 'Vulnerability feeds service is not running' },
      });
    }
  });

  // Proxy reports endpoints to the reporting service
  const reportingServiceUrl = process.env['REPORTING_SERVICE_URL'] ?? 'http://reporting:3006';
  router.use('/reports', auth, async (req, res) => {
    try {
      // Sanitize the URL to prevent path traversal on the downstream service.
      const parsed = new URL(req.url, 'http://placeholder');
      const pathSegments = parsed.pathname.split('/').filter(Boolean);
      if (pathSegments.some(s => s === '..' || s === '.')) {
        res.status(400).json({ success: false, error: { code: 'BAD_REQUEST', message: 'Invalid path' } });
        return;
      }

      // Ownership check: if the first segment is a UUID, verify the user owns it
      const possibleId = pathSegments[0];
      if (possibleId && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(possibleId)) {
        const isAdmin = req.user!.role === 'admin' || req.user!.role === 'super_admin';
        if (!isAdmin) {
          const ownerCheck = await pool.query(
            'SELECT id FROM submissions WHERE id = $1 AND user_id = $2',
            [possibleId, req.user!.sub],
          );
          if (ownerCheck.rows.length === 0) {
            res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Submission not found' } });
            return;
          }
        }
      }

      const targetUrl = `${reportingServiceUrl}/reports${parsed.pathname}${parsed.search}`;
      const proxyRes = await fetch(targetUrl, {
        method: req.method,
        headers: {
          'Content-Type': req.headers['content-type'] ?? 'application/json',
          'x-request-id': (req.headers['x-request-id'] as string) ?? '',
          'x-authenticated-user-id': req.user!.sub,
          'x-authenticated-user-role': req.user!.role,
          ...(process.env['INTERNAL_API_KEY'] ? { 'x-internal-api-key': process.env['INTERNAL_API_KEY'] } : {}),
        },
        body: ['POST', 'PUT', 'PATCH'].includes(req.method) ? JSON.stringify(req.body) : undefined,
        signal: AbortSignal.timeout(300_000),
      });

      // Forward all response headers
      const PROXY_HEADER_ALLOW = new Set(['content-type', 'content-length', 'content-disposition', 'cache-control', 'etag', 'last-modified']);
      for (const [key, value] of proxyRes.headers.entries()) {
        if (PROXY_HEADER_ALLOW.has(key.toLowerCase())) res.setHeader(key, value);
      }
      res.status(proxyRes.status);
      const buffer = Buffer.from(await proxyRes.arrayBuffer());
      res.send(buffer);
    } catch {
      res.status(502).json({
        success: false,
        data: null,
        error: { code: 'REPORTING_SERVICE_UNAVAILABLE', message: 'Could not reach the reporting service' },
        requestId: (req.headers['x-request-id'] as string) ?? '',
        timestamp: new Date().toISOString(),
      });
    }
  });

  // Dashboard stats — scoped to the authenticated user's submissions
  router.get('/dashboard/stats', auth, async (req, res, next) => {
    try {
      const userId = req.user!.sub;
      const counts = await pool.query(`
        SELECT
          (SELECT count(*) FROM submissions WHERE user_id = $1)::int AS total,
          (SELECT count(*) FROM submissions WHERE user_id = $1 AND status IN ('queued','analyzing'))::int AS active,
          (SELECT count(*) FROM submissions WHERE user_id = $1 AND threat_level IN ('high','critical'))::int AS threats,
          (SELECT count(*) FROM submissions WHERE user_id = $1 AND status = 'review')::int AS review
      `, [userId]);
      const row = counts.rows[0] as { total: number; active: number; threats: number; review: number } | undefined;
      const recent = await pool.query(`
        SELECT id, filename, threat_level AS "threatLevel", status, created_at AS "createdAt"
        FROM submissions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10
      `, [userId]);
      res.json({
        success: true,
        data: {
          totalSubmissions: row?.total ?? 0,
          activeAnalyses: row?.active ?? 0,
          threatsDetected: row?.threats ?? 0,
          pendingReview: row?.review ?? 0,
          recentSubmissions: recent.rows,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  // Dashboard trends — submissions by day, threat distribution, top families, recent critical
  // All queries scoped to the authenticated user's submissions.
  router.get('/dashboard/trends', auth, async (req, res, next) => {
    try {
      const userId = req.user!.sub;

      // Submissions per day for the last 7 days
      const byDayResult = await pool.query(`
        SELECT
          d::date AS date,
          COALESCE(c.cnt, 0)::int AS count
        FROM generate_series(
          CURRENT_DATE - INTERVAL '6 days',
          CURRENT_DATE,
          '1 day'
        ) AS d
        LEFT JOIN (
          SELECT DATE(created_at) AS day, COUNT(*)::int AS cnt
          FROM submissions
          WHERE created_at >= CURRENT_DATE - INTERVAL '6 days' AND user_id = $1
          GROUP BY DATE(created_at)
        ) c ON c.day = d::date
        ORDER BY d ASC
      `, [userId]);

      // Threat level distribution
      const threatDistResult = await pool.query(`
        SELECT
          COALESCE(threat_level, 'informational') AS level,
          COUNT(*)::int AS count
        FROM submissions
        WHERE user_id = $1
        GROUP BY COALESCE(threat_level, 'informational')
        ORDER BY count DESC
      `, [userId]);

      // Top malware families (from threat intel results, scoped to user's submissions)
      const topFamiliesResult = await pool.query(`
        SELECT ti.malware_family AS name, COUNT(*)::int AS count
        FROM threat_intel_results ti
        JOIN submissions s ON s.id = ti.submission_id
        WHERE ti.malware_family IS NOT NULL AND ti.malware_family != '' AND s.user_id = $1
        GROUP BY ti.malware_family
        ORDER BY count DESC
        LIMIT 10
      `, [userId]);

      // Recent critical/high submissions
      const recentCriticalResult = await pool.query(`
        SELECT
          s.id,
          s.filename,
          s.threat_level AS "threatLevel",
          COALESCE(ti.malware_family, '') AS family
        FROM submissions s
        LEFT JOIN threat_intel_results ti ON ti.submission_id = s.id
        WHERE s.threat_level IN ('critical', 'high') AND s.user_id = $1
        ORDER BY s.created_at DESC
        LIMIT 10
      `, [userId]);

      res.json({
        success: true,
        data: {
          submissionsByDay: byDayResult.rows.map((r: Record<string, unknown>) => ({
            date: r['date'],
            count: r['count'],
          })),
          threatDistribution: threatDistResult.rows.map((r: Record<string, unknown>) => ({
            level: r['level'],
            count: r['count'],
          })),
          topFamilies: topFamiliesResult.rows.map((r: Record<string, unknown>) => ({
            name: r['name'],
            count: r['count'],
          })),
          recentCritical: recentCriticalResult.rows.map((r: Record<string, unknown>) => ({
            id: r['id'],
            filename: r['filename'],
            threatLevel: r['threatLevel'],
            family: r['family'],
          })),
        },
      });
    } catch (err) {
      next(err);
    }
  });

  // ATT&CK matrix — scoped to the authenticated user's submissions
  router.get('/attack-matrix', auth, async (req, res, next) => {
    try {
      const userId = req.user!.sub;
      const result = await pool.query(`
        SELECT at.tactic_id, at.technique_id, count(*)::int AS count
        FROM attack_techniques at
        JOIN submissions s ON s.id = at.submission_id
        WHERE s.user_id = $1
        GROUP BY at.tactic_id, at.technique_id
      `, [userId]);
      const tactics = new Map<string, { id: string; name: string; techniques: Array<{ id: string; name: string; count: number }> }>();
      for (const row of result.rows as Array<{ tactic_id: string; technique_id: string; count: number }>) {
        if (!tactics.has(row.tactic_id)) {
          tactics.set(row.tactic_id, { id: row.tactic_id, name: row.tactic_id, techniques: [] });
        }
        tactics.get(row.tactic_id)!.techniques.push({ id: row.technique_id, name: row.technique_id, count: row.count });
      }
      res.json({ success: true, data: [...tactics.values()] });
    } catch (err) {
      next(err);
    }
  });

  // ── API Documentation (Swagger UI) ──────────────────────────────────────────

  // Serve the OpenAPI spec as YAML
  router.get('/openapi.yaml', (_req, res) => {
    try {
      const currentDir = __dirname;
      const specPath = join(currentDir, '..', '..', '..', '..', 'docs', 'api', 'openapi.yaml');
      const spec = readFileSync(specPath, 'utf-8');
      res.setHeader('Content-Type', 'text/yaml');
      res.send(spec);
    } catch {
      res.status(404).send('OpenAPI spec not found');
    }
  });

  // Serve Swagger UI HTML page at /api/docs (note: mounted under /api/v1, so actual path is /api/v1/docs)
  // We also mount at the parent level via the app for /api/docs convenience
  router.get('/docs', (_req, res) => {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>FraudVault API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui.css" />
  <style>
    body { margin: 0; background: #1a1a2e; }
    .swagger-ui .topbar { display: none; }
    .swagger-ui { max-width: 1200px; margin: 0 auto; padding: 20px; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: '/api/v1/openapi.yaml',
      dom_id: '#swagger-ui',
      deepLinking: true,
      presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset,
      ],
      layout: 'BaseLayout',
    });
  </script>
</body>
</html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });

  return router;
}
