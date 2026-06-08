import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validation.js';
import type Redis from 'ioredis';
import { createAuthMiddleware } from '../middleware/auth.js';
import type { AppConfig } from '../config.js';
import type pg from 'pg';

const searchSchema = z.object({
  q: z.string().min(1).max(500),
  field: z.enum(['all', 'hash', 'filename', 'domain', 'url', 'ip', 'registry_key', 'malware_family', 'attack_technique']).default('all'),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
});

interface SearchHit {
  id: string;
  filename: string;
  sha256: string;
  threatScore: number | null;
  threatLevel: string | null;
  status: string;
  createdAt: string;
  matchField: string;
  matchValue?: string;
  vt?: {
    detections: number;
    total: number;
    link: string | null;
    family: string | null;
  } | null;
}

function mapRow(row: Record<string, unknown>, matchField: string, matchValue?: string): SearchHit {
  return {
    id: String(row['id'] ?? ''),
    filename: String(row['filename'] ?? ''),
    sha256: String(row['sha256'] ?? ''),
    threatScore: row['threat_score'] != null ? Number(row['threat_score']) : null,
    threatLevel: row['threat_level'] ? String(row['threat_level']) : null,
    status: String(row['status'] ?? ''),
    createdAt: String(row['created_at'] ?? ''),
    matchField,
    matchValue,
    vt: null,
  };
}

async function enrichWithVt(pool: pg.Pool, hits: SearchHit[]): Promise<void> {
  if (hits.length === 0) return;
  const ids = hits.map(h => h.id);
  const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
  const vtRes = await pool.query(
    `SELECT submission_id, provider, detection_count, total_engines, malware_family, raw_response
     FROM threat_intel_results
     WHERE submission_id IN (${placeholders}) AND provider LIKE 'virustotal%'
     ORDER BY total_engines DESC`,
    ids,
  );
  const vtBySubmission = new Map<string, { detections: number; total: number; link: string | null; family: string | null }>();
  for (const row of vtRes.rows as Array<Record<string, unknown>>) {
    const sid = String(row['submission_id']);
    if (vtBySubmission.has(sid)) continue;
    const raw = row['raw_response'] as Record<string, unknown> | null;
    vtBySubmission.set(sid, {
      detections: Number(row['detection_count'] ?? 0),
      total: Number(row['total_engines'] ?? 0),
      link: (raw?.['vtLink'] as string) ?? null,
      family: row['malware_family'] ? String(row['malware_family']) : null,
    });
  }
  for (const hit of hits) {
    hit.vt = vtBySubmission.get(hit.id) ?? null;
  }
}

export function createSearchRouter(pool: pg.Pool, config: AppConfig, redis?: Redis): Router {
  const router = Router();
  const auth = createAuthMiddleware(config, redis);

  router.use(auth);

  router.get(
    '/',
    validate({ query: searchSchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { q, field, page, pageSize } = req.query as unknown as z.infer<typeof searchSchema>;
        const userId = req.user!.sub;
        const offset = (page - 1) * pageSize;
        const escaped = q.replace(/[%_\\]/g, '\\$&');

        let hits: SearchHit[] = [];

        if (field === 'hash') {
          const normalized = q.toLowerCase().replace(/[^a-f0-9]/g, '');
          if (normalized.length >= 32) {
            const result = await pool.query(
              `SELECT id, filename, sha256, threat_score, threat_level, status, created_at
               FROM submissions
               WHERE (md5 = $1 OR sha1 = $1 OR sha256 = $1) AND user_id = $2
               ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
              [normalized, userId, pageSize, offset],
            );
            hits = (result.rows as Record<string, unknown>[]).map(r => mapRow(r, 'hash', normalized));
          }
        } else if (field === 'filename') {
          const result = await pool.query(
            `SELECT id, filename, sha256, threat_score, threat_level, status, created_at
             FROM submissions
             WHERE filename ILIKE $1 ESCAPE '\\' AND user_id = $2
             ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
            [`%${escaped}%`, userId, pageSize, offset],
          );
          hits = (result.rows as Record<string, unknown>[]).map(r => mapRow(r, 'filename', q));
        } else if (['domain', 'url', 'ip', 'registry_key'].includes(field)) {
          const iocType = field === 'registry_key' ? 'registry_key' : field;
          const result = await pool.query(
            `SELECT DISTINCT ON (s.id) s.id, s.filename, s.sha256, s.threat_score, s.threat_level, s.status, s.created_at,
                    i.value AS matched_ioc, i.type AS ioc_type
             FROM iocs i
             JOIN submissions s ON s.id = i.submission_id
             WHERE i.value ILIKE $1 ESCAPE '\\' AND i.type = $2 AND s.user_id = $3
             ORDER BY s.id, s.created_at DESC LIMIT $4 OFFSET $5`,
            [`%${escaped}%`, iocType, userId, pageSize, offset],
          );
          hits = (result.rows as Record<string, unknown>[]).map(r => mapRow(r, field, String(r['matched_ioc'] ?? '')));
        } else if (field === 'malware_family') {
          const result = await pool.query(
            `SELECT DISTINCT ON (s.id) s.id, s.filename, s.sha256, s.threat_score, s.threat_level, s.status, s.created_at,
                    ti.malware_family
             FROM threat_intel_results ti
             JOIN submissions s ON s.id = ti.submission_id
             WHERE ti.malware_family ILIKE $1 ESCAPE '\\' AND s.user_id = $2
             ORDER BY s.id, s.created_at DESC LIMIT $3 OFFSET $4`,
            [`%${escaped}%`, userId, pageSize, offset],
          );
          hits = (result.rows as Record<string, unknown>[]).map(r => mapRow(r, 'malware_family', String(r['malware_family'] ?? '')));
        } else if (field === 'attack_technique') {
          const result = await pool.query(
            `SELECT DISTINCT ON (s.id) s.id, s.filename, s.sha256, s.threat_score, s.threat_level, s.status, s.created_at,
                    at.technique_id
             FROM attack_techniques at
             JOIN submissions s ON s.id = at.submission_id
             WHERE at.technique_id ILIKE $1 ESCAPE '\\' AND s.user_id = $2
             ORDER BY s.id, s.created_at DESC LIMIT $3 OFFSET $4`,
            [`%${escaped}%`, userId, pageSize, offset],
          );
          hits = (result.rows as Record<string, unknown>[]).map(r => mapRow(r, 'attack_technique', String(r['technique_id'] ?? '')));
        } else {
          // field === 'all': search filename first, then hashes, then IOCs
          const normalized = q.toLowerCase().replace(/[^a-f0-9]/g, '');
          const isHash = /^[a-f0-9]{32,128}$/.test(normalized);

          if (isHash) {
            const result = await pool.query(
              `SELECT id, filename, sha256, threat_score, threat_level, status, created_at
               FROM submissions
               WHERE (md5 = $1 OR sha1 = $1 OR sha256 = $1) AND user_id = $2
               ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
              [normalized, userId, pageSize, offset],
            );
            hits = (result.rows as Record<string, unknown>[]).map(r => mapRow(r, 'hash', normalized));
          }

          if (hits.length === 0) {
            const result = await pool.query(
              `SELECT id, filename, sha256, threat_score, threat_level, status, created_at
               FROM submissions
               WHERE filename ILIKE $1 ESCAPE '\\' AND user_id = $2
               ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
              [`%${escaped}%`, userId, pageSize, offset],
            );
            hits = (result.rows as Record<string, unknown>[]).map(r => mapRow(r, 'filename', q));
          }

          if (hits.length === 0) {
            const result = await pool.query(
              `SELECT DISTINCT ON (s.id) s.id, s.filename, s.sha256, s.threat_score, s.threat_level, s.status, s.created_at,
                      i.value AS matched_ioc, i.type AS ioc_type
               FROM iocs i
               JOIN submissions s ON s.id = i.submission_id
               WHERE i.value ILIKE $1 ESCAPE '\\' AND s.user_id = $2
               ORDER BY s.id, s.created_at DESC LIMIT $3 OFFSET $4`,
              [`%${escaped}%`, userId, pageSize, offset],
            );
            hits = (result.rows as Record<string, unknown>[]).map(r => mapRow(r, String(r['ioc_type'] ?? 'ioc'), String(r['matched_ioc'] ?? '')));
          }
        }

        // Enrich all results with VT data
        await enrichWithVt(pool, hits);

        res.status(200).json({
          success: true,
          data: hits,
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}
