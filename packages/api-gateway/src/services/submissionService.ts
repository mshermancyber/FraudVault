import { createHash } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import type pg from 'pg';
import type Redis from 'ioredis';
import { SUPPORTED_FILE_EXTENSIONS } from '@scanboy/shared';
import { AppError } from '../middleware/errorHandler.js';

const PRIVATE_IP_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i,
  /^fd/i,
  /^::ffff:(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.)/i,
];

interface ListQuery {
  page: number;
  pageSize: number;
  status?: string;
  threatLevel?: string;
  sortBy: string;
  sortOrder: string;
}

interface SubmissionRow {
  id: string;
  user_id: string;
  filename: string;
  file_size: number;
  file_type: string;
  mime_type: string;
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
  submission_type: string;
  status: string;
  threat_level: string | null;
  threat_score: number | null;
  created_at: string;
  updated_at: string;
}

function mapRow(row: SubmissionRow): Record<string, unknown> {
  return {
    id: row.id,
    userId: row.user_id,
    filename: row.filename,
    fileSize: row.file_size,
    fileType: row.file_type,
    mimeType: row.mime_type,
    md5: row.md5?.trim(),
    sha1: row.sha1?.trim(),
    sha256: row.sha256?.trim(),
    sha512: row.sha512?.trim(),
    submissionType: row.submission_type,
    status: row.status,
    threatLevel: row.threat_level ?? 'informational',
    threatScore: row.threat_score ?? 0,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const ALLOWED_SORT_COLUMNS: ReadonlySet<string> = new Set([
  'submittedAt',
  'threatScore',
  'fileName',
]);

const SORT_COLUMN_MAP: Record<string, string> = {
  submittedAt: 'created_at',
  threatScore: 'threat_score',
  fileName: 'filename',
};

export class SubmissionService {
  constructor(
    private readonly pool: pg.Pool,
    private readonly redis?: Redis,
  ) {}

  async list(userId: string, query: ListQuery): Promise<{ data: Record<string, unknown>[]; total: number; page: number; pageSize: number; totalPages: number }> {
    const { page, pageSize, status, threatLevel, sortBy, sortOrder } = query;
    const offset = (page - 1) * pageSize;

    const conditions: string[] = [];
    const params: Array<string | number> = [];

    // Always scope to the authenticated user's submissions.
    params.push(userId);
    conditions.push(`user_id = $${String(params.length)}`);

    if (status) {
      params.push(status);
      conditions.push(`status = $${String(params.length)}`);
    }

    if (threatLevel) {
      params.push(threatLevel);
      conditions.push(`threat_level = $${String(params.length)}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const resolvedSort = ALLOWED_SORT_COLUMNS.has(sortBy)
      ? (SORT_COLUMN_MAP[sortBy] ?? 'created_at')
      : 'created_at';
    const resolvedOrder = sortOrder === 'asc' ? 'ASC' : 'DESC';

    const countResult = await this.pool.query(
      `SELECT COUNT(*) as total FROM submissions ${whereClause}`,
      params,
    );
    const total = parseInt(countResult.rows[0]?.total as string, 10) || 0;

    params.push(pageSize, offset);
    const dataResult = await this.pool.query(
      `SELECT * FROM submissions ${whereClause}
       ORDER BY ${resolvedSort} ${resolvedOrder}
       LIMIT $${String(params.length - 1)} OFFSET $${String(params.length)}`,
      params,
    );

    return {
      data: dataResult.rows.map((row) => mapRow(row as SubmissionRow)),
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
    };
  }

  async getById(id: string, userId: string): Promise<Record<string, unknown>> {
    const result = await this.pool.query(
      `SELECT * FROM submissions WHERE id = $1 AND user_id = $2`,
      [id, userId],
    );

    if (result.rows.length === 0) {
      throw new AppError(404, 'NOT_FOUND', 'Submission not found');
    }

    const submission = mapRow(result.rows[0] as SubmissionRow);

    const [staticRes, dynamicRes, tiRes, iocRes, attackRes, notesRes, jobsRes] = await Promise.all([
      this.pool.query('SELECT * FROM static_analysis_results WHERE submission_id = $1', [id]),
      this.pool.query('SELECT id, submission_id, processes, network_activity, memory_activity, duration_seconds, created_at FROM dynamic_analysis_results WHERE submission_id = $1', [id]),
      this.pool.query('SELECT * FROM threat_intel_results WHERE submission_id = $1', [id]),
      this.pool.query('SELECT type, value, context, confidence FROM iocs WHERE submission_id = $1 ORDER BY confidence DESC', [id]),
      this.pool.query('SELECT tactic_id AS "tacticId", technique_id AS "techniqueId", evidence, confidence FROM attack_techniques WHERE submission_id = $1 ORDER BY confidence DESC', [id]),
      this.pool.query(`SELECT sn.id, sn.content, u.username, sn.created_at AS "createdAt"
        FROM submission_notes sn JOIN users u ON sn.user_id = u.id
        WHERE sn.submission_id = $1 ORDER BY sn.created_at DESC`, [id]),
      this.pool.query('SELECT id, job_type AS "jobType", status, started_at AS "startedAt", completed_at AS "completedAt" FROM analysis_jobs WHERE submission_id = $1', [id]),
    ]);

    return {
      ...submission,
      staticAnalysis: staticRes.rows[0] ?? null,
      dynamicAnalysis: dynamicRes.rows[0] ?? null,
      threatIntel: tiRes.rows,
      iocs: iocRes.rows,
      attackTechniques: attackRes.rows,
      notes: notesRes.rows,
      jobs: jobsRes.rows,
    };
  }

  async create(
    userId: string,
    file: Express.Multer.File,
    _tags?: string[],
    options?: { networkMode?: string; timeout?: number; analysisWorkflow?: 'default' | 'container' },
  ): Promise<Record<string, unknown>> {
    const ext = this.extractExtension(file.originalname);
    if (ext && !SUPPORTED_FILE_EXTENSIONS.has(ext)) {
      throw new AppError(400, 'UNSUPPORTED_FILE_TYPE', `File extension "${ext}" is not supported`);
    }

    const md5 = createHash('md5').update(file.buffer).digest('hex');
    const sha1 = createHash('sha1').update(file.buffer).digest('hex');
    const sha256 = createHash('sha256').update(file.buffer).digest('hex');
    const sha512 = createHash('sha512').update(file.buffer).digest('hex');

    const submissionType = options?.analysisWorkflow === 'container' ? 'container' : this.detectSubmissionType(file.originalname, file.mimetype);

    const result = await this.pool.query(
      `INSERT INTO submissions
         (user_id, filename, file_size, file_type, mime_type, md5, sha1, sha256, sha512, submission_type, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'submitted')
       RETURNING *`,
      [
        userId,
        file.originalname.replace(/[<>"'&]/g, '_').replace(/[^\x20-\x7E]/g, '_').slice(0, 255),
        file.size,
        ext ?? 'unknown',
        file.mimetype,
        md5,
        sha1,
        sha256,
        sha512,
        submissionType,
      ],
    );

    const submission = mapRow(result.rows[0] as SubmissionRow);

    if (this.redis) {
      // Store file buffer in Redis for orchestrator to pick up (TTL 1 hour)
      await this.redis.setex(
        `scanboy:file:${submission['id'] as string}`,
        3600,
        file.buffer.toString('base64'),
      );
      await this.redis.publish('scanboy:submissions:new', JSON.stringify({
        submissionId: submission['id'],
        sha256: submission['sha256'],
        storagePath: `redis:scanboy:file:${submission['id'] as string}`,
        userId,
        filename: file.originalname,
        options: options ?? undefined,
      }));
    }

    return submission;
  }

  async createUrlSubmission(
    userId: string,
    url: string,
  ): Promise<Record<string, unknown>> {
    // Normalize GitHub blob URLs to raw download URLs
    let downloadUrl = url;
    const ghBlobMatch = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/blob\/(.+)$/.exec(url);
    if (ghBlobMatch) {
      downloadUrl = `https://raw.githubusercontent.com/${ghBlobMatch[1]}/${ghBlobMatch[2]}`;
    }

    // SSRF guard: resolve hostname and reject private/internal IPs
    const parsedUrl = new URL(downloadUrl);
    const hostname = parsedUrl.hostname;
    if (hostname === 'localhost' || hostname.startsWith('[') || hostname.endsWith('.local') || hostname.endsWith('.internal') || /^\d+$/.test(hostname)) {
      throw new AppError(400, 'URL_BLOCKED', 'URLs targeting internal or local hosts are not allowed');
    }
    let resolvedAddress: string;
    try {
      const { address } = await lookup(hostname);
      if (PRIVATE_IP_RANGES.some(r => r.test(address))) {
        throw new AppError(400, 'URL_BLOCKED', 'URLs resolving to private IP addresses are not allowed');
      }
      resolvedAddress = address;
    } catch (err) {
      if (err instanceof AppError) throw err;
      throw new AppError(400, 'URL_DOWNLOAD_FAILED', `Cannot resolve hostname: ${hostname}`);
    }

    // Pin to resolved IP to prevent DNS rebinding (TOCTOU)
    const pinnedUrl = new URL(downloadUrl);
    pinnedUrl.hostname = resolvedAddress;

    // Download the file from the URL
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120_000);
    let fileBuffer: Buffer;
    let contentType = 'application/octet-stream';
    try {
      let currentUrl = pinnedUrl.href;
      let currentHostHeader = hostname;
      let resp: Response | null = null;
      for (let redirects = 0; redirects < 10; redirects++) {
        resp = await fetch(currentUrl, {
          signal: controller.signal,
          headers: { 'User-Agent': 'FraudVault/1.0', 'Host': currentHostHeader },
          redirect: 'manual',
        });
        if (resp.status < 300 || resp.status >= 400 || !resp.headers.get('location')) break;
        const redirectTarget = new URL(resp.headers.get('location')!, currentUrl);
        if (redirectTarget.protocol !== 'http:' && redirectTarget.protocol !== 'https:') {
          throw new AppError(400, 'URL_BLOCKED', 'Redirect to non-HTTP protocol blocked');
        }
        const rHost = redirectTarget.hostname;
        if (rHost === 'localhost' || rHost.startsWith('[') || rHost.endsWith('.local') || rHost.endsWith('.internal')) {
          throw new AppError(400, 'URL_BLOCKED', 'Redirect to internal host blocked');
        }
        let rAddr: string;
        try {
          const result = await lookup(rHost);
          rAddr = result.address;
          if (PRIVATE_IP_RANGES.some(r => r.test(rAddr))) {
            throw new AppError(400, 'URL_BLOCKED', 'Redirect to private IP address blocked');
          }
        } catch (e) {
          if (e instanceof AppError) throw e;
          throw new AppError(400, 'URL_DOWNLOAD_FAILED', `Cannot resolve redirect target: ${rHost}`);
        }
        const pinnedRedirect = new URL(redirectTarget.href);
        pinnedRedirect.hostname = rAddr;
        currentUrl = pinnedRedirect.href;
        currentHostHeader = rHost;
      }
      if (!resp) throw new AppError(400, 'URL_DOWNLOAD_FAILED', 'No response received');
      if (!resp.ok) {
        throw new AppError(400, 'URL_DOWNLOAD_FAILED', `Failed to download URL: HTTP ${String(resp.status)}`);
      }
      const maxSize = 100 * 1024 * 1024; // 100MB
      const clHeader = resp.headers.get('content-length');
      if (clHeader && parseInt(clHeader, 10) > maxSize) {
        throw new AppError(400, 'FILE_TOO_LARGE', 'Remote file exceeds 100MB limit');
      }
      const reader = resp.body?.getReader();
      if (!reader) throw new AppError(400, 'URL_DOWNLOAD_FAILED', 'No response body');
      const chunks: Uint8Array[] = [];
      let totalSize = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        totalSize += value.byteLength;
        if (totalSize > maxSize) {
          await reader.cancel();
          throw new AppError(400, 'FILE_TOO_LARGE', 'Downloaded file exceeds 100MB limit');
        }
        chunks.push(value);
      }
      fileBuffer = Buffer.concat(chunks);
      contentType = resp.headers.get('content-type') ?? contentType;
    } catch (err) {
      if (err instanceof AppError) throw err;
      throw new AppError(400, 'URL_DOWNLOAD_FAILED', `Failed to download URL: ${String((err as Error).message)}`);
    } finally {
      clearTimeout(timeout);
    }

    const rawFilename = url.split('/').pop() || url.split('/').filter(Boolean).pop() || 'download';
    const filename = decodeURIComponent(rawFilename).replace(/[/\\<>"'&]/g, '_').replace(/[^\x20-\x7E]/g, '_').slice(0, 255) || 'download';
    const ext = this.extractExtension(filename);
    if (ext && !SUPPORTED_FILE_EXTENSIONS.has(ext)) {
      throw new AppError(400, 'UNSUPPORTED_FILE_TYPE', `File extension "${ext}" is not supported`);
    }
    const md5 = createHash('md5').update(fileBuffer).digest('hex');
    const sha1 = createHash('sha1').update(fileBuffer).digest('hex');
    const sha256 = createHash('sha256').update(fileBuffer).digest('hex');
    const sha512 = createHash('sha512').update(fileBuffer).digest('hex');

    const result = await this.pool.query(
      `INSERT INTO submissions
         (user_id, filename, file_size, file_type, mime_type, md5, sha1, sha256, sha512, submission_type, status, source_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'url', 'submitted', $10)
       RETURNING *`,
      [
        userId,
        filename,
        fileBuffer.length,
        ext ?? 'unknown',
        contentType,
        md5,
        sha1,
        sha256,
        sha512,
        url,
      ],
    );

    const submission = mapRow(result.rows[0] as SubmissionRow);

    if (this.redis) {
      await this.redis.setex(
        `scanboy:file:${submission['id'] as string}`,
        3600,
        fileBuffer.toString('base64'),
      );
      await this.redis.publish('scanboy:submissions:new', JSON.stringify({
        submissionId: submission['id'],
        sha256: submission['sha256'],
        storagePath: `redis:scanboy:file:${submission['id'] as string}`,
        userId,
        filename,
      }));
    }

    return submission;
  }

  async updateTags(id: string, userId: string, tags: string[]): Promise<Record<string, unknown>> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Verify ownership before modifying tags.
      const ownerCheck = await client.query(
        'SELECT id FROM submissions WHERE id = $1 AND user_id = $2',
        [id, userId],
      );
      if (ownerCheck.rows.length === 0) {
        throw new AppError(404, 'NOT_FOUND', 'Submission not found');
      }

      await client.query('DELETE FROM submission_tags WHERE submission_id = $1', [id]);
      for (const tag of tags) {
        await client.query('INSERT INTO submission_tags (submission_id, tag) VALUES ($1, $2)', [id, tag]);
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
    return this.getById(id, userId);
  }

  async delete(id: string, userId: string): Promise<void> {
    const result = await this.pool.query(
      `DELETE FROM submissions WHERE id = $1 AND user_id = $2 RETURNING id`,
      [id, userId],
    );

    if (result.rows.length === 0) {
      throw new AppError(404, 'NOT_FOUND', 'Submission not found');
    }
  }

  private detectSubmissionType(filename: string, mimeType: string): string {
    const ext = this.extractExtension(filename)?.toLowerCase() ?? '';
    if (['.eml', '.msg'].includes(ext)) return 'email';
    if (mimeType.includes('docker') || mimeType.includes('oci')) return 'container';
    return 'file';
  }

  private extractExtension(filename: string): string | null {
    const dotIndex = filename.lastIndexOf('.');
    if (dotIndex === -1) return null;
    return filename.slice(dotIndex).toLowerCase();
  }
}
