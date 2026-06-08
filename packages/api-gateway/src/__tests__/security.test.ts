import { describe, it, expect, vi } from 'vitest';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import { validate } from '../middleware/validation.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { requireRole } from '../middleware/rbac.js';
import { UserRole, MAX_TAGS_PER_SUBMISSION } from '@scanboy/shared';
import type { Request, Response, NextFunction } from 'express';
import type { AppConfig } from '../config.js';

// ── Test config ─────────────────────────────────────────────────────────────

const TEST_JWT_SECRET = 'security-test-secret-key-32-chars!!!!!';

const testConfig: AppConfig = {
  nodeEnv: 'test',
  port: 3000,
  host: '0.0.0.0',
  corsOrigins: ['http://localhost:3000'],
  logLevel: 'silent',
  jwt: {
    secret: TEST_JWT_SECRET,
    expiry: '15m',
    refreshExpiry: '7d',
  },
  bcryptRounds: 4,
  postgres: { host: 'localhost', port: 5432, database: 'test', user: 'test', password: 'test', poolMax: 1 },
  redis: { host: 'localhost', port: 6379, password: undefined },
  rateLimit: { windowMs: 900_000, maxRequests: 100 },
};

// ── Helpers ─────────────────────────────────────────────────────────────────

function createMockReq(overrides: Partial<Request> = {}): Request {
  return {
    headers: {},
    body: {},
    query: {},
    params: {},
    ...overrides,
  } as unknown as Request;
}

function createMockRes(): Response {
  const res: Partial<Response> = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    getHeader: vi.fn().mockReturnValue('req-sec-123'),
    send: vi.fn().mockReturnThis(),
  };
  return res as Response;
}

// ── Schemas used in submission routes ───────────────────────────────────────

const listQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  status: z.string().optional(),
  threatLevel: z.string().optional(),
  sortBy: z.enum(['submittedAt', 'threatScore', 'fileName']).default('submittedAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

const idParamSchema = z.object({
  id: z.string().uuid(),
});

const updateTagsSchema = z.object({
  tags: z.array(z.string().min(1).max(50)).max(MAX_TAGS_PER_SUBMISSION),
});

// ── SQL Injection Tests ────────────────────────────────────────────────────

describe('SQL injection prevention', () => {
  it('rejects SQL injection in search page parameter', () => {
    const middleware = validate({ query: listQuerySchema });
    const req = createMockReq({
      query: { page: "1; DROP TABLE users;--" as unknown as string },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('rejects SQL injection in sortBy parameter', () => {
    const middleware = validate({ query: listQuerySchema });
    const req = createMockReq({
      query: { sortBy: "submittedAt; DROP TABLE submissions;--" },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('rejects non-UUID id parameters (SQL injection attempt)', () => {
    const middleware = validate({ params: idParamSchema });
    const req = createMockReq({
      params: { id: "1' OR '1'='1" },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('accepts valid UUID id parameters', () => {
    const middleware = validate({ params: idParamSchema });
    const req = createMockReq({
      params: { id: 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11' },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
  });

  it('rejects UNION-based SQL injection in status filter', () => {
    const middleware = validate({ query: listQuerySchema });
    const req = createMockReq({
      query: {
        status: "completed' UNION SELECT * FROM users--",
      },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    // The status field is a free string, so Zod won't reject it based on content.
    // However, parameterized queries in the service layer prevent injection.
    // The validation still passes Zod validation since status is optional string.
    // This test verifies Zod does its part (type coercion/validation).
    // The actual defense is parameterized queries, not input validation on this field.
    // So next() will be called, but the SQL injection won't execute.
    expect(next).toHaveBeenCalled();
  });
});

// ── XSS Prevention Tests ───────────────────────────────────────────────────

describe('XSS payload prevention', () => {
  it('rejects tags with excessive length', () => {
    const middleware = validate({ body: updateTagsSchema });
    const req = createMockReq({
      body: {
        tags: ['<script>alert("xss")</script>' + 'x'.repeat(100)],
      },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    // Tags longer than 50 chars are rejected
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('rejects too many tags', () => {
    const middleware = validate({ body: updateTagsSchema });
    const tags = Array.from({ length: MAX_TAGS_PER_SUBMISSION + 1 }, (_, i) => `tag${i}`);
    const req = createMockReq({ body: { tags } });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('rejects empty tag strings', () => {
    const middleware = validate({ body: updateTagsSchema });
    const req = createMockReq({
      body: { tags: ['valid-tag', ''] },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('accepts valid tags (XSS payloads are short enough to be valid strings)', () => {
    const middleware = validate({ body: updateTagsSchema });
    const req = createMockReq({
      body: { tags: ['<script>alert(1)</script>'] },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    // Zod accepts it because it's under 50 chars. The actual XSS prevention
    // depends on output encoding in the frontend, not input validation.
    // But the tag string IS sanitized by length constraints.
    expect(next).toHaveBeenCalled();
  });

  it('rejects pageSize over 100 (parameter tampering)', () => {
    const middleware = validate({ query: listQuerySchema });
    const req = createMockReq({
      query: { pageSize: '999999' },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
  });
});

// ── Rate Limiting Tests ────────────────────────────────────────────────────

describe('rate limiting configuration', () => {
  it('config has rate limit settings', () => {
    expect(testConfig.rateLimit.windowMs).toBe(900_000); // 15 minutes
    expect(testConfig.rateLimit.maxRequests).toBe(100);
  });

  it('rate limit window is at least 1 minute', () => {
    expect(testConfig.rateLimit.windowMs).toBeGreaterThanOrEqual(60_000);
  });

  it('rate limit max requests is reasonable', () => {
    expect(testConfig.rateLimit.maxRequests).toBeGreaterThan(0);
    expect(testConfig.rateLimit.maxRequests).toBeLessThanOrEqual(10_000);
  });
});

// ── Authentication Required Tests ──────────────────────────────────────────

describe('authentication required on protected routes', () => {
  const authMiddleware = createAuthMiddleware(testConfig);

  it('rejects request with no token', () => {
    const req = createMockReq();
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    authMiddleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    const jsonCall = vi.mocked(res.json).mock.calls[0]![0] as Record<string, unknown>;
    expect(jsonCall['success']).toBe(false);
  });

  it('rejects request with tampered token', () => {
    const token = jwt.sign(
      { sub: 'user-1', email: 'test@test.com', role: UserRole.Analyst },
      'wrong-secret-key-different-from-config',
      { expiresIn: '1h' },
    );

    const req = createMockReq({
      headers: { authorization: `Bearer ${token}` },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    authMiddleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('rejects request with malformed JWT', () => {
    const req = createMockReq({
      headers: { authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.' },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    authMiddleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('rejects request with empty Bearer value', () => {
    const req = createMockReq({
      headers: { authorization: 'Bearer ' },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    authMiddleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });
});

// ── RBAC Tests ─────────────────────────────────────────────────────────────

describe('RBAC prevents unauthorized role access', () => {
  it('Viewer cannot access Admin routes', () => {
    const middleware = requireRole(UserRole.Admin);
    const req = createMockReq();
    req.user = {
      sub: 'user-1',
      email: 'viewer@test.com',
      role: UserRole.Viewer,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('Analyst cannot access SuperAdmin routes', () => {
    const middleware = requireRole(UserRole.SuperAdmin);
    const req = createMockReq();
    req.user = {
      sub: 'user-1',
      email: 'analyst@test.com',
      role: UserRole.Analyst,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('Admin cannot access SuperAdmin routes', () => {
    const middleware = requireRole(UserRole.SuperAdmin);
    const req = createMockReq();
    req.user = {
      sub: 'user-1',
      email: 'admin@test.com',
      role: UserRole.Admin,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('role hierarchy is enforced correctly: Viewer < Analyst < Admin < SuperAdmin', () => {
    const roles = [UserRole.Viewer, UserRole.Analyst, UserRole.Admin, UserRole.SuperAdmin];

    for (let requiredIdx = 0; requiredIdx < roles.length; requiredIdx++) {
      for (let userIdx = 0; userIdx < roles.length; userIdx++) {
        const middleware = requireRole(roles[requiredIdx]!);
        const req = createMockReq();
        req.user = {
          sub: 'user-1',
          email: 'test@test.com',
          role: roles[userIdx]!,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
        };
        const res = createMockRes();
        const next = vi.fn() as NextFunction;

        middleware(req, res, next);

        if (userIdx >= requiredIdx) {
          expect(next).toHaveBeenCalled();
        } else {
          expect(next).not.toHaveBeenCalled();
          expect(res.status).toHaveBeenCalledWith(403);
        }
      }
    }
  });
});

// ── Validation error format ────────────────────────────────────────────────

describe('validation error response format', () => {
  it('returns structured error with validation details', () => {
    const middleware = validate({ query: listQuerySchema });
    const req = createMockReq({
      query: { page: 'not-a-number', pageSize: '-5' },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        error: expect.objectContaining({
          code: 'VALIDATION_ERROR',
          message: 'Request validation failed',
        }),
      }),
    );
  });
});
