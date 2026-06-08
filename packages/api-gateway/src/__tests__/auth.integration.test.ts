import { describe, it, expect, vi, beforeEach } from 'vitest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { AuthService } from '../services/authService.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { requireRole } from '../middleware/rbac.js';
import { UserRole } from '@scanboy/shared';
import type { AppConfig } from '../config.js';
import type { Request, Response, NextFunction } from 'express';

// ── Config ──────────────────────────────────────────────────────────────────

const TEST_JWT_SECRET = 'test-secret-key-for-unit-testing-only-32-chars!!';

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
  bcryptRounds: 4, // Low for speed in tests
  postgres: {
    host: 'localhost',
    port: 5432,
    database: 'test',
    user: 'test',
    password: 'test',
    poolMax: 1,
  },
  redis: {
    host: 'localhost',
    port: 6379,
    password: undefined,
  },
  rateLimit: {
    windowMs: 900_000,
    maxRequests: 100,
  },
};

// ── Mock DB pool ────────────────────────────────────────────────────────────

function createMockPool() {
  return {
    query: vi.fn(),
    connect: vi.fn(),
    end: vi.fn(),
    on: vi.fn(),
  };
}

function createMockRedis() {
  return {
    get: vi.fn(),
    set: vi.fn(),
    setex: vi.fn(),
    del: vi.fn(),
    quit: vi.fn(),
  };
}

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
    getHeader: vi.fn().mockReturnValue('req-123'),
    send: vi.fn().mockReturnThis(),
  };
  return res as Response;
}

describe('AuthService integration', () => {
  let mockPool: ReturnType<typeof createMockPool>;
  let mockRedis: ReturnType<typeof createMockRedis>;
  let authService: AuthService;

  beforeEach(() => {
    mockPool = createMockPool();
    mockRedis = createMockRedis();
    authService = new AuthService(
      mockPool as unknown as import('pg').Pool,
      mockRedis as unknown as import('ioredis').default,
      testConfig,
    );
  });

  describe('login with valid credentials', () => {
    it('returns tokens for valid credentials without MFA', async () => {
      const passwordHash = await bcrypt.hash('correct-password', 4);
      mockPool.query.mockResolvedValueOnce({
        rows: [
          {
            id: 'user-1',
            email: 'analyst@scanboy.io',
            display_name: 'Analyst',
            role: UserRole.Analyst,
            password_hash: passwordHash,
            mfa_enabled: false,
          },
        ],
      });
      // Update last login query
      mockPool.query.mockResolvedValueOnce({ rows: [] });

      const result = await authService.login('analyst@scanboy.io', 'correct-password');

      expect(result.tokens).toBeDefined();
      expect(result.tokens!.accessToken).toBeTruthy();
      expect(result.tokens!.refreshToken).toBeTruthy();
      expect(result.mfaRequired).toBeUndefined();

      // Verify the token is actually valid JWT
      const decoded = jwt.verify(result.tokens!.accessToken, TEST_JWT_SECRET) as jwt.JwtPayload;
      expect(decoded['sub']).toBe('user-1');
      expect(decoded['email']).toBe('analyst@scanboy.io');
      expect(decoded['role']).toBe(UserRole.Analyst);
    });

    it('returns MFA session when MFA is enabled', async () => {
      const passwordHash = await bcrypt.hash('password', 4);
      mockPool.query.mockResolvedValueOnce({
        rows: [
          {
            id: 'user-2',
            email: 'admin@scanboy.io',
            display_name: 'Admin',
            role: UserRole.Admin,
            password_hash: passwordHash,
            mfa_enabled: true,
          },
        ],
      });
      mockRedis.setex.mockResolvedValueOnce('OK');

      const result = await authService.login('admin@scanboy.io', 'password');

      expect(result.mfaRequired).toBe(true);
      expect(result.mfaSessionId).toBeTruthy();
      expect(result.tokens).toBeUndefined();
      expect(mockRedis.setex).toHaveBeenCalledTimes(1);
    });
  });

  describe('login with invalid credentials', () => {
    it('throws for non-existent user', async () => {
      mockPool.query.mockResolvedValueOnce({ rows: [] });

      await expect(
        authService.login('nonexistent@scanboy.io', 'password'),
      ).rejects.toThrow('Invalid email or password');
    });

    it('throws for wrong password', async () => {
      const passwordHash = await bcrypt.hash('correct-password', 4);
      mockPool.query.mockResolvedValueOnce({
        rows: [
          {
            id: 'user-1',
            email: 'user@scanboy.io',
            display_name: 'User',
            role: UserRole.Viewer,
            password_hash: passwordHash,
            mfa_enabled: false,
          },
        ],
      });

      await expect(
        authService.login('user@scanboy.io', 'wrong-password'),
      ).rejects.toThrow('Invalid email or password');
    });
  });

  describe('JWT token generation and verification', () => {
    it('generates tokens that can be verified', async () => {
      const passwordHash = await bcrypt.hash('test-pass', 4);
      mockPool.query.mockResolvedValueOnce({
        rows: [
          {
            id: 'user-3',
            email: 'test@scanboy.io',
            display_name: 'Test',
            role: UserRole.Admin,
            password_hash: passwordHash,
            mfa_enabled: false,
          },
        ],
      });
      mockPool.query.mockResolvedValueOnce({ rows: [] });

      const result = await authService.login('test@scanboy.io', 'test-pass');
      const accessToken = result.tokens!.accessToken;

      const decoded = jwt.verify(accessToken, TEST_JWT_SECRET) as jwt.JwtPayload;
      expect(decoded['sub']).toBe('user-3');
      expect(decoded['role']).toBe(UserRole.Admin);
      expect(decoded['exp']).toBeDefined();
      expect(decoded['iat']).toBeDefined();
    });

    it('refresh tokens contain type=refresh', async () => {
      const passwordHash = await bcrypt.hash('test', 4);
      mockPool.query.mockResolvedValueOnce({
        rows: [
          {
            id: 'user-4',
            email: 'user4@scanboy.io',
            display_name: 'User4',
            role: UserRole.Viewer,
            password_hash: passwordHash,
            mfa_enabled: false,
          },
        ],
      });
      mockPool.query.mockResolvedValueOnce({ rows: [] });

      const result = await authService.login('user4@scanboy.io', 'test');
      const refreshToken = result.tokens!.refreshToken;

      const decoded = jwt.verify(refreshToken, TEST_JWT_SECRET) as jwt.JwtPayload;
      expect(decoded['type']).toBe('refresh');
    });
  });

  describe('token expiry handling', () => {
    it('rejects expired tokens', () => {
      const expiredToken = jwt.sign(
        { sub: 'user-1', email: 'test@test.com', role: UserRole.Viewer },
        TEST_JWT_SECRET,
        { expiresIn: '0s' },
      );

      expect(() => jwt.verify(expiredToken, TEST_JWT_SECRET)).toThrow(
        jwt.TokenExpiredError,
      );
    });

    it('accepts non-expired tokens', () => {
      const validToken = jwt.sign(
        { sub: 'user-1', email: 'test@test.com', role: UserRole.Viewer },
        TEST_JWT_SECRET,
        { expiresIn: '1h' },
      );

      const decoded = jwt.verify(validToken, TEST_JWT_SECRET) as jwt.JwtPayload;
      expect(decoded['sub']).toBe('user-1');
    });
  });

  describe('token refresh', () => {
    it('refreshes a valid refresh token', async () => {
      const refreshToken = jwt.sign(
        { sub: 'user-1', email: 'test@test.com', role: UserRole.Analyst, type: 'refresh' },
        TEST_JWT_SECRET,
        { expiresIn: '7d' },
      );

      mockRedis.get.mockResolvedValueOnce(null); // Not revoked
      mockRedis.setex.mockResolvedValueOnce('OK'); // Revoke old token

      const result = await authService.refresh(refreshToken);
      expect(result.tokens.accessToken).toBeTruthy();
      expect(result.tokens.refreshToken).toBeTruthy();
      expect(result.tokens.expiresIn).toBeTruthy();

      // Verify old token is revoked
      expect(mockRedis.setex).toHaveBeenCalled();
    });

    it('rejects revoked refresh tokens', async () => {
      const refreshToken = jwt.sign(
        { sub: 'user-1', email: 'test@test.com', role: UserRole.Analyst, type: 'refresh' },
        TEST_JWT_SECRET,
        { expiresIn: '7d' },
      );

      mockRedis.get.mockResolvedValueOnce('1'); // Revoked!

      await expect(authService.refresh(refreshToken)).rejects.toThrow('revoked');
    });
  });
});

describe('Auth middleware', () => {
  const authMiddleware = createAuthMiddleware(testConfig);

  it('passes through with valid Bearer token', () => {
    const token = jwt.sign(
      { sub: 'user-1', email: 'test@test.com', role: UserRole.Analyst },
      TEST_JWT_SECRET,
      { expiresIn: '1h' },
    );

    const req = createMockReq({
      headers: { authorization: `Bearer ${token}` },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    authMiddleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.user).toBeDefined();
    expect(req.user!.sub).toBe('user-1');
  });

  it('rejects request with no Authorization header', () => {
    const req = createMockReq();
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    authMiddleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('rejects request with invalid token', () => {
    const req = createMockReq({
      headers: { authorization: 'Bearer invalid-token-here' },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    authMiddleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        error: expect.objectContaining({ message: 'Invalid token' }),
      }),
    );
  });

  it('rejects expired tokens with specific message', () => {
    const expiredToken = jwt.sign(
      { sub: 'user-1', email: 'test@test.com', role: UserRole.Viewer },
      TEST_JWT_SECRET,
      { expiresIn: '0s' },
    );

    // Wait a tick to ensure the token is expired
    const req = createMockReq({
      headers: { authorization: `Bearer ${expiredToken}` },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    authMiddleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: expect.objectContaining({ message: 'Token has expired' }),
      }),
    );
  });

  it('rejects non-Bearer auth scheme', () => {
    const req = createMockReq({
      headers: { authorization: 'Basic dXNlcjpwYXNz' },
    });
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    authMiddleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });
});

describe('RBAC middleware', () => {
  it('allows access when user role meets minimum', () => {
    const middleware = requireRole(UserRole.Analyst);
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
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('allows access when user role exactly matches minimum', () => {
    const middleware = requireRole(UserRole.Analyst);
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
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('denies access when user role is below minimum', () => {
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
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: expect.objectContaining({ code: 'FORBIDDEN' }),
      }),
    );
  });

  it('returns 401 when no user is on the request', () => {
    const middleware = requireRole(UserRole.Viewer);
    const req = createMockReq();
    // No req.user set
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('SuperAdmin can access Admin-required routes', () => {
    const middleware = requireRole(UserRole.Admin);
    const req = createMockReq();
    req.user = {
      sub: 'user-1',
      email: 'super@test.com',
      role: UserRole.SuperAdmin,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const res = createMockRes();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
  });
});
