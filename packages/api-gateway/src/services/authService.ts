import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { randomUUID, createHash } from 'node:crypto';
import type pg from 'pg';
import type Redis from 'ioredis';
import type { UserRole } from '@scanboy/shared';
import { REDIS_KEY_PREFIXES } from '@scanboy/shared';
import { AppError } from '../middleware/errorHandler.js';
import type { AppConfig } from '../config.js';

function tokenHash(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: string;
}

interface LoginResult {
  token?: string;
  refreshToken?: string;
  user?: { id: string; email: string; username: string; role: string };
  mfaRequired?: boolean;
  mfaSessionId?: string;
}

export class AuthService {
  constructor(
    private readonly pool: pg.Pool,
    private readonly redis: Redis,
    private readonly config: AppConfig,
  ) {}

  async login(email: string, password: string): Promise<LoginResult> {
    const result = await this.pool.query(
      `SELECT id, email, username, role, password_hash, mfa_enabled
       FROM users WHERE email = $1 AND status = 'active'`,
      [email],
    );

    const user = result.rows[0] as
      | { id: string; email: string; username: string; role: UserRole; password_hash: string; mfa_enabled: boolean }
      | undefined;

    if (!user) {
      await bcrypt.hash('dummy', this.config.bcryptRounds);
      throw new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
    }

    const MAX_FAILED_ATTEMPTS = 10;
    const LOCKOUT_MINUTES = 15;
    const lockoutKey = `${REDIS_KEY_PREFIXES.SESSION}lockout:${user.id}`;
    const locked = await this.redis.get(lockoutKey);
    if (locked) {
      throw new AppError(429, 'ACCOUNT_LOCKED', `Account locked due to too many failed attempts. Try again in ${LOCKOUT_MINUTES} minutes.`);
    }

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      const failKey = `${REDIS_KEY_PREFIXES.SESSION}fail_count:${user.id}`;
      const newCount = await this.redis.incr(failKey);
      if (newCount === 1) {
        await this.redis.expire(failKey, LOCKOUT_MINUTES * 60);
      }
      if (newCount >= MAX_FAILED_ATTEMPTS) {
        await this.redis.setex(
          `${REDIS_KEY_PREFIXES.SESSION}lockout:${user.id}`,
          LOCKOUT_MINUTES * 60,
          '1',
        );
      }
      throw new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
    }

    // If MFA is enabled, require a second step.
    if (user.mfa_enabled) {
      const mfaSessionId = randomUUID();
      await this.redis.setex(
        `${REDIS_KEY_PREFIXES.SESSION}mfa:${mfaSessionId}`,
        300, // 5-minute expiry
        JSON.stringify({ userId: user.id, email: user.email, role: user.role }),
      );
      return { mfaRequired: true, mfaSessionId };
    }

    // Reset failed attempts on successful login.
    await this.redis.del(`${REDIS_KEY_PREFIXES.SESSION}fail_count:${user.id}`);
    await this.pool.query(
      `UPDATE users SET last_login_at = NOW() WHERE id = $1`,
      [user.id],
    );

    const tokens = this.generateTokenPair(user.id, user.email, user.role);
    return {
      token: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
      },
    };
  }

  async verifyMfa(mfaSessionId: string, _token: string): Promise<{ tokens: TokenPair }> {
    const sessionData = await this.redis.get(`${REDIS_KEY_PREFIXES.SESSION}mfa:${mfaSessionId}`);
    if (!sessionData) {
      throw new AppError(401, 'MFA_SESSION_EXPIRED', 'MFA session has expired');
    }

    let parsed: { userId: string; email: string; role: UserRole };
    try {
      parsed = JSON.parse(sessionData) as { userId: string; email: string; role: UserRole };
    } catch {
      throw new AppError(401, 'MFA_SESSION_INVALID', 'MFA session data is corrupt');
    }
    void parsed;

    const mfaAttemptKey = `${REDIS_KEY_PREFIXES.SESSION}mfa_attempts:${mfaSessionId}`;
    const attempts = await this.redis.incr(mfaAttemptKey);
    if (attempts === 1) {
      await this.redis.expire(mfaAttemptKey, 300);
    }
    if (attempts > 5) {
      await this.redis.del(`${REDIS_KEY_PREFIXES.SESSION}mfa:${mfaSessionId}`);
      await this.redis.del(mfaAttemptKey);
      throw new AppError(429, 'MFA_RATE_LIMITED', 'Too many MFA attempts. Please log in again.');
    }

    // Until TOTP integration is complete, reject all MFA attempts to avoid
    // silently bypassing MFA for users who have it enabled.
    throw new AppError(501, 'MFA_NOT_IMPLEMENTED', 'MFA verification is not yet available. Contact an administrator.');

    // TODO: When TOTP is implemented, replace the throw above with actual
    // verification and uncomment the lines below.
    // await this.redis.del(`${REDIS_KEY_PREFIXES.SESSION}mfa:${mfaSessionId}`);
    // await this.redis.del(mfaAttemptKey);
    // await this.pool.query(`UPDATE users SET last_login_at = NOW() WHERE id = $1`, [userId]);
    // const tokens = this.generateTokenPair(userId, email, role);
    // return { tokens };
  }

  async refresh(refreshToken: string): Promise<{ tokens: TokenPair }> {
    try {
      const payload = jwt.verify(refreshToken, this.config.jwt.refreshSecret, {
        algorithms: ['HS256'],
      }) as {
        sub: string;
        email: string;
        role: UserRole;
        type: string;
      };

      if (payload.type !== 'refresh') {
        throw new AppError(401, 'INVALID_TOKEN', 'Invalid refresh token');
      }

      const revokeKey = `${REDIS_KEY_PREFIXES.SESSION}revoked:${tokenHash(refreshToken)}`;
      const wasSet = await this.redis.set(revokeKey, '1', 'EX', 7 * 24 * 60 * 60, 'NX');
      if (!wasSet) {
        throw new AppError(401, 'TOKEN_REVOKED', 'Refresh token has already been used');
      }

      const userRow = await this.pool.query(
        'SELECT email, role, status FROM users WHERE id = $1',
        [payload.sub],
      );
      if (userRow.rows.length === 0 || userRow.rows[0].status !== 'active') {
        throw new AppError(401, 'USER_INACTIVE', 'User account is inactive or deleted');
      }
      const currentUser = userRow.rows[0];
      const tokens = this.generateTokenPair(payload.sub, currentUser.email, currentUser.role);

      return { tokens };
    } catch (err) {
      if (err instanceof AppError) throw err;
      throw new AppError(401, 'INVALID_TOKEN', 'Invalid or expired refresh token');
    }
  }

  async logout(accessToken: string): Promise<void> {
    try {
      const payload = jwt.verify(accessToken, this.config.jwt.secret, {
        algorithms: ['HS256'],
        ignoreExpiration: true,
      }) as { exp: number };

      const ttl = Math.max(0, payload.exp - Math.floor(Date.now() / 1000));
      if (ttl > 0) {
        await this.redis.setex(
          `${REDIS_KEY_PREFIXES.SESSION}revoked:${tokenHash(accessToken)}`,
          ttl,
          '1',
        );
      }
    } catch {
      // If the token is invalid, there is nothing to revoke.
    }
  }

  async revokeRefreshToken(refreshToken: string): Promise<void> {
    try {
      const payload = jwt.verify(refreshToken, this.config.jwt.refreshSecret, {
        algorithms: ['HS256'],
        ignoreExpiration: true,
      }) as { type?: string; exp: number };

      if (payload.type !== 'refresh') return;

      const ttl = Math.max(0, payload.exp - Math.floor(Date.now() / 1000));
      if (ttl > 0) {
        await this.redis.set(
          `${REDIS_KEY_PREFIXES.SESSION}revoked:${tokenHash(refreshToken)}`,
          '1', 'EX', ttl, 'NX',
        );
      }
    } catch {
      // Invalid token — nothing to revoke.
    }
  }

  private generateTokenPair(userId: string, email: string, role: UserRole): TokenPair {
    const accessToken = jwt.sign(
      { sub: userId, email, role },
      this.config.jwt.secret,
      { algorithm: 'HS256', expiresIn: this.config.jwt.expiry } as jwt.SignOptions,
    );

    const refreshToken = jwt.sign(
      { sub: userId, email, role, type: 'refresh' },
      this.config.jwt.refreshSecret,
      { algorithm: 'HS256', expiresIn: this.config.jwt.refreshExpiry } as jwt.SignOptions,
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: this.config.jwt.expiry,
    };
  }
}
