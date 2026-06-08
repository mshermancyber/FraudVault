import rateLimit from 'express-rate-limit';
import type { AppConfig } from '../config.js';

/**
 * Creates a global rate limiter based on the app configuration.
 */
export function createRateLimiter(config: AppConfig) {
  return rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.maxRequests,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    skip: (req) => req.path === '/health' || req.path === '/ready',
    message: {
      success: false,
      data: null,
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests. Please try again later.',
      },
      timestamp: new Date().toISOString(),
    },
    keyGenerator: (req) => {
      // Use authenticated user ID when available, otherwise fall back to IP.
      return req.user?.sub ?? req.ip ?? 'unknown';
    },
  });
}

/**
 * A stricter rate limiter for auth endpoints to prevent brute-force attacks.
 */
export function createAuthRateLimiter() {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: {
      success: false,
      data: null,
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many authentication attempts. Please try again later.',
      },
      timestamp: new Date().toISOString(),
    },
  });
}
