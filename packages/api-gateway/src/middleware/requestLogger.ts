import pinoHttp from 'pino-http';
import { randomUUID } from 'node:crypto';
import type { Logger } from 'pino';

/**
 * Creates pino-http request logging middleware.
 * Assigns a unique request ID to each incoming request.
 */
export function createRequestLogger(logger: Logger) {
  return pinoHttp({
    logger,
    genReqId: () => randomUUID(),
    customLogLevel: (_req, res, err) => {
      if (err || (res.statusCode >= 500)) return 'error';
      if (res.statusCode >= 400) return 'warn';
      return 'info';
    },
    customSuccessMessage: (req, res) => {
      return `${req.method} ${req.url} ${res.statusCode}`;
    },
    customErrorMessage: (req, res) => {
      return `${req.method} ${req.url} ${res.statusCode}`;
    },
    // Redact sensitive headers.
    serializers: {
      req: (req) => ({
        id: req.id,
        method: req.method,
        url: req.url,
        remoteAddress: req.remoteAddress,
      }),
      res: (res) => ({
        statusCode: res.statusCode,
      }),
    },
  });
}
