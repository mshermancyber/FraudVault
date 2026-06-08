import type { Request, Response, NextFunction } from 'express';
import type { Logger } from 'pino';

export class AppError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

/**
 * Global error handling middleware. Must be registered last.
 */
export function createErrorHandler(logger: Logger) {
  return (err: Error, req: Request, res: Response, _next: NextFunction): void => {
    const requestId = res.getHeader('x-request-id') as string | undefined;

    if (err instanceof AppError) {
      logger.warn({ err, requestId, path: req.path }, 'Application error');
      res.status(err.statusCode).json({
        success: false,
        data: null,
        error: {
          code: err.code,
          message: err.message,
          details: err.details,
        },
        requestId,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    // Unexpected errors - do NOT leak details in production.
    logger.error({ err, requestId, path: req.path }, 'Unhandled error');

    res.status(500).json({
      success: false,
      data: null,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An internal error occurred',
      },
      requestId,
      timestamp: new Date().toISOString(),
    });
  };
}
