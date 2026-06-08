import type { Request, Response, NextFunction } from 'express';
import { type ZodSchema, ZodError } from 'zod';

interface ValidationTargets {
  body?: ZodSchema;
  query?: ZodSchema;
  params?: ZodSchema;
}

/**
 * Creates middleware that validates request body, query, and/or params
 * against the provided Zod schemas.
 *
 * On validation failure, responds with 400 and structured error details.
 */
export function validate(schemas: ValidationTargets) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const errors: Array<{ target: string; issues: Array<{ path: string; message: string }> }> = [];

    if (schemas.body) {
      const result = schemas.body.safeParse(req.body);
      if (!result.success) {
        errors.push({
          target: 'body',
          issues: formatZodError(result.error),
        });
      } else {
        req.body = result.data;
      }
    }

    if (schemas.query) {
      const result = schemas.query.safeParse(req.query);
      if (!result.success) {
        errors.push({
          target: 'query',
          issues: formatZodError(result.error),
        });
      } else {
        // Replace query with parsed (and coerced) values.
        (req as unknown as Record<string, unknown>)['query'] = result.data;
      }
    }

    if (schemas.params) {
      const result = schemas.params.safeParse(req.params);
      if (!result.success) {
        errors.push({
          target: 'params',
          issues: formatZodError(result.error),
        });
      }
    }

    if (errors.length > 0) {
      res.status(400).json({
        success: false,
        data: null,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Request validation failed',
          details: { validationErrors: errors },
        },
        requestId: res.getHeader('x-request-id') as string,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    next();
  };
}

function formatZodError(error: ZodError): Array<{ path: string; message: string }> {
  return error.issues.map((issue) => ({
    path: issue.path.join('.'),
    message: issue.message,
  }));
}
