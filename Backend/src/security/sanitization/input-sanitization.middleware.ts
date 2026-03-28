import { BadRequestException } from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';
import { SqlInjectionDetectedError, sanitizeDeep } from './sanitization.utils';

/**
 * Global request sanitization:
 * - Unicode normalization (NFKC)
 * - DOM sanitizer for HTML/script content (XSS reduction)
 * - Recursive removal of NoSQL operator keys (`$...`) and prototype-pollution keys
 * - SQLi heuristic detection with hard fail (403/400)
 */
export function inputSanitizationMiddleware(
  req: Request,
  _res: Response,
  next: NextFunction,
): void {
  try {
    if (req.body) req.body = sanitizeDeep(req.body);
    if (req.query) req.query = sanitizeDeep(req.query);
    if (req.params) req.params = sanitizeDeep(req.params);
    next();
  } catch (err) {
    if (err instanceof SqlInjectionDetectedError) {
      return next(new BadRequestException('Invalid input'));
    }
    return next(err);
  }
}
