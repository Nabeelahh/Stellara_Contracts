import { registerDecorator, ValidationArguments, ValidationOptions } from 'class-validator';
import { Transform } from 'class-transformer';
import {
  sanitizeDeep,
  containsNoSqlOperators,
  containsSqlInjection,
  containsXss,
  type SanitizationOptions,
} from './sanitization.utils';

/**
 * Rejects strings that match conservative SQL injection heuristics.
 */
export function NoSqlInjection(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'NoSqlInjection',
      target: object.constructor,
      propertyName,
      options: validationOptions,
      validator: {
        validate(value: unknown) {
          if (value === null || value === undefined) return true;
          if (typeof value !== 'string') return false;
          return !containsSqlInjection(value);
        },
        defaultMessage(args: ValidationArguments) {
          return `${args.property} contains potential SQL injection patterns`;
        },
      },
    });
  };
}

/**
 * Ensures objects do not contain dangerous Mongo-style operators like `$ne`, `$gt`, etc.
 */
export function NoNoSqlOperators(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'NoNoSqlOperators',
      target: object.constructor,
      propertyName,
      options: validationOptions,
      validator: {
        validate(value: unknown) {
          if (value === null || value === undefined) return true;
          return !containsNoSqlOperators(value);
        },
        defaultMessage(args: ValidationArguments) {
          return `${args.property} contains forbidden NoSQL operators`;
        },
      },
    });
  };
}

/**
 * Sanitizes HTML content using DOM sanitizer and strips script tags by default.
 * If `allowedTags` is provided, only those tags are allowed.
 */
export function SanitizeHtml(
  options: SanitizationOptions = {} as SanitizationOptions,
  validationOptions?: ValidationOptions,
) {
  return function (object: object, propertyName: string) {
    // Transform first (so DTO values are cleaned before validation checks).
    Transform(({ value }) => {
      if (value === null || value === undefined) return value;
      if (typeof value !== 'string') return value;

      // sanitizeDeep gives us NFKC normalization + HTML sanitization for strings.
      return sanitizeDeep(value, { ...options, detectSqlInjection: false });
    })(object, propertyName);

    registerDecorator({
      name: 'SanitizeHtml',
      target: object.constructor,
      propertyName,
      options: validationOptions,
      validator: {
        validate(value: unknown) {
          if (value === null || value === undefined) return true;
          if (typeof value !== 'string') return false;
          // After sanitization, script tags should be gone.
          return !containsXss(value);
        },
        defaultMessage(args: ValidationArguments) {
          return `${args.property} contains forbidden XSS content`;
        },
      },
    });
  };
}
