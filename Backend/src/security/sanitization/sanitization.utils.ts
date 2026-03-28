// sanitize-html exports the sanitizer function directly (no default export).
// Using `require` import form avoids TS default-export interop issues.
// eslint-disable-next-line @typescript-eslint/no-var-requires
import sanitizeHtml = require('sanitize-html');

export type SanitizationOptions = {
  /**
   * Whitelisted HTML tags.
   * If empty, all tags are stripped (recommended for API input).
   */
  allowedTags?: string[];

  /**
   * If true, the sanitizer will apply conservative SQL injection heuristics
   * and throw when they are detected.
   *
   * The global middleware sets this to true (default). Decorators that only
   * need HTML sanitization can disable it to avoid throwing during transform.
   */
  detectSqlInjection?: boolean;
};

export class SanitizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SanitizationError';
  }
}

export class SqlInjectionDetectedError extends SanitizationError {
  constructor() {
    super('Potential SQL injection detected');
    this.name = 'SqlInjectionDetectedError';
  }
}

const DEFAULT_SANITIZATION_OPTIONS: Required<SanitizationOptions> = {
  allowedTags: [],
  detectSqlInjection: true,
};

// Conservative SQLi heuristics; avoids blocking benign text like "hello world".
const SQLI_KEYWORD_REGEX = new RegExp(
  String.raw`\b(select|insert|update|delete|drop|truncate|union|alter|create|grant|revoke|sleep|benchmark)\b`,
  'i',
);
const SQLI_COMMENT_REGEX = /(--|\#|\/\*.*?\*\/)/i;
const SQLI_BOOLEAN_BYPASS_REGEX = /\b(or|and)\b\s+1\s*=\s*1\b/i;
const SQLI_STATEMENT_SEPARATOR_REGEX = /;/;

function normalizeUnicode(value: string): string {
  try {
    return value.normalize('NFKC');
  } catch {
    return value;
  }
}

export function containsSqlInjection(value: string): boolean {
  const v = normalizeUnicode(value);
  return (
    SQLI_KEYWORD_REGEX.test(v) ||
    SQLI_COMMENT_REGEX.test(v) ||
    SQLI_BOOLEAN_BYPASS_REGEX.test(v) ||
    SQLI_STATEMENT_SEPARATOR_REGEX.test(v)
  );
}

const XSS_SCRIPT_REGEX = /<\s*script\b/i;

export function containsXss(value: string): boolean {
  return XSS_SCRIPT_REGEX.test(value);
}

function sanitizeHtmlString(value: string, options: SanitizationOptions): string {
  const normalized = normalizeUnicode(value);
  const { allowedTags } = { ...DEFAULT_SANITIZATION_OPTIONS, ...options };

  return sanitizeHtml(normalized, {
    allowedTags,
    allowedAttributes: {},
    // Ensure dangerous tags never survive sanitization.
    disallowedTagsMode: 'discard',
  });
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;
  if (Array.isArray(value)) return false;
  // Robust "plain object" check for request payloads, including objects with
  // polluted prototypes (e.g. via `__proto__`).
  return Object.prototype.toString.call(value) === '[object Object]';
}

const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

function stripNoSqlOperators(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(obj)) {
    if (key.startsWith('$')) continue;
    if (DANGEROUS_KEYS.has(key)) continue;
    result[key] = val;
  }
  return result;
}

export function sanitizeDeep<T>(
  input: T,
  options: SanitizationOptions = {} as SanitizationOptions,
): T {
  // Primitive passthrough
  if (input === null || input === undefined) return input;

  if (typeof input === 'string') {
    const normalized = normalizeUnicode(input);
    const detectSqlInjection =
      options.detectSqlInjection ?? DEFAULT_SANITIZATION_OPTIONS.detectSqlInjection;
    if (detectSqlInjection && containsSqlInjection(normalized)) {
      throw new SqlInjectionDetectedError();
    }
    return sanitizeHtmlString(normalized, options) as T;
  }

  if (Array.isArray(input)) {
    return input.map((v) => sanitizeDeep(v, options)) as T;
  }

  if (isPlainObject(input)) {
    const withoutNoSqlOperators = stripNoSqlOperators(input as Record<string, unknown>);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(withoutNoSqlOperators)) {
      out[k] = sanitizeDeep(v, options);
    }
    return out as T;
  }

  // For non-plain objects (Date, Buffer, etc.) we avoid mutating.
  return input;
}

export function containsNoSqlOperators(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (Array.isArray(value)) return value.some(containsNoSqlOperators);
  if (!isPlainObject(value)) return false;

  for (const [key, v] of Object.entries(value)) {
    if (key.startsWith('$')) return true;
    if (DANGEROUS_KEYS.has(key)) return true;
    if (containsNoSqlOperators(v)) return true;
  }
  return false;
}
