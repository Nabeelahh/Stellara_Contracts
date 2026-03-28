const DURATION_UNITS_MS: Record<string, number> = {
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

export function parseDurationToMilliseconds(
  value: string | number | undefined,
  fallbackMs: number,
): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (!value) {
    return fallbackMs;
  }

  const normalized = String(value).trim().toLowerCase();
  if (/^\d+$/.test(normalized)) {
    return parseInt(normalized, 10);
  }

  const match = normalized.match(/^(\d+)(ms|s|m|h|d)$/);
  if (!match) {
    return fallbackMs;
  }

  const [, amount, unit] = match;
  return parseInt(amount, 10) * DURATION_UNITS_MS[unit];
}

export function parseDurationToSeconds(
  value: string | number | undefined,
  fallbackSeconds: number,
): number {
  const milliseconds = parseDurationToMilliseconds(value, fallbackSeconds * 1000);

  return Math.max(1, Math.floor(milliseconds / 1000));
}
