import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { containsSqlInjection, containsXss, sanitizeDeep } from './sanitization.utils';
import { NoNoSqlOperators, NoSqlInjection, SanitizeHtml } from './sanitization.decorators';

describe('Input sanitization & validators', () => {
  it('strips script/XSS content from HTML strings', () => {
    const input = '<script>alert(1)</script>';
    const sanitized = sanitizeDeep(input);
    expect(sanitized).not.toBe(input);
    expect(String(sanitized)).not.toMatch(/<\s*script\b/i);
    expect(containsXss(String(sanitized))).toBe(false);
  });

  it('detects conservative SQL injection patterns', () => {
    expect(containsSqlInjection('hello world')).toBe(false);
    expect(containsSqlInjection('1 OR 1=1 --')).toBe(true);
    expect(containsSqlInjection('DROP TABLE users;')).toBe(true);
  });

  it('removes NoSQL operator keys ($...) and prototype-pollution keys', () => {
    const sanitized = sanitizeDeep({
      ok: 'yes',
      filter: { $ne: 'x', name: 'bob' },
      $gt: 5,
      __proto__: { polluted: true },
    });

    expect((sanitized as any).ok).toBe('yes');
    expect((sanitized as any).$gt).toBeUndefined();
    expect((sanitized as any).filter.$ne).toBeUndefined();
    expect((sanitized as any).filter.name).toBe('bob');
    expect(Object.prototype.hasOwnProperty.call(sanitized as any, '__proto__')).toBe(false);
  });

  it('NoSqlInjection decorator rejects likely SQLi strings', async () => {
    class Dto {
      @NoSqlInjection()
      input!: string;
    }

    const dto = plainToInstance(Dto, { input: '1 OR 1=1 --' });
    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
  });

  it('SanitizeHtml decorator sanitizes content and validator passes', async () => {
    class Dto {
      @SanitizeHtml()
      text!: string;
    }

    const dto = plainToInstance(Dto, { text: '<script>alert(1)</script>' });
    expect(dto.text).not.toMatch(/<\s*script\b/i);
    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });

  it('NoNoSqlOperators decorator rejects objects with $-operators', async () => {
    class Dto {
      @NoNoSqlOperators()
      filter!: Record<string, unknown>;
    }

    const dto = plainToInstance(Dto, { filter: { $gt: 3, ok: true } });
    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
  });
});
