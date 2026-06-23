import { WebhookSecretService } from './webhook-secret.service';
import { createHmac } from 'crypto';

const TEST_KEY = 'a'.repeat(64); // 64-char hex string for tests

describe('WebhookSecretService', () => {
  let service: WebhookSecretService;

  beforeEach(() => {
    process.env.WEBHOOK_SECRET_KEY = TEST_KEY;
    service = new WebhookSecretService();
  });

  afterEach(() => {
    delete process.env.WEBHOOK_SECRET_KEY;
  });

  describe('initialization', () => {
    it('throws when WEBHOOK_SECRET_KEY is missing', () => {
      delete process.env.WEBHOOK_SECRET_KEY;
      expect(() => new WebhookSecretService()).toThrow('WEBHOOK_SECRET_KEY');
    });

    it('throws when WEBHOOK_SECRET_KEY is wrong length', () => {
      process.env.WEBHOOK_SECRET_KEY = 'tooshort';
      expect(() => new WebhookSecretService()).toThrow('WEBHOOK_SECRET_KEY');
    });
  });

  describe('encrypt / decrypt', () => {
    it('round-trips a plaintext secret', () => {
      const plaintext = 'my-signing-secret-123';
      const encrypted = service.encrypt(plaintext);
      expect(encrypted).not.toBe(plaintext);
      expect(service.decrypt(encrypted)).toBe(plaintext);
    });

    it('produces different ciphertexts for the same input (random IV)', () => {
      const encrypted1 = service.encrypt('same-secret');
      const encrypted2 = service.encrypt('same-secret');
      expect(encrypted1).not.toBe(encrypted2);
      // But both decrypt to the same value
      expect(service.decrypt(encrypted1)).toBe('same-secret');
      expect(service.decrypt(encrypted2)).toBe('same-secret');
    });

    it('throws on tampered ciphertext (GCM auth tag mismatch)', () => {
      const encrypted = service.encrypt('secret');
      const [iv, tag, ct] = encrypted.split(':');
      // Flip a byte in the ciphertext
      const tampered = `${iv}:${tag}:ff${ct.slice(2)}`;
      expect(() => service.decrypt(tampered)).toThrow();
    });

    it('throws on malformed stored value', () => {
      expect(() => service.decrypt('notvalid')).toThrow(
        'Invalid encrypted secret format',
      );
    });
  });

  describe('sign', () => {
    it('produces a deterministic HMAC-SHA256 hex string', () => {
      const sig = service.sign('payload', 'secret');
      const expected = createHmac('sha256', 'secret')
        .update('payload')
        .digest('hex');
      expect(sig).toBe(expected);
    });
  });

  describe('rotation', () => {
    it('signing still works after rotating to a new secret', () => {
      const oldSecret = 'old-secret';
      const newSecret = 'new-secret';
      const payload = 'some-webhook-payload';

      // Simulate storing the new encrypted secret after rotation
      const encryptedNew = service.encrypt(newSecret);
      const decrypted = service.decrypt(encryptedNew);

      const sig = service.sign(payload, decrypted);
      const expected = createHmac('sha256', newSecret)
        .update(payload)
        .digest('hex');

      expect(sig).toBe(expected);
      // Old secret no longer matches
      expect(service.sign(payload, oldSecret)).not.toBe(sig);
    });
  });
});
