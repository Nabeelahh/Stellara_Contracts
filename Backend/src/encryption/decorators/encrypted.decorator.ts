import { SetMetadata } from '@nestjs/common';
import { EncryptionService } from '../services/encryption.service';

export const ENCRYPTED_FIELD_KEY = 'encrypted_field';

interface EncryptedFieldOptions {
  fieldName?: string;
  fieldType?: string;
  encrypt?: boolean;
}

/**
 * Decorator to mark fields for encryption
 * @param options Configuration for encryption
 */
export function EncryptedField(options: EncryptedFieldOptions = {}) {
  return function (target: any, propertyKey: string | symbol) {
    SetMetadata(ENCRYPTED_FIELD_KEY, {
      propertyKey,
      fieldName: options.fieldName || propertyKey.toString(),
      fieldType: options.fieldType || 'unknown',
      encrypt: options.encrypt !== false, // Default to true
    })(target, propertyKey);
  };
}

/**
 * Decorator to automatically encrypt/decrypt entity fields
 */
export function AutoEncrypt(options: EncryptedFieldOptions = {}) {
  return function (target: any) {
    // Process all properties with EncryptedField decorator
    for (const propertyKey in target.prototype) {
      const metadata = Reflect.getMetadata(ENCRYPTED_FIELD_KEY, target.prototype, propertyKey);

      if (metadata && metadata.encrypt) {
        const originalDescriptor = Object.getOwnPropertyDescriptor(target.prototype, propertyKey);

        if (originalDescriptor) {
          const { get, set } = originalDescriptor;

          Object.defineProperty(target.prototype, propertyKey, {
            get: function () {
              const value = get.call(this);
              return value; // Will be decrypted by interceptor
            },
            set: function (value) {
              // Will be encrypted by interceptor
              set.call(this, value);
            },
            enumerable: true,
            configurable: true,
          });
        }
      }
    }
  };
}
