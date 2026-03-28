import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { Reflector } from '@nestjs/core';
import { ENCRYPTED_FIELD_KEY } from '../decorators/encrypted.decorator';
import { EncryptionService } from '../services/encryption.service';

@Injectable()
export class EncryptionInterceptor implements NestInterceptor {
  constructor(
    private readonly reflector: Reflector,
    private readonly encryptionService: EncryptionService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();

    return next.handle().pipe(
      map(async (data) => {
        // Process the response data for encryption/decryption
        return await this.processResponseData(data, request);
      }),
    );
  }

  private async processResponseData(data: any, request: any): Promise<any> {
    if (!data || typeof data !== 'object') {
      return data;
    }

    // Handle arrays
    if (Array.isArray(data)) {
      return await Promise.all(data.map((item) => this.processObject(item, request)));
    }

    // Handle single objects
    return await this.processObject(data, request);
  }

  private async processObject(obj: any, request: any): Promise<any> {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }

    const processed = { ...obj };

    // Get encrypted fields metadata
    const constructor = obj.constructor;
    const encryptedFields = this.getEncryptedFields(constructor);

    for (const fieldConfig of encryptedFields) {
      const { propertyKey, fieldName, fieldType, encrypt } = fieldConfig;
      const value = obj[fieldName];

      if (value !== undefined && value !== null && encrypt) {
        try {
          // Check if value is already encrypted (has encrypted structure)
          if (this.isEncryptedValue(value)) {
            // Decrypt the value
            const decrypted = await this.decryptValue(value, fieldType);
            processed[fieldName] = decrypted;
          } else {
            // Encrypt the value
            const encrypted = await this.encryptValue(value, fieldType);
            processed[fieldName] = encrypted;
          }
        } catch (error) {
          console.error(`Failed to process field ${fieldName}:`, error);
          processed[fieldName] = value; // Keep original value on error
        }
      }
    }

    return processed;
  }

  private getEncryptedFields(constructor: any): any[] {
    const fields = [];

    // Get all properties of the constructor prototype
    const prototype = constructor.prototype;

    for (const propertyKey in prototype) {
      const metadata = Reflect.getMetadata(ENCRYPTED_FIELD_KEY, prototype, propertyKey);

      if (metadata) {
        fields.push(metadata);
      }
    }

    return fields;
  }

  private isEncryptedValue(value: any): boolean {
    return (
      value &&
      typeof value === 'object' &&
      value.encryptedData &&
      value.iv &&
      value.keyId &&
      value.algorithm
    );
  }

  private async encryptValue(value: any, fieldType: string): Promise<any> {
    const stringValue = typeof value === 'string' ? value : JSON.stringify(value);

    const result = await this.encryptionService.encryptField(stringValue, fieldType);

    return {
      encryptedData: result.encryptedData,
      iv: result.iv,
      keyId: result.keyId,
      algorithm: result.algorithm,
    };
  }

  private async decryptValue(encryptedValue: any, fieldType: string): Promise<any> {
    try {
      const result = await this.encryptionService.decryptField(
        encryptedValue.encryptedData,
        encryptedValue.iv,
        encryptedValue.keyId,
        fieldType,
      );

      if (result.success) {
        // Try to parse as JSON first, fallback to string
        try {
          return JSON.parse(result.decryptedData);
        } catch {
          return result.decryptedData;
        }
      }

      throw new Error(result.error || 'Decryption failed');
    } catch (error) {
      console.error('Decryption error:', error);
      return encryptedValue; // Return original value on error
    }
  }
}
