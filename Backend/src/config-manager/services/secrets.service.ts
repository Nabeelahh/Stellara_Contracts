import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
  CreateSecretCommand,
  UpdateSecretCommand,
  DescribeSecretCommand,
} from '@aws-sdk/client-secrets-manager';

@Injectable()
export class SecretsService implements OnModuleInit {
  private readonly logger = new Logger(SecretsService.name);
  private client: SecretsManagerClient;
  private readonly cache = new Map<string, { value: string; expiresAt: number }>();
  private readonly cacheTtlMs = 5 * 60 * 1000; // 5 minutes

  constructor(private readonly configService: ConfigService) {}

  onModuleInit() {
    const region = this.configService.get<string>('AWS_REGION', 'us-east-1');
    const accessKeyId = this.configService.get<string>('AWS_ACCESS_KEY_ID');
    const secretAccessKey = this.configService.get<string>('AWS_SECRET_ACCESS_KEY');

    this.client = new SecretsManagerClient({
      region,
      ...(accessKeyId && secretAccessKey ? { credentials: { accessKeyId, secretAccessKey } } : {}),
    });
  }

  async getSecret(secretId: string): Promise<string | null> {
    const cached = this.cache.get(secretId);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.value;
    }

    try {
      const response = await this.client.send(new GetSecretValueCommand({ SecretId: secretId }));
      const value = response.SecretString ?? null;
      if (value) {
        this.cache.set(secretId, { value, expiresAt: Date.now() + this.cacheTtlMs });
      }
      return value;
    } catch (err) {
      this.logger.warn(`Could not fetch secret "${secretId}": ${(err as Error).message}`);
      return null;
    }
  }

  async setSecret(secretId: string, value: string): Promise<void> {
    try {
      // Check if secret exists
      await this.client.send(new DescribeSecretCommand({ SecretId: secretId }));
      await this.client.send(new UpdateSecretCommand({ SecretId: secretId, SecretString: value }));
    } catch (err: any) {
      if (err?.name === 'ResourceNotFoundException') {
        await this.client.send(new CreateSecretCommand({ Name: secretId, SecretString: value }));
      } else {
        throw err;
      }
    }
    // Invalidate cache
    this.cache.delete(secretId);
  }

  invalidateCache(secretId: string): void {
    this.cache.delete(secretId);
  }
}
