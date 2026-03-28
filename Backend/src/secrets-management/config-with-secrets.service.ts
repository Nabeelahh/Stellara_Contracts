// src/secrets-management/config-with-secrets.service.ts
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService as NestConfigService } from '@nestjs/config';
import { SecretsManagementService } from './secrets-management.service';

export interface AppConfig {
  // Database
  database: {
    host: string;
    port: number;
    username: string;
    password: string;
    database: string;
    url: string;
  };

  // JWT
  jwt: {
    secret: string;
    refreshSecret: string;
    expiration: string;
    refreshExpiration: string;
  };

  // Stripe
  stripe: {
    secretKey: string;
    publishableKey: string;
    webhookSecret: string;
  };

  // Twilio
  twilio: {
    accountSid: string;
    authToken: string;
    phoneNumber: string;
  };

  // AWS
  aws: {
    region: string;
    accessKeyId: string;
    secretAccessKey: string;
  };

  // Other configs (still from env for non-sensitive data)
  port: number;
  apiPrefix: string;
  nodeEnv: string;
  stellarNetwork: string;
  stellarRpcUrl: string;
  stellarNetworkPassphrase: string;
  projectLaunchContractId: string;
  escrowContractId: string;
  indexerPollIntervalMs: number;
  indexerReorgDepthThreshold: number;
}

@Injectable()
export class ConfigWithSecretsService implements OnModuleInit {
  private readonly logger = new Logger(ConfigWithSecretsService.name);
  private config: Partial<AppConfig> = {};
  private initialized = false;

  constructor(
    private nestConfigService: NestConfigService,
    private secretsService: SecretsManagementService,
  ) {}

  async onModuleInit() {
    await this.loadConfiguration();
    this.initialized = true;
    this.logger.log('Configuration with secrets loaded successfully');
  }

  /**
   * Load all configuration including secrets
   */
  private async loadConfiguration(): Promise<void> {
    try {
      // Load secrets from AWS Secrets Manager
      const [
        databaseSecret,
        jwtSecret,
        stripeSecret,
        twilioSecret,
        awsSecret,
      ] = await Promise.all([
        this.secretsService.getSecret('stellara/database', 'config-service'),
        this.secretsService.getSecret('stellara/jwt', 'config-service'),
        this.secretsService.getSecret('stellara/stripe', 'config-service'),
        this.secretsService.getSecret('stellara/twilio', 'config-service'),
        this.secretsService.getSecret('stellara/aws', 'config-service'),
      ]);

      // Database configuration
      this.config.database = {
        host: databaseSecret?.host || this.nestConfigService.get<string>('DATABASE_HOST', 'localhost'),
        port: databaseSecret?.port || this.nestConfigService.get<number>('DATABASE_PORT', 5432),
        username: databaseSecret?.username || this.nestConfigService.get<string>('DATABASE_USER', 'postgres'),
        password: databaseSecret?.password || this.nestConfigService.get<string>('DATABASE_PASSWORD', ''),
        database: databaseSecret?.database || this.nestConfigService.get<string>('DATABASE_NAME', 'stellara'),
        url: databaseSecret ?
          `postgresql://${databaseSecret.username}:${databaseSecret.password}@${databaseSecret.host}:${databaseSecret.port}/${databaseSecret.database}` :
          this.nestConfigService.get<string>('DATABASE_URL', ''),
      };

      // JWT configuration
      this.config.jwt = {
        secret: jwtSecret?.secret || this.nestConfigService.get<string>('JWT_SECRET', 'fallback-secret'),
        refreshSecret: jwtSecret?.refreshSecret || this.nestConfigService.get<string>('JWT_REFRESH_SECRET', 'fallback-refresh-secret'),
        expiration: this.nestConfigService.get<string>('JWT_EXPIRATION', '1h'),
        refreshExpiration: this.nestConfigService.get<string>('JWT_REFRESH_EXPIRATION', '7d'),
      };

      // Stripe configuration
      this.config.stripe = {
        secretKey: stripeSecret?.secretKey || this.nestConfigService.get<string>('STRIPE_SECRET_KEY', ''),
        publishableKey: stripeSecret?.publishableKey || this.nestConfigService.get<string>('STRIPE_PUBLISHABLE_KEY', ''),
        webhookSecret: stripeSecret?.webhookSecret || this.nestConfigService.get<string>('STRIPE_WEBHOOK_SECRET', ''),
      };

      // Twilio configuration
      this.config.twilio = {
        accountSid: twilioSecret?.accountSid || this.nestConfigService.get<string>('TWILIO_ACCOUNT_SID', ''),
        authToken: twilioSecret?.authToken || this.nestConfigService.get<string>('TWILIO_AUTH_TOKEN', ''),
        phoneNumber: twilioSecret?.phoneNumber || this.nestConfigService.get<string>('TWILIO_PHONE_NUMBER', ''),
      };

      // AWS configuration
      this.config.aws = {
        region: awsSecret?.region || this.nestConfigService.get<string>('AWS_REGION', 'us-east-1'),
        accessKeyId: awsSecret?.accessKeyId || this.nestConfigService.get<string>('AWS_ACCESS_KEY_ID', ''),
        secretAccessKey: awsSecret?.secretAccessKey || this.nestConfigService.get<string>('AWS_SECRET_ACCESS_KEY', ''),
      };

      // Non-sensitive configuration (still from environment)
      this.config.port = this.nestConfigService.get<number>('PORT', 3000);
      this.config.apiPrefix = this.nestConfigService.get<string>('API_PREFIX', 'api/v1');
      this.config.nodeEnv = this.nestConfigService.get<string>('NODE_ENV', 'development');
      this.config.stellarNetwork = this.nestConfigService.get<string>('STELLAR_NETWORK', 'testnet');
      this.config.stellarRpcUrl = this.nestConfigService.get<string>('STELLAR_RPC_URL', '');
      this.config.stellarNetworkPassphrase = this.nestConfigService.get<string>('STELLAR_NETWORK_PASSPHRASE', '');
      this.config.projectLaunchContractId = this.nestConfigService.get<string>('PROJECT_LAUNCH_CONTRACT_ID', '');
      this.config.escrowContractId = this.nestConfigService.get<string>('ESCROW_CONTRACT_ID', '');
      this.config.indexerPollIntervalMs = this.nestConfigService.get<number>('INDEXER_POLL_INTERVAL_MS', 30000);
      this.config.indexerReorgDepthThreshold = this.nestConfigService.get<number>('INDEXER_REORG_DEPTH_THRESHOLD', 10);

      this.logger.log('Configuration loaded successfully with secrets from AWS Secrets Manager');
    } catch (error) {
      this.logger.error(`Failed to load configuration with secrets: ${error.message}`);
      // Fallback to environment variables only
      this.loadFallbackConfiguration();
    }
  }

  /**
   * Fallback configuration loading (environment variables only)
   */
  private loadFallbackConfiguration(): void {
    this.logger.warn('Using fallback configuration (environment variables only)');

    this.config = {
      database: {
        host: this.nestConfigService.get<string>('DATABASE_HOST', 'localhost'),
        port: this.nestConfigService.get<number>('DATABASE_PORT', 5432),
        username: this.nestConfigService.get<string>('DATABASE_USER', 'postgres'),
        password: this.nestConfigService.get<string>('DATABASE_PASSWORD', ''),
        database: this.nestConfigService.get<string>('DATABASE_NAME', 'stellara'),
        url: this.nestConfigService.get<string>('DATABASE_URL', ''),
      },
      jwt: {
        secret: this.nestConfigService.get<string>('JWT_SECRET', 'fallback-secret'),
        refreshSecret: this.nestConfigService.get<string>('JWT_REFRESH_SECRET', 'fallback-refresh-secret'),
        expiration: this.nestConfigService.get<string>('JWT_EXPIRATION', '1h'),
        refreshExpiration: this.nestConfigService.get<string>('JWT_REFRESH_EXPIRATION', '7d'),
      },
      stripe: {
        secretKey: this.nestConfigService.get<string>('STRIPE_SECRET_KEY', ''),
        publishableKey: this.nestConfigService.get<string>('STRIPE_PUBLISHABLE_KEY', ''),
        webhookSecret: this.nestConfigService.get<string>('STRIPE_WEBHOOK_SECRET', ''),
      },
      twilio: {
        accountSid: this.nestConfigService.get<string>('TWILIO_ACCOUNT_SID', ''),
        authToken: this.nestConfigService.get<string>('TWILIO_AUTH_TOKEN', ''),
        phoneNumber: this.nestConfigService.get<string>('TWILIO_PHONE_NUMBER', ''),
      },
      aws: {
        region: this.nestConfigService.get<string>('AWS_REGION', 'us-east-1'),
        accessKeyId: this.nestConfigService.get<string>('AWS_ACCESS_KEY_ID', ''),
        secretAccessKey: this.nestConfigService.get<string>('AWS_SECRET_ACCESS_KEY', ''),
      },
      port: this.nestConfigService.get<number>('PORT', 3000),
      apiPrefix: this.nestConfigService.get<string>('API_PREFIX', 'api/v1'),
      nodeEnv: this.nestConfigService.get<string>('NODE_ENV', 'development'),
      stellarNetwork: this.nestConfigService.get<string>('STELLAR_NETWORK', 'testnet'),
      stellarRpcUrl: this.nestConfigService.get<string>('STELLAR_RPC_URL', ''),
      stellarNetworkPassphrase: this.nestConfigService.get<string>('STELLAR_NETWORK_PASSPHRASE', ''),
      projectLaunchContractId: this.nestConfigService.get<string>('PROJECT_LAUNCH_CONTRACT_ID', ''),
      escrowContractId: this.nestConfigService.get<string>('ESCROW_CONTRACT_ID', ''),
      indexerPollIntervalMs: this.nestConfigService.get<number>('INDEXER_POLL_INTERVAL_MS', 30000),
      indexerReorgDepthThreshold: this.nestConfigService.get<number>('INDEXER_REORG_DEPTH_THRESHOLD', 10),
    };
  }

  /**
   * Get the complete configuration
   */
  getConfig(): AppConfig {
    if (!this.initialized) {
      throw new Error('Configuration not yet initialized');
    }
    return this.config as AppConfig;
  }

  /**
   * Get database configuration
   */
  getDatabaseConfig() {
    return this.config.database;
  }

  /**
   * Get JWT configuration
   */
  getJwtConfig() {
    return this.config.jwt;
  }

  /**
   * Get Stripe configuration
   */
  getStripeConfig() {
    return this.config.stripe;
  }

  /**
   * Get Twilio configuration
   */
  getTwilioConfig() {
    return this.config.twilio;
  }

  /**
   * Get AWS configuration
   */
  getAwsConfig() {
    return this.config.aws;
  }

  /**
   * Get a specific configuration value
   */
  get<T = any>(key: keyof AppConfig | string): T | undefined {
    const keys = key.split('.');
    let value: any = this.config;

    for (const k of keys) {
      if (value && typeof value === 'object' && k in value) {
        value = value[k];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Check if configuration is loaded
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Refresh configuration (useful for testing or manual updates)
   */
  async refreshConfiguration(): Promise<void> {
    this.logger.log('Refreshing configuration...');
    await this.loadConfiguration();
    this.logger.log('Configuration refreshed successfully');
  }
}