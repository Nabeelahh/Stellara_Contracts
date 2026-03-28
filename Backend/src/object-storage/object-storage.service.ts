// src/object-storage/object-storage.service.ts
import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ObjectStorageProvider, ObjectStorageConfig, UploadOptions } from './object-storage.interface';
import { AwsS3Provider } from './providers/aws-s3.provider';
import { AzureBlobProvider } from './providers/azure-blob.provider';
import { GcpStorageProvider } from './providers/gcp-storage.provider';
import { IpfsProvider } from './providers/ipfs.provider';
import { ArweaveProvider } from './providers/arweave.provider';

@Injectable()
export class ObjectStorageService {
  private provider: ObjectStorageProvider;

  constructor(private configService: ConfigService) {
    const providerType = this.configService.get<string>('OBJECT_STORAGE_PROVIDER', 'aws');
    const config = this.getProviderConfig(providerType);

    switch (providerType) {
      case 'aws':
        this.provider = new AwsS3Provider(config);
        break;
      case 'azure':
        this.provider = new AzureBlobProvider(config);
        break;
      case 'gcp':
        this.provider = new GcpStorageProvider(config);
        break;
      case 'ipfs':
        this.provider = new IpfsProvider(config);
        break;
      case 'arweave':
        this.provider = new ArweaveProvider(config);
        break;
      default:
        throw new Error(`Unsupported object storage provider: ${providerType}`);
    }
  }

  private getProviderConfig(provider: string): ObjectStorageConfig {
    const baseConfig = {
      provider: provider as 'aws' | 'azure' | 'gcp' | 'ipfs' | 'arweave',
      bucket: this.configService.get<string>('OBJECT_STORAGE_BUCKET', 'stellara-storage'),
    };

    switch (provider) {
      case 'aws':
        return {
          ...baseConfig,
          region: this.configService.get<string>('AWS_REGION', 'us-east-1'),
          credentials: {
            accessKeyId: this.configService.get<string>('AWS_ACCESS_KEY_ID'),
            secretAccessKey: this.configService.get<string>('AWS_SECRET_ACCESS_KEY'),
          },
        };
      case 'azure':
        return {
          ...baseConfig,
          credentials: {
            accountName: this.configService.get<string>('AZURE_STORAGE_ACCOUNT'),
            accountKey: this.configService.get<string>('AZURE_STORAGE_KEY'),
          },
        };
      case 'gcp':
        return {
          ...baseConfig,
          credentials: {
            projectId: this.configService.get<string>('GCP_PROJECT_ID'),
            serviceAccountKey: this.configService.get<string>('GCP_SERVICE_ACCOUNT_KEY'),
          },
        };
      case 'ipfs':
        return {
          ...baseConfig,
          host: this.configService.get<string>('IPFS_HOST', 'ipfs.infura.io'),
          port: Number(this.configService.get<string>('IPFS_PORT', '5001')),
          protocol: this.configService.get<string>('IPFS_PROTOCOL', 'https') as 'https' | 'http',
          auth: {
            projectId: this.configService.get<string>('IPFS_PROJECT_ID'),
            projectSecret: this.configService.get<string>('IPFS_PROJECT_SECRET'),
            apiKey: this.configService.get<string>('IPFS_API_KEY'),
            apiSecret: this.configService.get<string>('IPFS_API_SECRET'),
          },
          gatewayUrl: this.configService.get<string>('IPFS_GATEWAY_URL', 'https://ipfs.io/ipfs'),
        };
      case 'arweave':
        return {
          ...baseConfig,
          host: this.configService.get<string>('ARWEAVE_HOST', 'arweave.net'),
          port: Number(this.configService.get<string>('ARWEAVE_PORT', '443')),
          protocol: this.configService.get<string>('ARWEAVE_PROTOCOL', 'https') as 'https' | 'http',
          walletJson: this.configService.get<string>('ARWEAVE_WALLET_JSON'),
          gatewayUrl: this.configService.get<string>('ARWEAVE_GATEWAY_URL', 'https://arweave.net'),
        };
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }
  }

  async upload(file: Buffer, key: string, options?: UploadOptions): Promise<string> {
    return this.provider.upload(file, key, options);
  }

  async download(key: string): Promise<Buffer> {
    return this.provider.download(key);
  }

  async delete(key: string): Promise<void> {
    return this.provider.delete(key);
  }

  async list(prefix?: string): Promise<string[]> {
    return this.provider.list(prefix);
  }

  async getSignedUrl(key: string, expiresIn: number = 3600): Promise<string> {
    return this.provider.getSignedUrl(key, expiresIn);
  }

  async exists(key: string): Promise<boolean> {
    return this.provider.exists(key);
  }

  // Multi-cloud replication methods
  async uploadWithReplication(file: Buffer, key: string, options?: UploadOptions): Promise<string[]> {
    const results: string[] = [];

    // Upload to primary provider
    const primaryUrl = await this.upload(file, key, options);
    results.push(primaryUrl);

    // TODO: Implement cross-cloud replication
    // This would upload to secondary providers for redundancy

    return results;
  }

  async getNearestUrl(key: string, expiresIn: number = 3600): Promise<string> {
    // TODO: Implement geo-aware URL selection
    // This would return the URL from the geographically closest provider
    return this.getSignedUrl(key, expiresIn);
  }
}