// src/object-storage/object-storage.interface.ts
export interface ObjectStorageProvider {
  upload(file: Buffer, key: string, options?: UploadOptions): Promise<string>;
  download(key: string): Promise<Buffer>;
  delete(key: string): Promise<void>;
  list(prefix?: string): Promise<string[]>;
  getSignedUrl(key: string, expiresIn: number): Promise<string>;
  exists(key: string): Promise<boolean>;
}

export interface UploadOptions {
  contentType?: string;
  metadata?: Record<string, string>;
  acl?: 'private' | 'public-read';
  storageClass?: 'STANDARD' | 'GLACIER' | 'DEEP_ARCHIVE';
}

export interface BaseObjectStorageConfig {
  provider: 'aws' | 'azure' | 'gcp' | 'ipfs' | 'arweave';
  bucket?: string;
}

export interface AwsStorageConfig extends BaseObjectStorageConfig {
  provider: 'aws';
  region?: string;
  credentials: {
    accessKeyId?: string;
    secretAccessKey?: string;
  };
}

export interface AzureStorageConfig extends BaseObjectStorageConfig {
  provider: 'azure';
  credentials: {
    accountName?: string;
    accountKey?: string;
  };
}

export interface GcpStorageConfig extends BaseObjectStorageConfig {
  provider: 'gcp';
  credentials: {
    projectId?: string;
    serviceAccountKey?: string;
  };
}

export interface IpfsStorageConfig extends BaseObjectStorageConfig {
  provider: 'ipfs';
  host?: string;
  port?: number;
  protocol?: 'https' | 'http';
  auth?: {
    projectId?: string;
    projectSecret?: string;
    apiKey?: string;
    apiSecret?: string;
  };
  gatewayUrl?: string;
}

export interface ArweaveStorageConfig extends BaseObjectStorageConfig {
  provider: 'arweave';
  host?: string;
  port?: number;
  protocol?: 'https' | 'http';
  gatewayUrl?: string;
  walletJson?: string;
}

export type ObjectStorageConfig =
  | AwsStorageConfig
  | AzureStorageConfig
  | GcpStorageConfig
  | IpfsStorageConfig
  | ArweaveStorageConfig;
