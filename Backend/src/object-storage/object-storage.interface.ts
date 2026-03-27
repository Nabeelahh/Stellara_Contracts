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
}

export interface ObjectStorageConfig {
  provider: 'aws' | 'azure' | 'gcp';
  region?: string;
  bucket: string;
  credentials: {
    accessKeyId?: string;
    secretAccessKey?: string;
    accountName?: string;
    accountKey?: string;
    projectId?: string;
    serviceAccountKey?: string;
  };
}