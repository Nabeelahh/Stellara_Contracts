// src/object-storage/providers/gcp-storage.provider.ts
import { Injectable } from '@nestjs/common';
import { Storage } from '@google-cloud/storage';
import { ObjectStorageProvider, ObjectStorageConfig, UploadOptions } from '../object-storage.interface';

@Injectable()
export class GcpStorageProvider implements ObjectStorageProvider {
  private storage: Storage;
  private bucket: string;

  constructor(private config: ObjectStorageConfig) {
    this.bucket = config.bucket;

    if (config.credentials.serviceAccountKey) {
      // Use service account key
      this.storage = new Storage({
        projectId: config.credentials.projectId,
        credentials: JSON.parse(config.credentials.serviceAccountKey),
      });
    } else {
      // Use default credentials (for GKE workloads)
      this.storage = new Storage({
        projectId: config.credentials.projectId,
      });
    }
  }

  async upload(file: Buffer, key: string, options?: UploadOptions): Promise<string> {
    const bucket = this.storage.bucket(this.bucket);
    const fileObj = bucket.file(key);

    const uploadOptions = {
      contentType: options?.contentType,
      metadata: {
        metadata: options?.metadata,
      },
      public: options?.acl === 'public-read',
    };

    await fileObj.save(file, uploadOptions);
    return `gs://${this.bucket}/${key}`;
  }

  async download(key: string): Promise<Buffer> {
    const bucket = this.storage.bucket(this.bucket);
    const fileObj = bucket.file(key);

    const [buffer] = await fileObj.download();
    return buffer;
  }

  async delete(key: string): Promise<void> {
    const bucket = this.storage.bucket(this.bucket);
    const fileObj = bucket.file(key);

    await fileObj.delete();
  }

  async list(prefix?: string): Promise<string[]> {
    const bucket = this.storage.bucket(this.bucket);
    const [files] = await bucket.getFiles({ prefix });

    return files.map(file => file.name);
  }

  async getSignedUrl(key: string, expiresIn: number): Promise<string> {
    const bucket = this.storage.bucket(this.bucket);
    const fileObj = bucket.file(key);

    const [url] = await fileObj.getSignedUrl({
      action: 'read',
      expires: Date.now() + expiresIn * 1000,
    });

    return url;
  }

  async exists(key: string): Promise<boolean> {
    const bucket = this.storage.bucket(this.bucket);
    const fileObj = bucket.file(key);

    try {
      await fileObj.exists();
      return true;
    } catch (error) {
      return false;
    }
  }
}