// src/object-storage/providers/azure-blob.provider.ts
import { Injectable } from '@nestjs/common';
import { BlobServiceClient, StorageSharedKeyCredential } from '@azure/storage-blob';
import { ObjectStorageProvider, ObjectStorageConfig, UploadOptions } from '../object-storage.interface';

@Injectable()
export class AzureBlobProvider implements ObjectStorageProvider {
  private blobServiceClient: BlobServiceClient;

  constructor(private config: ObjectStorageConfig) {
    const sharedKeyCredential = new StorageSharedKeyCredential(
      config.credentials.accountName!,
      config.credentials.accountKey!
    );

    this.blobServiceClient = new BlobServiceClient(
      `https://${config.credentials.accountName}.blob.core.windows.net`,
      sharedKeyCredential
    );
  }

  async upload(file: Buffer, key: string, options?: UploadOptions): Promise<string> {
    const containerClient = this.blobServiceClient.getContainerClient(this.config.bucket);
    const blockBlobClient = containerClient.getBlockBlobClient(key);

    const uploadOptions = {
      blobHTTPHeaders: {
        blobContentType: options?.contentType,
      },
      metadata: options?.metadata,
    };

    await blockBlobClient.upload(file, file.length, uploadOptions);
    return `https://${this.config.credentials.accountName}.blob.core.windows.net/${this.config.bucket}/${key}`;
  }

  async download(key: string): Promise<Buffer> {
    const containerClient = this.blobServiceClient.getContainerClient(this.config.bucket);
    const blockBlobClient = containerClient.getBlockBlobClient(key);

    const downloadResponse = await blockBlobClient.download();
    if (!downloadResponse.readableStreamBody) {
      throw new Error(`Object ${key} not found`);
    }

    const chunks: Buffer[] = [];
    for await (const chunk of downloadResponse.readableStreamBody) {
      chunks.push(Buffer.from(chunk));
    }

    return Buffer.concat(chunks);
  }

  async delete(key: string): Promise<void> {
    const containerClient = this.blobServiceClient.getContainerClient(this.config.bucket);
    const blockBlobClient = containerClient.getBlockBlobClient(key);

    await blockBlobClient.delete();
  }

  async list(prefix?: string): Promise<string[]> {
    const containerClient = this.blobServiceClient.getContainerClient(this.config.bucket);
    const blobs: string[] = [];

    for await (const blob of containerClient.listBlobsFlat({ prefix })) {
      blobs.push(blob.name);
    }

    return blobs;
  }

  async getSignedUrl(key: string, expiresIn: number): Promise<string> {
    const containerClient = this.blobServiceClient.getContainerClient(this.config.bucket);
    const blockBlobClient = containerClient.getBlockBlobClient(key);

    const expiresOn = new Date(Date.now() + expiresIn * 1000);
    const sasToken = await blockBlobClient.generateSasUrl({
      expiresOn,
      permissions: { read: true },
    });

    return sasToken;
  }

  async exists(key: string): Promise<boolean> {
    const containerClient = this.blobServiceClient.getContainerClient(this.config.bucket);
    const blockBlobClient = containerClient.getBlockBlobClient(key);

    try {
      await blockBlobClient.getProperties();
      return true;
    } catch (error) {
      return false;
    }
  }
}