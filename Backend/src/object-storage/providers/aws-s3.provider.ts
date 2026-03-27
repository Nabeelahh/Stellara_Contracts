// src/object-storage/providers/aws-s3.provider.ts
import { Injectable } from '@nestjs/common';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command, HeadObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { ObjectStorageProvider, ObjectStorageConfig, UploadOptions } from '../object-storage.interface';

@Injectable()
export class AwsS3Provider implements ObjectStorageProvider {
  private s3Client: S3Client;

  constructor(private config: ObjectStorageConfig) {
    this.s3Client = new S3Client({
      region: config.region || 'us-east-1',
      credentials: {
        accessKeyId: config.credentials.accessKeyId!,
        secretAccessKey: config.credentials.secretAccessKey!,
      },
    });
  }

  async upload(file: Buffer, key: string, options?: UploadOptions): Promise<string> {
    const command = new PutObjectCommand({
      Bucket: this.config.bucket,
      Key: key,
      Body: file,
      ContentType: options?.contentType,
      Metadata: options?.metadata,
      ACL: options?.acl === 'public-read' ? 'public-read' : 'private',
    });

    await this.s3Client.send(command);
    return `s3://${this.config.bucket}/${key}`;
  }

  async download(key: string): Promise<Buffer> {
    const command = new GetObjectCommand({
      Bucket: this.config.bucket,
      Key: key,
    });

    const response = await this.s3Client.send(command);
    if (!response.Body) {
      throw new Error(`Object ${key} not found`);
    }

    return Buffer.from(await response.Body.transformToByteArray());
  }

  async delete(key: string): Promise<void> {
    const command = new DeleteObjectCommand({
      Bucket: this.config.bucket,
      Key: key,
    });

    await this.s3Client.send(command);
  }

  async list(prefix?: string): Promise<string[]> {
    const command = new ListObjectsV2Command({
      Bucket: this.config.bucket,
      Prefix: prefix,
    });

    const response = await this.s3Client.send(command);
    return (response.Contents || []).map(obj => obj.Key!).filter(Boolean);
  }

  async getSignedUrl(key: string, expiresIn: number): Promise<string> {
    const command = new GetObjectCommand({
      Bucket: this.config.bucket,
      Key: key,
    });

    return getSignedUrl(this.s3Client, command, { expiresIn });
  }

  async exists(key: string): Promise<boolean> {
    try {
      const command = new HeadObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      });

      await this.s3Client.send(command);
      return true;
    } catch (error) {
      return false;
    }
  }
}