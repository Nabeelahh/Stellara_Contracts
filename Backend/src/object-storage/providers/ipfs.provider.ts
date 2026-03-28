import { Buffer } from 'buffer';
import { create, IPFSHTTPClient } from 'ipfs-http-client';
import { ObjectStorageConfig, ObjectStorageProvider, UploadOptions } from '../object-storage.interface';

export class IpfsProvider implements ObjectStorageProvider {
  private client: IPFSHTTPClient;
  private gatewayUrl: string;

  constructor(private config: ObjectStorageConfig) {
    const host = (config as any).host || 'ipfs.infura.io';
    const port = (config as any).port || 5001;
    const protocol = (config as any).protocol || 'https';
    const auth = this.getAuthHeader((config as any).auth);
    const url = `${protocol}://${host}:${port}/api/v0`;
    this.gatewayUrl = (config as any).gatewayUrl || 'https://ipfs.io/ipfs';

    this.client = create({
      url,
      headers: auth ? { authorization: auth } : undefined,
    });
  }

  private getAuthHeader(auth: any): string | undefined {
    if (!auth) return undefined;
    if (auth.projectId && auth.projectSecret) {
      return `Basic ${Buffer.from(`${auth.projectId}:${auth.projectSecret}`).toString('base64')}`;
    }
    if (auth.apiKey && auth.apiSecret) {
      return `Basic ${Buffer.from(`${auth.apiKey}:${auth.apiSecret}`).toString('base64')}`;
    }
    return undefined;
  }

  async upload(file: Buffer, key: string): Promise<string> {
    const result = await this.client.add({ path: key, content: file }, { pin: true, wrapWithDirectory: false });
    if (!result.cid) {
      throw new Error('IPFS upload failed');
    }
    return `ipfs://${result.cid.toString()}`;
  }

  async download(key: string): Promise<Buffer> {
    const cid = key.replace(/^ipfs:\/\//, '');
    const chunks: Buffer[] = [];
    for await (const chunk of this.client.cat(cid)) {
      chunks.push(Buffer.from(chunk as Uint8Array));
    }
    return Buffer.concat(chunks);
  }

  async delete(key: string): Promise<void> {
    throw new Error('Delete is not supported for IPFS content-addressed storage');
  }

  async list(prefix?: string): Promise<string[]> {
    throw new Error('List is not supported for IPFS content-addressed storage');
  }

  async getSignedUrl(key: string): Promise<string> {
    const cid = key.replace(/^ipfs:\/\//, '');
    return `${this.gatewayUrl.replace(/\/$/, '')}/${cid}`;
  }

  async exists(key: string): Promise<boolean> {
    try {
      const cid = key.replace(/^ipfs:\/\//, '');
      for await (const _ of this.client.cat(cid)) {
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }
}
