import Arweave from 'arweave';
import { Buffer } from 'buffer';
import { ObjectStorageConfig, ObjectStorageProvider, UploadOptions } from '../object-storage.interface';

export class ArweaveProvider implements ObjectStorageProvider {
  private client: Arweave;
  private wallet: any;
  private gatewayUrl: string;

  constructor(private config: ObjectStorageConfig) {
    const host = (config as any).host || 'arweave.net';
    const port = (config as any).port || 443;
    const protocol = (config as any).protocol || 'https';
    this.gatewayUrl = (config as any).gatewayUrl || 'https://arweave.net';

    this.client = Arweave.init({
      host,
      port,
      protocol,
    });

    if (!(config as any).walletJson) {
      throw new Error('ARWEAVE_WALLET_JSON is required for Arweave provider');
    }

    try {
      this.wallet = JSON.parse((config as any).walletJson);
    } catch (error) {
      throw new Error('Invalid Arweave wallet JSON');
    }
  }

  async upload(file: Buffer, key: string, options?: UploadOptions): Promise<string> {
    const transaction = await this.client.createTransaction({ data: file }, this.wallet);
    transaction.addTag('Content-Type', options?.contentType || 'application/octet-stream');
    transaction.addTag('App-Name', 'stellara-backend');
    transaction.addTag('Resource-Key', key);

    await this.client.transactions.sign(transaction, this.wallet);
    const response = await this.client.transactions.post(transaction);

    if (response.status !== 200 && response.status !== 202) {
      throw new Error(`Arweave upload failed with status ${response.status}`);
    }

    return `ar://${transaction.id}`;
  }

  async download(key: string): Promise<Buffer> {
    const txId = key.replace(/^ar:\/\//, '');
    const data = await this.client.transactions.getData(txId, { decode: true, string: false });
    return Buffer.from(data as ArrayBuffer);
  }

  async delete(key: string): Promise<void> {
    throw new Error('Delete is not supported for Arweave immutable storage');
  }

  async list(prefix?: string): Promise<string[]> {
    throw new Error('List is not supported for Arweave immutable storage');
  }

  async getSignedUrl(key: string): Promise<string> {
    const txId = key.replace(/^ar:\/\//, '');
    return `${this.gatewayUrl.replace(/\/$/, '')}/${txId}`;
  }

  async exists(key: string): Promise<boolean> {
    try {
      const txId = key.replace(/^ar:\/\//, '');
      const status = await this.client.transactions.getStatus(txId);
      return status.status === 200 || status.status === 202 || status.status === 208;
    } catch {
      return false;
    }
  }
}
