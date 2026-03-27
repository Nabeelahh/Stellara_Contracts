import { Injectable, Logger } from '@nestjs/common';
import { ethers } from 'ethers';

@Injectable()
export class MetaRelayerService {
  private readonly logger = new Logger(MetaRelayerService.name);
  private provider: ethers.providers.JsonRpcProvider | null = null;
  private relayerWallet: ethers.Wallet | null = null;

  constructor() {
    const rpc = process.env.ETH_RPC_URL || null;
    const pk = process.env.RELAYER_PRIVATE_KEY || null;
    if (rpc && pk) {
      this.provider = new ethers.providers.JsonRpcProvider(rpc);
      this.relayerWallet = new ethers.Wallet(pk, this.provider);
    }
  }

  /**
   * Relay a signed EIP-712 meta-transaction.
   * For now: expects a raw transaction payload and a signature from the user.
   */
  async relayRawTx(rawTx: string, userSignature: string) {
    if (!this.relayerWallet) throw new Error('Relayer not configured');
    // In production: verify signature against EIP-712 typed data and nonce management
    const tx = await this.relayerWallet.sendTransaction({ data: rawTx });
    this.logger.log(`Relayed tx ${tx.hash}`);
    await tx.wait();
    return tx.hash;
  }
}
