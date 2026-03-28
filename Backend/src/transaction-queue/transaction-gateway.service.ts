import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomUUID, createHash } from 'node:crypto';
import { CircuitBreakerService } from '../circuit-breaker/circuit-breaker.service';

export type SubmittedTxResult = {
  txHash: string;
  nonce: bigint;
  feeBid: bigint;
  raw: Record<string, unknown>;
};

export type PolledTxResult = {
  status: 'PENDING' | 'CONFIRMED' | 'FAILED';
  raw: Record<string, unknown>;
};

type SimulatedTxState = {
  polls: number;
  status: 'PENDING' | 'CONFIRMED' | 'FAILED';
  submittedAt: number;
  failureReason?: string;
};

@Injectable()
export class TransactionGatewayService {
  private readonly logger = new Logger(TransactionGatewayService.name);
  private readonly simulationMode: boolean;
  private readonly simulatedTransactions = new Map<string, SimulatedTxState>();

  constructor(
    private readonly configService: ConfigService,
    private readonly circuitBreakerService: CircuitBreakerService,
  ) {
    this.simulationMode =
      this.configService.get<string>('TX_QUEUE_SIMULATION_MODE', 'true') === 'true';
    this.circuitBreakerService.register('stellar-rpc', {
      failureThreshold: 5,
      failureWindowMs: 10_000,
      openTimeoutMs: 30_000,
      halfOpenMaxCalls: 10,
      halfOpenSuccessThreshold: 3,
    });
  }

  async submitTransaction(input: {
    signerAddress: string;
    contractAddress: string;
    functionName: string;
    payload: Record<string, unknown>;
    nonce: bigint;
    feeBid: bigint;
  }): Promise<SubmittedTxResult> {
    return this.circuitBreakerService.execute('stellar-rpc', async () => {
      if (this.simulationMode) {
        const hash = createHash('sha256')
          .update(
            JSON.stringify({
              signer: input.signerAddress,
              contract: input.contractAddress,
              functionName: input.functionName,
              payload: input.payload,
              nonce: input.nonce.toString(),
              feeBid: input.feeBid.toString(),
              seed: randomUUID(),
            }),
          )
          .digest('hex');

        const txHash = `sim_${hash.slice(0, 48)}`;
        this.simulatedTransactions.set(txHash, {
          polls: 0,
          status: 'PENDING',
          submittedAt: Date.now(),
        });

        return {
          txHash,
          nonce: input.nonce,
          feeBid: input.feeBid,
          raw: {
            mode: 'simulation',
            acceptedAt: new Date().toISOString(),
          },
        };
      }

      this.logger.error(
        'Real Stellar submission is not wired yet. Set TX_QUEUE_SIMULATION_MODE=true for local/dev.',
      );
      throw new Error('Blockchain gateway is not configured for live submission');
    });
  }

  async getTransactionStatus(txHash: string): Promise<PolledTxResult> {
    return this.circuitBreakerService.execute('stellar-rpc', async () => {
      if (this.simulationMode) {
        const tx = this.simulatedTransactions.get(txHash);
        if (!tx) {
          return {
            status: 'FAILED',
            raw: { reason: 'transaction_not_found' },
          };
        }

        tx.polls += 1;

        if (tx.status === 'PENDING' && tx.polls >= 3) {
          tx.status = 'CONFIRMED';
        }

        return {
          status: tx.status,
          raw: {
            mode: 'simulation',
            polls: tx.polls,
            submittedAt: new Date(tx.submittedAt).toISOString(),
            failureReason: tx.failureReason,
          },
        };
      }

      throw new Error('Blockchain gateway status polling is not configured');
    });
  }

  async bumpFee(txHash: string, newFeeBid: bigint): Promise<{ accepted: boolean }> {
    return this.circuitBreakerService.execute('stellar-rpc', async () => {
      if (this.simulationMode) {
        const tx = this.simulatedTransactions.get(txHash);
        if (!tx) {
          return { accepted: false };
        }

        // Simulate that fee bump nudges a pending tx toward confirmation.
        tx.polls = Math.max(tx.polls, 2);
        return { accepted: true };
      }

      throw new Error('Blockchain gateway fee bumping is not configured');
    });
  }
}

