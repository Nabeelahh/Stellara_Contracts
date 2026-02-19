/**
 * Stellara Contract Event Indexer
 *
 * This script demonstrates how to:
 * 1. Subscribe to contract events from Stellar/Soroban
 * 2. Parse and decode event data
 * 3. Store events in a local database for querying
 * 4. Handle event-specific business logic
 *
 * Usage:
 *   npm install
 *   npm start
 *
 * Configuration via environment variables:
 *   STELLAR_RPC_URL - Soroban RPC endpoint (default: testnet)
 *   CONTRACT_IDS - Comma-separated list of contract IDs to monitor
 *   DATABASE_PATH - Path to SQLite database (default: ./events.db)
 *   POLL_INTERVAL - Polling interval in ms (default: 5000)
 */

import * as StellarSdk from '@stellar/stellar-sdk';
import { EventDatabase } from './database';
import {
  EVENT_TOPICS,
  type TradeExecutedEvent,
  type ProposalCreatedEvent,
  type ProposalApprovedEvent,
  type RewardAddedEvent,
  type RewardClaimedEvent,
  type ContractPausedEvent,
  type ContractUnpausedEvent,
  type FeeCollectedEvent,
} from './types';

// =============================================================================
// Configuration
// =============================================================================

const config = {
  rpcUrl: process.env.STELLAR_RPC_URL || 'https://soroban-testnet.stellar.org',
  contractIds: (process.env.CONTRACT_IDS || '').split(',').filter(Boolean),
  databasePath: process.env.DATABASE_PATH || './events.db',
  pollInterval: parseInt(process.env.POLL_INTERVAL || '5000', 10),
  startLedger: parseInt(process.env.START_LEDGER || '0', 10),
};

// =============================================================================
// Event Decoder
// =============================================================================

/**
 * Decodes a Soroban event value from XDR to a JavaScript object
 */
function decodeEventValue(value: StellarSdk.xdr.ScVal): unknown {
  const scValType = value.switch().name;

  switch (scValType) {
    case 'scvBool':
      return value.b();
    case 'scvU64':
      return BigInt(value.u64().toString());
    case 'scvI64':
      return BigInt(value.i64().toString());
    case 'scvU128': {
      const u128 = value.u128();
      const hi = BigInt(u128.hi().toString()) << 64n;
      const lo = BigInt(u128.lo().toString());
      return hi | lo;
    }
    case 'scvI128': {
      const i128 = value.i128();
      const hi = BigInt(i128.hi().toString()) << 64n;
      const lo = BigInt(i128.lo().toString());
      return hi | lo;
    }
    case 'scvSymbol':
      return value.sym().toString();
    case 'scvString':
      return value.str().toString();
    case 'scvAddress':
      return StellarSdk.Address.fromScVal(value).toString();
    case 'scvMap': {
      const map = value.map();
      if (!map) return {};
      const result: Record<string, unknown> = {};
      for (const entry of map) {
        const key = decodeEventValue(entry.key());
        const val = decodeEventValue(entry.val());
        result[String(key)] = val;
      }
      return result;
    }
    case 'scvVec': {
      const vec = value.vec();
      if (!vec) return [];
      return vec.map(v => decodeEventValue(v));
    }
    default:
      return value.toXDR('base64');
  }
}

/**
 * Extracts the topic string from event topics
 */
function extractTopic(topics: StellarSdk.xdr.ScVal[]): string {
  if (topics.length === 0) return 'unknown';
  return decodeEventValue(topics[0]) as string;
}

// =============================================================================
// Event Handlers
// =============================================================================

class EventHandler {
  constructor(private db: EventDatabase) {}

  handleTradeExecuted(contractId: string, data: TradeExecutedEvent, ledger: number, txHash: string): void {
    console.log(`[Trade] ID: ${data.trade_id}, Trader: ${data.trader}, Pair: ${data.pair}, Amount: ${data.amount}`);

    this.db.insertTrade({
      trade_id: data.trade_id,
      contract_id: contractId,
      trader: data.trader,
      pair: data.pair,
      amount: data.amount,
      price: data.price,
      is_buy: data.is_buy,
      fee_amount: data.fee_amount,
      fee_token: data.fee_token,
      timestamp: data.timestamp,
      ledger,
      tx_hash: txHash,
    });
  }

  handleContractPaused(contractId: string, data: ContractPausedEvent): void {
    console.log(`[Pause] Contract ${contractId} paused by ${data.paused_by}`);
    // Could trigger alerts, notifications, etc.
  }

  handleContractUnpaused(contractId: string, data: ContractUnpausedEvent): void {
    console.log(`[Unpause] Contract ${contractId} unpaused by ${data.unpaused_by}`);
  }

  handleFeeCollected(contractId: string, data: FeeCollectedEvent): void {
    console.log(`[Fee] ${data.amount} collected from ${data.payer} to ${data.recipient}`);
  }

  handleProposalCreated(
    contractId: string,
    data: ProposalCreatedEvent,
    ledger: number,
    txHash: string
  ): void {
    console.log(`[Proposal] ID: ${data.proposal_id}, Proposer: ${data.proposer}`);

    this.db.insertProposal({
      proposal_id: data.proposal_id,
      contract_id: contractId,
      proposer: data.proposer,
      new_contract_hash: data.new_contract_hash,
      target_contract: data.target_contract,
      description: data.description,
      approval_threshold: data.approval_threshold,
      timelock_delay: data.timelock_delay,
      status: 'pending',
      created_at: data.timestamp,
      ledger,
      tx_hash: txHash,
    });
  }

  handleProposalApproved(contractId: string, data: ProposalApprovedEvent): void {
    console.log(`[Approval] Proposal ${data.proposal_id} approved by ${data.approver} (${data.current_approvals}/${data.threshold})`);

    this.db.updateProposalApprovals(contractId, data.proposal_id, data.current_approvals);

    if (data.current_approvals >= data.threshold) {
      this.db.updateProposalStatus(contractId, data.proposal_id, 'approved');
    }
  }

  handleProposalRejected(contractId: string, proposalId: bigint): void {
    console.log(`[Reject] Proposal ${proposalId} rejected`);
    this.db.updateProposalStatus(contractId, proposalId, 'rejected');
  }

  handleProposalExecuted(contractId: string, proposalId: bigint): void {
    console.log(`[Execute] Proposal ${proposalId} executed`);
    this.db.updateProposalStatus(contractId, proposalId, 'executed');
  }

  handleProposalCancelled(contractId: string, proposalId: bigint): void {
    console.log(`[Cancel] Proposal ${proposalId} cancelled`);
    this.db.updateProposalStatus(contractId, proposalId, 'cancelled');
  }

  handleRewardAdded(contractId: string, data: RewardAddedEvent, ledger: number, txHash: string): void {
    console.log(`[Reward] ID: ${data.reward_id}, User: ${data.user}, Amount: ${data.amount}, Type: ${data.reward_type}`);

    this.db.insertReward({
      reward_id: data.reward_id,
      contract_id: contractId,
      user: data.user,
      amount: data.amount,
      reward_type: data.reward_type,
      reason: data.reason,
      granted_by: data.granted_by,
      granted_at: data.timestamp,
      claimed: false,
      claimed_at: null,
      ledger,
      tx_hash: txHash,
    });
  }

  handleRewardClaimed(contractId: string, data: RewardClaimedEvent): void {
    console.log(`[Claim] Reward ${data.reward_id} claimed by ${data.user}, Amount: ${data.amount}`);
    this.db.markRewardClaimed(contractId, data.reward_id, data.timestamp);
  }
}

// =============================================================================
// Event Indexer
// =============================================================================

class EventIndexer {
  private server: StellarSdk.SorobanRpc.Server;
  private db: EventDatabase;
  private handler: EventHandler;
  private running = false;

  constructor() {
    this.server = new StellarSdk.SorobanRpc.Server(config.rpcUrl);
    this.db = new EventDatabase(config.databasePath);
    this.handler = new EventHandler(this.db);
  }

  async start(): Promise<void> {
    console.log('Starting Stellara Event Indexer...');
    console.log(`RPC URL: ${config.rpcUrl}`);
    console.log(`Contracts: ${config.contractIds.length > 0 ? config.contractIds.join(', ') : '(all)'}`);
    console.log(`Poll Interval: ${config.pollInterval}ms`);

    this.running = true;

    // Get starting point
    const cursor = this.db.getCursor();
    let startLedger = cursor.last_ledger || config.startLedger;

    if (startLedger === 0) {
      // Start from recent ledger if no cursor
      const latestLedger = await this.server.getLatestLedger();
      startLedger = latestLedger.sequence - 100; // Start 100 ledgers back
    }

    console.log(`Starting from ledger: ${startLedger}`);

    while (this.running) {
      try {
        await this.pollEvents(startLedger);
        startLedger = this.db.getCursor().last_ledger + 1;
      } catch (error) {
        console.error('Error polling events:', error);
      }

      await this.sleep(config.pollInterval);
    }
  }

  stop(): void {
    console.log('Stopping indexer...');
    this.running = false;
    this.db.close();
  }

  private async pollEvents(startLedger: number): Promise<void> {
    try {
      const response = await this.server.getEvents({
        startLedger,
        filters: config.contractIds.length > 0
          ? config.contractIds.map(id => ({
              type: 'contract' as const,
              contractIds: [id],
            }))
          : undefined,
        limit: 100,
      });

      if (!response.events || response.events.length === 0) {
        return;
      }

      console.log(`Processing ${response.events.length} events...`);

      for (const event of response.events) {
        await this.processEvent(event);
      }

      // Update cursor to latest processed ledger
      const lastEvent = response.events[response.events.length - 1];
      this.db.updateCursor(lastEvent.ledger, lastEvent.pagingToken);
    } catch (error: any) {
      // Handle "start is before oldest ledger" error
      if (error?.message?.includes('start is before')) {
        const latestLedger = await this.server.getLatestLedger();
        this.db.updateCursor(latestLedger.sequence - 10);
        console.log(`Cursor reset to ledger ${latestLedger.sequence - 10}`);
      } else {
        throw error;
      }
    }
  }

  private async processEvent(event: StellarSdk.SorobanRpc.Api.EventResponse): Promise<void> {
    const contractId = event.contractId;
    const ledger = event.ledger;
    const txHash = event.txHash;

    // Decode topics and value
    const topics = event.topic.map(t => StellarSdk.xdr.ScVal.fromXDR(t, 'base64'));
    const topic = extractTopic(topics);
    const value = StellarSdk.xdr.ScVal.fromXDR(event.value, 'base64');
    const data = decodeEventValue(value) as Record<string, unknown>;

    // Store generic event
    this.db.insertEvent({
      contract_id: contractId,
      topic,
      ledger,
      ledger_closed_at: event.ledgerClosedAt,
      tx_hash: txHash,
      event_index: parseInt(event.id.split('-').pop() || '0', 10),
      data,
    });

    // Handle specific event types
    switch (topic) {
      case EVENT_TOPICS.TRADE_EXECUTED:
        this.handler.handleTradeExecuted(contractId, data as unknown as TradeExecutedEvent, ledger, txHash);
        break;
      case EVENT_TOPICS.CONTRACT_PAUSED:
        this.handler.handleContractPaused(contractId, data as unknown as ContractPausedEvent);
        break;
      case EVENT_TOPICS.CONTRACT_UNPAUSED:
        this.handler.handleContractUnpaused(contractId, data as unknown as ContractUnpausedEvent);
        break;
      case EVENT_TOPICS.FEE_COLLECTED:
        this.handler.handleFeeCollected(contractId, data as unknown as FeeCollectedEvent);
        break;
      case EVENT_TOPICS.PROPOSAL_CREATED:
        this.handler.handleProposalCreated(contractId, data as unknown as ProposalCreatedEvent, ledger, txHash);
        break;
      case EVENT_TOPICS.PROPOSAL_APPROVED:
        this.handler.handleProposalApproved(contractId, data as unknown as ProposalApprovedEvent);
        break;
      case EVENT_TOPICS.PROPOSAL_REJECTED:
        this.handler.handleProposalRejected(contractId, (data as any).proposal_id);
        break;
      case EVENT_TOPICS.PROPOSAL_EXECUTED:
        this.handler.handleProposalExecuted(contractId, (data as any).proposal_id);
        break;
      case EVENT_TOPICS.PROPOSAL_CANCELLED:
        this.handler.handleProposalCancelled(contractId, (data as any).proposal_id);
        break;
      case EVENT_TOPICS.REWARD_ADDED:
        this.handler.handleRewardAdded(contractId, data as unknown as RewardAddedEvent, ledger, txHash);
        break;
      case EVENT_TOPICS.REWARD_CLAIMED:
        this.handler.handleRewardClaimed(contractId, data as unknown as RewardClaimedEvent);
        break;
      default:
        console.log(`[Unknown] Topic: ${topic}, Data:`, data);
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// =============================================================================
// Main
// =============================================================================

async function main(): Promise<void> {
  const indexer = new EventIndexer();

  // Handle graceful shutdown
  process.on('SIGINT', () => indexer.stop());
  process.on('SIGTERM', () => indexer.stop());

  await indexer.start();
}

main().catch(console.error);
