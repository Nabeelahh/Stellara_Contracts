/**
 * Standardized event types for Stellara contracts
 * These types mirror the on-chain event structures for off-chain indexing
 */

// =============================================================================
// Event Topic Constants
// =============================================================================

export const EVENT_TOPICS = {
  // Trading events
  TRADE_EXECUTED: 'trade',
  CONTRACT_PAUSED: 'paused',
  CONTRACT_UNPAUSED: 'unpause',
  FEE_COLLECTED: 'fee',

  // Governance events
  PROPOSAL_CREATED: 'propose',
  PROPOSAL_APPROVED: 'approve',
  PROPOSAL_REJECTED: 'reject',
  PROPOSAL_EXECUTED: 'execute',
  PROPOSAL_CANCELLED: 'cancel',

  // Social rewards events
  REWARD_ADDED: 'reward',
  REWARD_CLAIMED: 'claimed',

  // Token events
  TRANSFER: 'transfer',
  MINT: 'mint',
  BURN: 'burn',

  // Vesting events
  GRANT: 'grant',
  CLAIM: 'claim',
  REVOKE: 'revoke',
} as const;

export type EventTopic = typeof EVENT_TOPICS[keyof typeof EVENT_TOPICS];

// =============================================================================
// Trading Events
// =============================================================================

export interface TradeExecutedEvent {
  trade_id: bigint;
  trader: string;
  pair: string;
  amount: bigint;
  price: bigint;
  is_buy: boolean;
  fee_amount: bigint;
  fee_token: string;
  timestamp: bigint;
}

export interface ContractPausedEvent {
  paused_by: string;
  timestamp: bigint;
}

export interface ContractUnpausedEvent {
  unpaused_by: string;
  timestamp: bigint;
}

export interface FeeCollectedEvent {
  payer: string;
  recipient: string;
  amount: bigint;
  token: string;
  timestamp: bigint;
}

// =============================================================================
// Governance Events
// =============================================================================

export interface ProposalCreatedEvent {
  proposal_id: bigint;
  proposer: string;
  new_contract_hash: string;
  target_contract: string;
  description: string;
  approval_threshold: number;
  timelock_delay: bigint;
  timestamp: bigint;
}

export interface ProposalApprovedEvent {
  proposal_id: bigint;
  approver: string;
  current_approvals: number;
  threshold: number;
  timestamp: bigint;
}

export interface ProposalRejectedEvent {
  proposal_id: bigint;
  rejector: string;
  timestamp: bigint;
}

export interface ProposalExecutedEvent {
  proposal_id: bigint;
  executor: string;
  new_contract_hash: string;
  timestamp: bigint;
}

export interface ProposalCancelledEvent {
  proposal_id: bigint;
  cancelled_by: string;
  timestamp: bigint;
}

// =============================================================================
// Social Rewards Events
// =============================================================================

export interface RewardAddedEvent {
  reward_id: bigint;
  user: string;
  amount: bigint;
  reward_type: string;
  reason: string;
  granted_by: string;
  timestamp: bigint;
}

export interface RewardClaimedEvent {
  reward_id: bigint;
  user: string;
  amount: bigint;
  timestamp: bigint;
}

// =============================================================================
// Vesting Events
// =============================================================================

export interface GrantEvent {
  grant_id: bigint;
  beneficiary: string;
  amount: bigint;
  start_time: bigint;
  cliff: bigint;
  duration: bigint;
  granted_at: bigint;
  granted_by: string;
}

export interface ClaimEvent {
  grant_id: bigint;
  beneficiary: string;
  amount: bigint;
  claimed_at: bigint;
}

export interface RevokeEvent {
  grant_id: bigint;
  beneficiary: string;
  revoked_at: bigint;
  revoked_by: string;
}

// =============================================================================
// Generic Event Wrapper
// =============================================================================

export interface IndexedEvent {
  id: number;
  contract_id: string;
  topic: EventTopic;
  ledger: number;
  ledger_closed_at: string;
  tx_hash: string;
  event_index: number;
  data: unknown;
  created_at: string;
}

// =============================================================================
// Database Schema Types
// =============================================================================

export interface Trade {
  id: number;
  trade_id: bigint;
  contract_id: string;
  trader: string;
  pair: string;
  amount: bigint;
  price: bigint;
  is_buy: boolean;
  fee_amount: bigint;
  fee_token: string;
  timestamp: bigint;
  ledger: number;
  tx_hash: string;
  indexed_at: string;
}

export interface Proposal {
  id: number;
  proposal_id: bigint;
  contract_id: string;
  proposer: string;
  new_contract_hash: string;
  target_contract: string;
  description: string;
  approval_threshold: number;
  timelock_delay: bigint;
  status: 'pending' | 'approved' | 'rejected' | 'executed' | 'cancelled';
  created_at: bigint;
  updated_at: string;
}

export interface Reward {
  id: number;
  reward_id: bigint;
  contract_id: string;
  user: string;
  amount: bigint;
  reward_type: string;
  reason: string;
  granted_by: string;
  granted_at: bigint;
  claimed: boolean;
  claimed_at: bigint | null;
  ledger: number;
  tx_hash: string;
  indexed_at: string;
}
