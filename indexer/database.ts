/**
 * SQLite database for storing indexed events
 * This is an example implementation - production systems might use PostgreSQL, etc.
 */

import Database from 'better-sqlite3';
import type { IndexedEvent, Trade, Proposal, Reward } from './types';

export class EventDatabase {
  private db: Database.Database;

  constructor(dbPath: string = './events.db') {
    this.db = new Database(dbPath);
    this.initSchema();
  }

  private initSchema(): void {
    // Enable WAL mode for better performance
    this.db.pragma('journal_mode = WAL');

    // Generic events table for all event types
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        contract_id TEXT NOT NULL,
        topic TEXT NOT NULL,
        ledger INTEGER NOT NULL,
        ledger_closed_at TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        event_index INTEGER NOT NULL,
        data TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(tx_hash, event_index)
      );

      CREATE INDEX IF NOT EXISTS idx_events_contract ON events(contract_id);
      CREATE INDEX IF NOT EXISTS idx_events_topic ON events(topic);
      CREATE INDEX IF NOT EXISTS idx_events_ledger ON events(ledger);
    `);

    // Trades table for structured trade data
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS trades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trade_id INTEGER NOT NULL,
        contract_id TEXT NOT NULL,
        trader TEXT NOT NULL,
        pair TEXT NOT NULL,
        amount TEXT NOT NULL,
        price TEXT NOT NULL,
        is_buy INTEGER NOT NULL,
        fee_amount TEXT NOT NULL,
        fee_token TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        ledger INTEGER NOT NULL,
        tx_hash TEXT NOT NULL,
        indexed_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(contract_id, trade_id)
      );

      CREATE INDEX IF NOT EXISTS idx_trades_trader ON trades(trader);
      CREATE INDEX IF NOT EXISTS idx_trades_pair ON trades(pair);
      CREATE INDEX IF NOT EXISTS idx_trades_timestamp ON trades(timestamp);
    `);

    // Proposals table for governance tracking
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS proposals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        proposal_id INTEGER NOT NULL,
        contract_id TEXT NOT NULL,
        proposer TEXT NOT NULL,
        new_contract_hash TEXT NOT NULL,
        target_contract TEXT NOT NULL,
        description TEXT NOT NULL,
        approval_threshold INTEGER NOT NULL,
        current_approvals INTEGER DEFAULT 0,
        timelock_delay INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        executed_at INTEGER,
        ledger INTEGER NOT NULL,
        tx_hash TEXT NOT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(contract_id, proposal_id)
      );

      CREATE INDEX IF NOT EXISTS idx_proposals_status ON proposals(status);
      CREATE INDEX IF NOT EXISTS idx_proposals_proposer ON proposals(proposer);
    `);

    // Rewards table for social rewards tracking
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS rewards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reward_id INTEGER NOT NULL,
        contract_id TEXT NOT NULL,
        user TEXT NOT NULL,
        amount TEXT NOT NULL,
        reward_type TEXT NOT NULL,
        reason TEXT NOT NULL,
        granted_by TEXT NOT NULL,
        granted_at INTEGER NOT NULL,
        claimed INTEGER DEFAULT 0,
        claimed_at INTEGER,
        ledger INTEGER NOT NULL,
        tx_hash TEXT NOT NULL,
        indexed_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(contract_id, reward_id)
      );

      CREATE INDEX IF NOT EXISTS idx_rewards_user ON rewards(user);
      CREATE INDEX IF NOT EXISTS idx_rewards_type ON rewards(reward_type);
      CREATE INDEX IF NOT EXISTS idx_rewards_claimed ON rewards(claimed);
    `);

    // Cursor table for tracking indexing progress
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS cursor (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        last_ledger INTEGER NOT NULL,
        last_cursor TEXT,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      INSERT OR IGNORE INTO cursor (id, last_ledger) VALUES (1, 0);
    `);
  }

  // ==========================================================================
  // Generic Event Storage
  // ==========================================================================

  insertEvent(event: Omit<IndexedEvent, 'id' | 'created_at'>): number {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO events (contract_id, topic, ledger, ledger_closed_at, tx_hash, event_index, data)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      event.contract_id,
      event.topic,
      event.ledger,
      event.ledger_closed_at,
      event.tx_hash,
      event.event_index,
      JSON.stringify(event.data)
    );

    return result.lastInsertRowid as number;
  }

  getEventsByContract(contractId: string, limit = 100): IndexedEvent[] {
    const stmt = this.db.prepare(`
      SELECT * FROM events WHERE contract_id = ? ORDER BY ledger DESC, event_index DESC LIMIT ?
    `);

    const rows = stmt.all(contractId, limit) as any[];
    return rows.map(row => ({
      ...row,
      data: JSON.parse(row.data)
    }));
  }

  getEventsByTopic(topic: string, limit = 100): IndexedEvent[] {
    const stmt = this.db.prepare(`
      SELECT * FROM events WHERE topic = ? ORDER BY ledger DESC, event_index DESC LIMIT ?
    `);

    const rows = stmt.all(topic, limit) as any[];
    return rows.map(row => ({
      ...row,
      data: JSON.parse(row.data)
    }));
  }

  // ==========================================================================
  // Trade Storage
  // ==========================================================================

  insertTrade(trade: Omit<Trade, 'id' | 'indexed_at'>): void {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO trades (
        trade_id, contract_id, trader, pair, amount, price, is_buy,
        fee_amount, fee_token, timestamp, ledger, tx_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      trade.trade_id.toString(),
      trade.contract_id,
      trade.trader,
      trade.pair,
      trade.amount.toString(),
      trade.price.toString(),
      trade.is_buy ? 1 : 0,
      trade.fee_amount.toString(),
      trade.fee_token,
      Number(trade.timestamp),
      trade.ledger,
      trade.tx_hash
    );
  }

  getTradesByTrader(trader: string, limit = 100): Trade[] {
    const stmt = this.db.prepare(`
      SELECT * FROM trades WHERE trader = ? ORDER BY timestamp DESC LIMIT ?
    `);
    return stmt.all(trader, limit) as Trade[];
  }

  getTradesByPair(pair: string, limit = 100): Trade[] {
    const stmt = this.db.prepare(`
      SELECT * FROM trades WHERE pair = ? ORDER BY timestamp DESC LIMIT ?
    `);
    return stmt.all(pair, limit) as Trade[];
  }

  getTradeVolume(pair: string, since: number): { buy_volume: string; sell_volume: string } {
    const stmt = this.db.prepare(`
      SELECT
        COALESCE(SUM(CASE WHEN is_buy = 1 THEN CAST(amount AS INTEGER) ELSE 0 END), 0) as buy_volume,
        COALESCE(SUM(CASE WHEN is_buy = 0 THEN CAST(amount AS INTEGER) ELSE 0 END), 0) as sell_volume
      FROM trades
      WHERE pair = ? AND timestamp >= ?
    `);
    return stmt.get(pair, since) as { buy_volume: string; sell_volume: string };
  }

  // ==========================================================================
  // Proposal Storage
  // ==========================================================================

  insertProposal(proposal: Omit<Proposal, 'id' | 'updated_at'> & { ledger: number; tx_hash: string }): void {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO proposals (
        proposal_id, contract_id, proposer, new_contract_hash, target_contract,
        description, approval_threshold, timelock_delay, status, created_at, ledger, tx_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      proposal.proposal_id.toString(),
      proposal.contract_id,
      proposal.proposer,
      proposal.new_contract_hash,
      proposal.target_contract,
      proposal.description,
      proposal.approval_threshold,
      Number(proposal.timelock_delay),
      proposal.status,
      Number(proposal.created_at),
      proposal.ledger,
      proposal.tx_hash
    );
  }

  updateProposalStatus(contractId: string, proposalId: bigint, status: string): void {
    const stmt = this.db.prepare(`
      UPDATE proposals SET status = ?, updated_at = CURRENT_TIMESTAMP
      WHERE contract_id = ? AND proposal_id = ?
    `);
    stmt.run(status, contractId, proposalId.toString());
  }

  updateProposalApprovals(contractId: string, proposalId: bigint, approvals: number): void {
    const stmt = this.db.prepare(`
      UPDATE proposals SET current_approvals = ?, updated_at = CURRENT_TIMESTAMP
      WHERE contract_id = ? AND proposal_id = ?
    `);
    stmt.run(approvals, contractId, proposalId.toString());
  }

  getActiveProposals(contractId: string): Proposal[] {
    const stmt = this.db.prepare(`
      SELECT * FROM proposals WHERE contract_id = ? AND status IN ('pending', 'approved')
      ORDER BY created_at DESC
    `);
    return stmt.all(contractId) as Proposal[];
  }

  // ==========================================================================
  // Reward Storage
  // ==========================================================================

  insertReward(reward: Omit<Reward, 'id' | 'indexed_at'>): void {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO rewards (
        reward_id, contract_id, user, amount, reward_type, reason,
        granted_by, granted_at, claimed, claimed_at, ledger, tx_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      reward.reward_id.toString(),
      reward.contract_id,
      reward.user,
      reward.amount.toString(),
      reward.reward_type,
      reward.reason,
      reward.granted_by,
      Number(reward.granted_at),
      reward.claimed ? 1 : 0,
      reward.claimed_at ? Number(reward.claimed_at) : null,
      reward.ledger,
      reward.tx_hash
    );
  }

  markRewardClaimed(contractId: string, rewardId: bigint, claimedAt: bigint): void {
    const stmt = this.db.prepare(`
      UPDATE rewards SET claimed = 1, claimed_at = ?
      WHERE contract_id = ? AND reward_id = ?
    `);
    stmt.run(Number(claimedAt), contractId, rewardId.toString());
  }

  getPendingRewards(user: string): Reward[] {
    const stmt = this.db.prepare(`
      SELECT * FROM rewards WHERE user = ? AND claimed = 0 ORDER BY granted_at DESC
    `);
    return stmt.all(user) as Reward[];
  }

  getUserRewardStats(user: string): { total_earned: string; total_claimed: string; pending: string } {
    const stmt = this.db.prepare(`
      SELECT
        COALESCE(SUM(CAST(amount AS INTEGER)), 0) as total_earned,
        COALESCE(SUM(CASE WHEN claimed = 1 THEN CAST(amount AS INTEGER) ELSE 0 END), 0) as total_claimed,
        COALESCE(SUM(CASE WHEN claimed = 0 THEN CAST(amount AS INTEGER) ELSE 0 END), 0) as pending
      FROM rewards WHERE user = ?
    `);
    return stmt.get(user) as { total_earned: string; total_claimed: string; pending: string };
  }

  // ==========================================================================
  // Cursor Management
  // ==========================================================================

  getCursor(): { last_ledger: number; last_cursor: string | null } {
    const stmt = this.db.prepare('SELECT last_ledger, last_cursor FROM cursor WHERE id = 1');
    return stmt.get() as { last_ledger: number; last_cursor: string | null };
  }

  updateCursor(ledger: number, cursor?: string): void {
    const stmt = this.db.prepare(`
      UPDATE cursor SET last_ledger = ?, last_cursor = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1
    `);
    stmt.run(ledger, cursor || null);
  }

  close(): void {
    this.db.close();
  }
}
