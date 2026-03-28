/**
 * Consistent Hashing Implementation for Database Sharding
 * 
 * Uses virtual nodes to ensure even distribution of keys across shards
 * and minimize rebalancing when shards are added/removed.
 */

export interface ShardNode {
  id: string;
  host: string;
  port: number;
  database: string;
  weight: number; // For weighted distribution
  region?: string;
}

export interface VirtualNode {
  hash: number;
  shardId: string;
}

export class ConsistentHashRing {
  private virtualNodes: VirtualNode[] = [];
  private shards: Map<string, ShardNode> = new Map();
  private readonly virtualNodesPerShard: number;
  private readonly hashFunction: (key: string) => number;

  constructor(
    virtualNodesPerShard: number = 150,
    hashFunction?: (key: string) => number
  ) {
    this.virtualNodesPerShard = virtualNodesPerShard;
    this.hashFunction = hashFunction || this.defaultHash;
  }

  /**
   * Add a shard to the ring
   */
  addShard(shard: ShardNode): void {
    if (this.shards.has(shard.id)) {
      throw new Error(`Shard ${shard.id} already exists`);
    }

    this.shards.set(shard.id, shard);

    // Create virtual nodes for this shard
    const virtualNodeCount = Math.floor(
      this.virtualNodesPerShard * shard.weight
    );

    for (let i = 0; i < virtualNodeCount; i++) {
      const hash = this.hashFunction(`${shard.id}:${i}`);
      this.virtualNodes.push({ hash, shardId: shard.id });
    }

    // Sort virtual nodes by hash for binary search
    this.virtualNodes.sort((a, b) => a.hash - b.hash);
  }

  /**
   * Remove a shard from the ring
   */
  removeShard(shardId: string): void {
    if (!this.shards.has(shardId)) {
      throw new Error(`Shard ${shardId} does not exist`);
    }

    this.shards.delete(shardId);
    this.virtualNodes = this.virtualNodes.filter(
      node => node.shardId !== shardId
    );
  }

  /**
   * Get the shard for a given key
   */
  getShard(key: string): ShardNode {
    if (this.virtualNodes.length === 0) {
      throw new Error('No shards available in the ring');
    }

    const hash = this.hashFunction(key);
    const shardId = this.findShardForHash(hash);
    const shard = this.shards.get(shardId);

    if (!shard) {
      throw new Error(`Shard ${shardId} not found`);
    }

    return shard;
  }

  /**
   * Get shard ID for a key (without full shard info)
   */
  getShardId(key: string): string {
    if (this.virtualNodes.length === 0) {
      throw new Error('No shards available in the ring');
    }

    const hash = this.hashFunction(key);
    return this.findShardForHash(hash);
  }

  /**
   * Get all shards
   */
  getAllShards(): ShardNode[] {
    return Array.from(this.shards.values());
  }

  /**
   * Get shard count
   */
  getShardCount(): number {
    return this.shards.size;
  }

  /**
   * Get virtual node count
   */
  getVirtualNodeCount(): number {
    return this.virtualNodes.length;
  }

  /**
   * Get the distribution statistics
   */
  getDistributionStats(): Map<string, number> {
    const stats = new Map<string, number>();
    
    for (const node of this.virtualNodes) {
      const count = stats.get(node.shardId) || 0;
      stats.set(node.shardId, count + 1);
    }

    return stats;
  }

  /**
   * Find which keys need to be migrated when adding a new shard
   */
  getMigrationPlan(newShard: ShardNode): Map<string, string> {
    const plan = new Map<string, string>();
    const tempRing = new ConsistentHashRing(
      this.virtualNodesPerShard,
      this.hashFunction
    );

    // Copy existing shards
    for (const shard of this.shards.values()) {
      tempRing.addShard(shard);
    }

    // Add new shard
    tempRing.addShard(newShard);

    // Find all virtual nodes that moved to the new shard
    for (const node of this.virtualNodes) {
      const newShardId = tempRing.findShardForHash(node.hash);
      if (newShardId === newShard.id && node.shardId !== newShard.id) {
        // This virtual node moved to the new shard
        plan.set(node.hash.toString(), newShard.id);
      }
    }

    return plan;
  }

  /**
   * Binary search to find the shard for a given hash
   */
  private findShardForHash(hash: number): string {
    let left = 0;
    let right = this.virtualNodes.length - 1;

    // Edge case: hash is greater than all virtual nodes
    if (hash > this.virtualNodes[right].hash) {
      return this.virtualNodes[0].shardId;
    }

    while (left < right) {
      const mid = Math.floor((left + right) / 2);
      
      if (this.virtualNodes[mid].hash < hash) {
        left = mid + 1;
      } else {
        right = mid;
      }
    }

    return this.virtualNodes[left].shardId;
  }

  /**
   * Default hash function (MurmurHash3-inspired)
   */
  private defaultHash(key: string): number {
    let h = 1779033703 ^ key.length;
    
    for (let i = 0; i < key.length; i++) {
      h = Math.imul(h ^ key.charCodeAt(i), 3432918353);
      h = (h << 13) | (h >>> 19);
    }

    h = Math.imul(h ^ (h >>> 16), 2246822507);
    h = Math.imul(h ^ (h >>> 13), 3266489909);
    h ^= h >>> 16;

    // Ensure positive 32-bit integer
    return h >>> 0;
  }
}

/**
 * Sharding Strategy Types
 */
export enum ShardingStrategy {
  TENANT = 'tenant',      // Shard by tenant ID
  USER = 'user',          // Shard by user ID
  GEOGRAPHIC = 'geo',     // Shard by geographic region
  HASH = 'hash',          // Shard by hash of key
  RANGE = 'range',        // Shard by range of key
}

/**
 * Shard Key Generator
 */
export class ShardKeyGenerator {
  /**
   * Generate shard key based on strategy
   */
  static generate(
    strategy: ShardingStrategy,
    data: {
      tenantId?: string;
      userId?: string;
      region?: string;
      entityId?: string;
    }
  ): string {
    switch (strategy) {
      case ShardingStrategy.TENANT:
        if (!data.tenantId) throw new Error('tenantId required for tenant sharding');
        return `tenant:${data.tenantId}`;
      
      case ShardingStrategy.USER:
        if (!data.userId) throw new Error('userId required for user sharding');
        return `user:${data.userId}`;
      
      case ShardingStrategy.GEOGRAPHIC:
        if (!data.region) throw new Error('region required for geographic sharding');
        return `geo:${data.region}`;
      
      case ShardingStrategy.HASH:
        if (!data.entityId) throw new Error('entityId required for hash sharding');
        return `hash:${data.entityId}`;
      
      default:
        throw new Error(`Unknown sharding strategy: ${strategy}`);
    }
  }
}
