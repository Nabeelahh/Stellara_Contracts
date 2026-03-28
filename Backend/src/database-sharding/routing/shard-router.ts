import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ConsistentHashRing,
  ShardNode,
  ShardingStrategy,
  ShardKeyGenerator,
} from '../hashing/consistent-hash';

/**
 * Shard Router Configuration
 */
export interface ShardRouterConfig {
  strategy: ShardingStrategy;
  defaultShard: ShardNode;
  shards: ShardNode[];
  crossShardQueries: boolean;
  replicationFactor?: number;
}

/**
 * Query Context for Routing
 */
export interface QueryContext {
  tenantId?: string;
  userId?: string;
  region?: string;
  entityId?: string;
  preferReadReplica?: boolean;
}

/**
 * Shard Router
 * 
 * Routes database queries to the appropriate shard based on
 * the configured sharding strategy.
 */
@Injectable()
export class ShardRouter {
  private readonly logger = new Logger(ShardRouter.name);
  private hashRing: ConsistentHashRing;
  private config: ShardRouterConfig;
  private connections: Map<string, any> = new Map(); // Shard ID -> Connection

  constructor(private readonly configService: ConfigService) {
    this.hashRing = new ConsistentHashRing();
  }

  /**
   * Initialize the router with configuration
   */
  initialize(config: ShardRouterConfig): void {
    this.config = config;

    // Add all shards to the hash ring
    for (const shard of config.shards) {
      this.hashRing.addShard(shard);
      this.logger.log(`Added shard ${shard.id} to routing ring`);
    }

    this.logger.log(
      `Shard router initialized with ${config.shards.length} shards using ${config.strategy} strategy`
    );
  }

  /**
   * Route a query to the appropriate shard
   */
  route(context: QueryContext): ShardNode {
    const shardKey = this.generateShardKey(context);
    const shard = this.hashRing.getShard(shardKey);

    this.logger.debug(`Routed query to shard ${shard.id} using key ${shardKey}`);
    
    return shard;
  }

  /**
   * Get shard ID for a context
   */
  getShardId(context: QueryContext): string {
    const shardKey = this.generateShardKey(context);
    return this.hashRing.getShardId(shardKey);
  }

  /**
   * Route multiple keys and return shard mapping
   */
  routeBatch(contexts: QueryContext[]): Map<string, QueryContext[]> {
    const shardMapping = new Map<string, QueryContext[]>();

    for (const context of contexts) {
      const shardId = this.getShardId(context);
      const contextsForShard = shardMapping.get(shardId) || [];
      contextsForShard.push(context);
      shardMapping.set(shardId, contextsForShard);
    }

    return shardMapping;
  }

  /**
   * Get all shards (for cross-shard queries)
   */
  getAllShards(): ShardNode[] {
    return this.hashRing.getAllShards();
  }

  /**
   * Add a new shard dynamically
   */
  addShard(shard: ShardNode): void {
    // Get migration plan before adding
    const migrationPlan = this.hashRing.getMigrationPlan(shard);
    
    this.hashRing.addShard(shard);
    
    this.logger.log(
      `Added new shard ${shard.id}. Migration plan: ${migrationPlan.size} keys to migrate`
    );
  }

  /**
   * Remove a shard (for maintenance or decommissioning)
   */
  removeShard(shardId: string): void {
    this.hashRing.removeShard(shardId);
    this.logger.log(`Removed shard ${shardId}`);
  }

  /**
   * Get shard statistics
   */
  getStats(): {
    shardCount: number;
    virtualNodeCount: number;
    distribution: Record<string, number>;
  } {
    const distribution = this.hashRing.getDistributionStats();
    const distributionRecord: Record<string, number> = {};
    
    for (const [shardId, count] of distribution) {
      distributionRecord[shardId] = count;
    }

    return {
      shardCount: this.hashRing.getShardCount(),
      virtualNodeCount: this.hashRing.getVirtualNodeCount(),
      distribution: distributionRecord,
    };
  }

  /**
   * Check if a query requires cross-shard execution
   */
  isCrossShard(contexts: QueryContext[]): boolean {
    if (contexts.length <= 1) return false;

    const firstShardId = this.getShardId(contexts[0]);
    
    for (let i = 1; i < contexts.length; i++) {
      if (this.getShardId(contexts[i]) !== firstShardId) {
        return true;
      }
    }

    return false;
  }

  /**
   * Generate shard key from context
   */
  private generateShardKey(context: QueryContext): string {
    return ShardKeyGenerator.generate(this.config.strategy, {
      tenantId: context.tenantId,
      userId: context.userId,
      region: context.region,
      entityId: context.entityId,
    });
  }

  /**
   * Get connection for a shard
   */
  getConnection(shardId: string): any {
    const connection = this.connections.get(shardId);
    if (!connection) {
      throw new Error(`No connection found for shard ${shardId}`);
    }
    return connection;
  }

  /**
   * Register a connection for a shard
   */
  registerConnection(shardId: string, connection: any): void {
    this.connections.set(shardId, connection);
  }
}

/**
 * Cross-Shard Query Coordinator
 * 
 * Handles queries that span multiple shards
 */
@Injectable()
export class CrossShardQueryCoordinator {
  private readonly logger = new Logger(CrossShardQueryCoordinator.name);

  constructor(private readonly shardRouter: ShardRouter) {}

  /**
   * Execute a query across multiple shards and aggregate results
   */
  async executeCrossShardQuery<T>(
    contexts: QueryContext[],
    queryFn: (shard: ShardNode, contexts: QueryContext[]) => Promise<T[]>,
    options: {
      orderBy?: string;
      orderDirection?: 'asc' | 'desc';
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<T[]> {
    if (!this.shardRouter.isCrossShard(contexts)) {
      // Single shard query - route normally
      const shard = this.shardRouter.route(contexts[0]);
      return queryFn(shard, contexts);
    }

    // Group contexts by shard
    const shardMapping = this.shardRouter.routeBatch(contexts);
    
    this.logger.debug(
      `Executing cross-shard query across ${shardMapping.size} shards`
    );

    // Execute queries in parallel
    const promises: Promise<T[]>[] = [];
    
    for (const [shardId, shardContexts] of shardMapping) {
      const shard = this.shardRouter
        .getAllShards()
        .find(s => s.id === shardId);
      
      if (shard) {
        promises.push(queryFn(shard, shardContexts));
      }
    }

    // Wait for all queries to complete
    const results = await Promise.all(promises);
    
    // Flatten and sort results
    let allResults = results.flat();

    // Apply sorting if specified
    if (options.orderBy) {
      allResults = this.sortResults(
        allResults,
        options.orderBy,
        options.orderDirection || 'asc'
      );
    }

    // Apply pagination
    if (options.offset) {
      allResults = allResults.slice(options.offset);
    }
    
    if (options.limit) {
      allResults = allResults.slice(0, options.limit);
    }

    return allResults;
  }

  /**
   * Execute an aggregation query across shards
   */
  async executeCrossShardAggregation<T>(
    aggregationType: 'count' | 'sum' | 'avg' | 'max' | 'min',
    field: string,
    contexts: QueryContext[],
    queryFn: (shard: ShardNode) => Promise<T[]>
  ): Promise<number> {
    const allShards = this.shardRouter.getAllShards();
    
    const promises = allShards.map(shard => queryFn(shard));
    const results = await Promise.all(promises);
    
    const allValues = results.flat();

    switch (aggregationType) {
      case 'count':
        return allValues.length;
      
      case 'sum':
        return allValues.reduce((sum, v) => sum + (v[field] || 0), 0);
      
      case 'avg':
        return allValues.length > 0
          ? allValues.reduce((sum, v) => sum + (v[field] || 0), 0) / allValues.length
          : 0;
      
      case 'max':
        return Math.max(...allValues.map(v => v[field] || 0));
      
      case 'min':
        return Math.min(...allValues.map(v => v[field] || 0));
      
      default:
        throw new Error(`Unknown aggregation type: ${aggregationType}`);
    }
  }

  /**
   * Sort results by a field
   */
  private sortResults<T>(
    results: T[],
    field: string,
    direction: 'asc' | 'desc'
  ): T[] {
    return results.sort((a, b) => {
      const aVal = a[field];
      const bVal = b[field];
      
      if (aVal < bVal) return direction === 'asc' ? -1 : 1;
      if (aVal > bVal) return direction === 'asc' ? 1 : -1;
      return 0;
    });
  }
}
