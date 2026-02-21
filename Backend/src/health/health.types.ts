export type HealthStatus = 'up' | 'down' | 'degraded' | 'unknown';
export type HealthCheckStatus = 'healthy' | 'unhealthy' | 'degraded';

export interface HealthIndicatorResult {
  name: string;
  status: HealthStatus;
  message?: string;
  details?: Record<string, any>;
  timestamp?: string;
}

export interface HealthCheckResult {
  status: HealthCheckStatus;
  timestamp: string;
  version: string;
  environment: string;
  uptime: number;
  checks: HealthIndicatorResult[];
  summary?: {
    total: number;
    healthy: number;
    degraded: number;
    unhealthy: number;
  };
}

export interface DatabaseHealthDetails {
  connection: boolean;
  latency: number;
  migrations: boolean;
  pool: {
    used: number;
    free: number;
    pending: number;
  };
}

export interface RedisHealthDetails {
  connection: boolean;
  latency: number;
  memory: {
    used: number;
    max: number;
    percentage: number;
  };
  keys: number;
}

export interface QueueHealthDetails {
  connection: boolean;
  latency: number;
  queues: Array<{
    name: string;
    active: number;
    waiting: number;
    failed: number;
    status: HealthStatus;
  }>;
}

export interface SystemHealthDetails {
  cpu: {
    usage: number;
    count: number;
  };
  memory: {
    used: number;
    total: number;
    percentage: number;
  };
  disk: {
    used: number;
    total: number;
    percentage: number;
  };
  process: {
    uptime: number;
    memory: NodeJS.MemoryUsage;
  };
}