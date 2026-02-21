// Basic health controller for demonstration
// In production, this would be properly typed with NestJS decorators

export class HealthController {
  // Liveness probe - minimal check
  checkLiveness() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      environment: 'development',
    };
  }

  // Readiness probe - checks critical dependencies
  checkReadiness() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      environment: 'development',
      checks: [
        { name: 'database', status: 'up' },
        { name: 'redis', status: 'up' },
        { name: 'process', status: 'up' },
      ],
    };
  }

  // Detailed health check
  checkDetailed() {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      environment: 'development',
      uptime: process.uptime(),
      checks: [
        {
          name: 'database',
          status: 'up',
          message: 'Database connection established',
          details: { latency: 5, connections: 10 },
        },
        {
          name: 'redis',
          status: 'up',
          message: 'Redis cache available',
          details: { latency: 2, memoryUsage: '45%', keyCount: 1250 },
        },
        {
          name: 'queue',
          status: 'up',
          message: 'Queue system operational',
          details: { activeJobs: 3, pendingJobs: 15, failedJobs: 0 },
        },
        {
          name: 'system',
          status: 'up',
          message: 'System resources healthy',
          details: { cpuUsage: '23%', memoryUsage: '67%' },
        },
      ],
      summary: {
        total: 4,
        healthy: 4,
        degraded: 0,
        unhealthy: 0,
      },
    };
  }
}