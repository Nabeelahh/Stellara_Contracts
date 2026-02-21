# 🏥 Production-Grade Health Monitoring System

## 🎯 Overview

This document describes the implementation of a production-grade health monitoring system for the Stellara backend that enables Kubernetes and other container orchestrators to accurately determine service liveness, readiness, and overall operational integrity.

## 🏗️ System Architecture

### Core Components

1. **Health Module** (`src/health/health.module.ts`)
   - Main module that registers health controllers and services
   - Integrates with the existing NestJS application

2. **Health Controller** (`src/health/health.controller.ts`)
   - Provides REST endpoints for health checks
   - Handles liveness, readiness, and detailed health queries

3. **Health Service** (`src/health/health.service.ts`)
   - Core business logic for health assessment
   - Coordinates multiple health indicators

4. **Health Indicators** (`src/health/indicators/`)
   - Database Health Indicator
   - Redis Health Indicator
   - Queue Health Indicator
   - System Health Indicator

5. **DTOs** (`src/health/dto/`)
   - Health response data structures
   - Swagger documentation integration

## 🚀 Endpoints

### 1. Liveness Probe
```
GET /health/live
```

**Purpose**: Determines if the application process is alive
**Used by**: Kubernetes for restart decisions
**Response Codes**: 
- `200 OK` - Application is running
- `503 Service Unavailable` - Application is not running

**Sample Response**:
```json
{
  "status": "ok",
  "timestamp": "2026-01-01T10:30:00.000Z",
  "version": "1.0.0",
  "environment": "production"
}
```

### 2. Readiness Probe
```
GET /health/ready
```

**Purpose**: Determines if the application is ready to serve traffic
**Used by**: Kubernetes for traffic routing decisions
**Response Codes**:
- `200 OK` - Ready to serve traffic
- `503 Service Unavailable` - Not ready to serve traffic

**Sample Response**:
```json
{
  "status": "ok",
  "timestamp": "2026-01-01T10:30:00.000Z",
  "version": "1.0.0",
  "environment": "production",
  "checks": [
    { "name": "database", "status": "up" },
    { "name": "redis", "status": "up" },
    { "name": "process", "status": "up" }
  ]
}
```

### 3. Detailed Health Check
```
GET /health
```

**Purpose**: Comprehensive system health information
**Used by**: Monitoring dashboards and debugging
**Response Codes**: `200 OK`

**Sample Response**:
```json
{
  "status": "healthy",
  "timestamp": "2026-01-01T10:30:00.000Z",
  "version": "1.0.0",
  "environment": "production",
  "uptime": 3600,
  "checks": [
    {
      "name": "database",
      "status": "up",
      "message": "Database connection established",
      "details": {
        "latency": 5,
        "connections": 10
      }
    },
    {
      "name": "redis",
      "status": "up",
      "message": "Redis cache available",
      "details": {
        "latency": 2,
        "memoryUsage": "45%",
        "keyCount": 1250
      }
    },
    {
      "name": "queue",
      "status": "up",
      "message": "Queue system operational",
      "details": {
        "activeJobs": 3,
        "pendingJobs": 15,
        "failedJobs": 0
      }
    },
    {
      "name": "system",
      "status": "up",
      "message": "System resources healthy",
      "details": {
        "cpuUsage": "23%",
        "memoryUsage": "67%"
      }
    }
  ],
  "summary": {
    "total": 4,
    "healthy": 4,
    "degraded": 0,
    "unhealthy": 0
  }
}
```

## 🛠️ Implementation Details

### Health Status Definitions

- **`up`**: Component is functioning normally
- **`degraded`**: Component is functioning but with performance issues
- **`down`**: Component is not functioning
- **`unknown`**: Component status cannot be determined

### Health Check Categories

#### 1. Liveness Checks (Minimal)
- Application process status
- Basic system resources

#### 2. Readiness Checks (Critical Dependencies)
- Database connectivity
- Redis cache availability
- Queue system status
- Essential service dependencies

#### 3. Detailed Checks (Comprehensive)
- All readiness checks plus:
- Performance metrics
- Resource utilization
- Queue depth and processing rates
- Error rates and statistics

### Health Indicator Implementations

#### Database Health Indicator
```typescript
// Checks:
// - Connection status
// - Query latency
// - Connection pool utilization
// - Migration status
// - Active connections count
```

#### Redis Health Indicator
```typescript
// Checks:
// - Connection status
// - Ping latency
// - Memory usage
// - Key count
// - Connected clients
```

#### Queue Health Indicator
```typescript
// Checks:
// - Queue connection status
// - Active job count
// - Waiting job count
// - Failed job count
// - Processing latency
```

#### System Health Indicator
```typescript
// Checks:
// - CPU usage
// - Memory usage
// - Disk space
// - Process uptime
// - Garbage collection stats
```

## 🐳 Kubernetes Integration

### Deployment Configuration

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stellara-backend
spec:
  template:
    spec:
      containers:
      - name: backend
        image: stellara/backend:latest
        ports:
        - containerPort: 3000
        livenessProbe:
          httpGet:
            path: /health/live
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
```

### Probe Configuration Guidelines

#### Liveness Probe
- **Initial Delay**: 30 seconds (allow app startup)
- **Period**: 10 seconds (frequent checks)
- **Timeout**: 5 seconds (quick failure detection)
- **Failure Threshold**: 3 (tolerate temporary issues)

#### Readiness Probe
- **Initial Delay**: 10 seconds (app should be ready quickly)
- **Period**: 5 seconds (responsive traffic routing)
- **Timeout**: 3 seconds (fast response required)
- **Failure Threshold**: 3 (avoid flapping)

## 📊 Monitoring & Alerting

### Prometheus Integration

The health system exposes metrics compatible with Prometheus:

```typescript
// Health metrics exposed via /metrics endpoint
http_requests_total{endpoint="/health/live", status="200"}
http_request_duration_seconds{endpoint="/health/ready"}
health_status{component="database", status="up"}
health_status{component="redis", status="degraded"}
```

### Alert Rules Examples

```yaml
# Critical alerts
- alert: BackendDown
  expr: up{job="stellara-backend"} == 0
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "Backend service is down"

- alert: DatabaseUnhealthy
  expr: health_status{component="database", status="down"} == 1
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "Database connection is unhealthy"

# Warning alerts
- alert: HighLatency
  expr: health_latency_seconds > 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Health check latency is high"
```

## 🔧 Configuration Options

### Environment Variables

```bash
# Health check timeouts
HEALTH_CHECK_TIMEOUT_MS=5000
HEALTH_CHECK_RETRIES=3

# Component-specific thresholds
DATABASE_LATENCY_THRESHOLD_MS=1000
REDIS_LATENCY_THRESHOLD_MS=500
QUEUE_WAITING_THRESHOLD=1000
CPU_USAGE_THRESHOLD=90
MEMORY_USAGE_THRESHOLD=90
```

### Custom Health Checks

```typescript
// Add custom health indicator
@Injectable()
export class CustomHealthIndicator {
  async isHealthy(): Promise<HealthIndicatorResult> {
    // Custom health logic
    return {
      name: 'custom-service',
      status: 'up',
      message: 'Custom service is healthy',
      details: { customMetric: 42 }
    };
  }
}

// Register in HealthModule
@Module({
  providers: [
    HealthService,
    CustomHealthIndicator,
    // ... other indicators
  ]
})
```

## 🧪 Testing Strategy

### Unit Tests
```typescript
describe('HealthService', () => {
  let service: HealthService;
  
  it('should return healthy status for liveness check', async () => {
    const result = await service.checkLiveness();
    expect(result.status).toBe('healthy');
  });
  
  it('should detect degraded components', async () => {
    const result = await service.checkDetailed();
    expect(result.summary.degraded).toBe(0);
  });
});
```

### Integration Tests
```typescript
describe('HealthController', () => {
  it('GET /health/live should return 200', async () => {
    const response = await request(app.getHttpServer())
      .get('/health/live')
      .expect(200);
      
    expect(response.body.status).toBe('ok');
  });
});
```

### Load Testing
```bash
# Test health endpoint performance
ab -n 1000 -c 10 http://localhost:3000/health
```

## 🚨 Troubleshooting

### Common Issues

1. **Probe Failures During Startup**
   - Increase `initialDelaySeconds`
   - Check application startup time
   - Review logs for initialization errors

2. **Flapping Readiness Probes**
   - Increase `failureThreshold`
   - Add jitter to health checks
   - Review dependency connection stability

3. **High Latency Health Checks**
   - Optimize database queries
   - Reduce external dependency calls
   - Implement caching for expensive checks

### Debugging Commands

```bash
# Check current health status
curl http://localhost:3000/health

# Check liveness specifically
curl http://localhost:3000/health/live

# Check readiness specifically
curl http://localhost:3000/health/ready

# Monitor probe behavior
kubectl describe pod <pod-name>
kubectl logs <pod-name> --previous
```

## 📈 Performance Considerations

### Health Check Optimization

1. **Caching Results**: Cache expensive health checks for 1-2 seconds
2. **Parallel Execution**: Run independent checks concurrently
3. **Early Termination**: Fail fast on critical dependency failures
4. **Minimal Overhead**: Keep liveness checks lightweight

### Resource Usage

- **Memory**: ~10-50MB additional for health monitoring
- **CPU**: Minimal impact (<1% CPU for periodic checks)
- **Network**: Negligible external calls for internal checks

## 🔄 Future Enhancements

### Planned Features

1. **Circuit Breaker Integration**
   - Automatically mark degraded services
   - Prevent cascading failures

2. **Adaptive Thresholds**
   - Machine learning based anomaly detection
   - Dynamic threshold adjustment based on load

3. **Multi-Region Health Checks**
   - Cross-region dependency monitoring
   - Global service health visualization

4. **Health History Tracking**
   - Trend analysis and predictive maintenance
   - Uptime SLA reporting

5. **Automated Remediation**
   - Self-healing capabilities
   - Automated failover mechanisms

## 📚 References

- [Kubernetes Liveness and Readiness Probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
- [NestJS Health Checks](https://docs.nestjs.com/recipes/healthchecks)
- [Prometheus Monitoring](https://prometheus.io/docs/practices/instrumentation/)
- [Google SRE Workbook - Health Checking](https://sre.google/workbook/health-checking/)

---
*This health monitoring system provides production-grade observability for the Stellara platform, ensuring reliable service operation and facilitating automated operations in containerized environments.*