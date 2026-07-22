import { Module } from '@nestjs/common';
import { LoggingService } from './services/logging.service';
import { TracingService } from './services/tracing.service';
import { MetricsService } from './services/metrics.service';
import { TracingInterceptor } from './interceptors/tracing.interceptor';
import { WebSocketTracingAdapter } from './middleware/websocket-tracing.adapter';
import { QueueJobTracingWrapper } from './middleware/queue-job-tracing.wrapper';
import { CorrelationMiddleware } from './middleware/correlation.middleware';
import { MetricsController } from './controllers/metrics.controller';

/**
 * Observability Module
 * Provides comprehensive logging, tracing, and metrics for the application.
 *
 * Features:
 * - Structured logging with Winston
 * - Distributed tracing with trace ID propagation (Jaeger-compatible)
 * - Correlation ID propagation across HTTP, WebSocket, queue, and DB layers
 * - Prometheus metrics collection with correlation-aware counters
 * - Integration with HTTP, WebSocket, and queue workers
 */
@Module({
  controllers: [MetricsController],
  providers: [
    LoggingService,
    TracingService,
    MetricsService,
    TracingInterceptor,
    WebSocketTracingAdapter,
    QueueJobTracingWrapper,
    CorrelationMiddleware,
  ],
  exports: [
    LoggingService,
    TracingService,
    MetricsService,
    TracingInterceptor,
    WebSocketTracingAdapter,
    QueueJobTracingWrapper,
    CorrelationMiddleware,
  ],
})
export class ObservabilityModule {}
