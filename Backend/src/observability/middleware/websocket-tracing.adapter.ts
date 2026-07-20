import { Injectable } from '@nestjs/common';
import { Socket } from 'socket.io';
import { TracingService } from '../services/tracing.service';
import { LoggingService } from '../services/logging.service';
import { MetricsService } from '../services/metrics.service';
import { TraceContext } from '../types/trace-context.interface';

/**
 * WebSocket Tracing Adapter
 * Manages trace context for WebSocket connections and messages.
 * Propagates the correlation ID (X-Request-ID) across the WebSocket layer
 * so that a request that starts as HTTP can continue through WS events
 * with the same identifier.
 */
@Injectable()
export class WebSocketTracingAdapter {
  private socketTraceMap = new Map<string, TraceContext>();

  constructor(
    private tracingService: TracingService,
    private loggingService: LoggingService,
    private metricsService: MetricsService,
  ) {}

  /**
   * Initialize tracing for WebSocket connection
   */
  initializeConnection(socket: Socket, namespace: string): TraceContext {
    const handshakeHeaders = socket.handshake.headers;
    const traceContext = this.tracingService.extractTraceContext(
      handshakeHeaders as Record<string, string>,
    );

    // Reuse existing correlation ID or generate a new one
    const correlationId =
      (socket.handshake.query?.correlationId as string) ||
      (socket.handshake.query?.['x-request-id'] as string) ||
      (handshakeHeaders['x-request-id'] as string) ||
      this.metricsService.generateCorrelationId();

    this.tracingService.addMetadata(traceContext.traceId, { correlationId });

    this.socketTraceMap.set(socket.id, traceContext);

    (socket as any).traceContext = traceContext;
    (socket as any).correlationId = correlationId;

    this.metricsService.recordWebSocketConnection(namespace, correlationId);

    this.loggingService.info('WebSocket connection established', {
      traceId: traceContext.traceId,
      spanId: traceContext.spanId,
      correlationId,
      socketId: socket.id,
      namespace,
      userId: traceContext.userId,
      remoteAddress: socket.handshake.address,
      userAgent: socket.handshake.headers['user-agent'],
    });

    return traceContext;
  }

  /**
   * Handle WebSocket disconnection
   */
  handleDisconnection(socketId: string, namespace: string, reason: string) {
    const traceContext = this.socketTraceMap.get(socketId);

    if (traceContext) {
      const correlationId =
        (traceContext.metadata?.['correlationId'] as string) || '';

      this.metricsService.recordWebSocketDisconnection(
        namespace,
        reason,
        correlationId,
      );

      this.loggingService.info('WebSocket connection closed', {
        traceId: traceContext.traceId,
        spanId: traceContext.spanId,
        correlationId,
        socketId,
        namespace,
        reason,
        userId: traceContext.userId,
      });

      this.socketTraceMap.delete(socketId);
    }
  }

  /**
   * Record WebSocket message with tracing
   */
  recordMessage(
    socketId: string,
    namespace: string,
    eventType: string,
    messageSize: number = 0,
  ) {
    const traceContext = this.socketTraceMap.get(socketId);

    if (traceContext) {
      const correlationId =
        (traceContext.metadata?.['correlationId'] as string) || '';

      this.metricsService.recordWebSocketMessage(
        namespace,
        eventType,
        correlationId,
      );

      this.loggingService.debug('WebSocket message', {
        traceId: traceContext.traceId,
        spanId: traceContext.spanId,
        correlationId,
        socketId,
        namespace,
        eventType,
        messageSize,
        userId: traceContext.userId,
      });
    }
  }

  /**
   * Inject trace context into WebSocket message
   */
  injectTraceContext(socketId: string): Record<string, string> {
    const traceContext = this.socketTraceMap.get(socketId);
    if (!traceContext) {
      return {};
    }
    const headers = this.tracingService.injectTraceContext(traceContext);
    return headers as unknown as Record<string, string>;
  }

  /**
   * Get trace context for socket
   */
  getTraceContext(socketId: string): TraceContext | undefined {
    return this.socketTraceMap.get(socketId);
  }

  /**
   * Update trace context metadata
   */
  updateMetadata(socketId: string, metadata: Record<string, any>) {
    const traceContext = this.socketTraceMap.get(socketId);
    if (traceContext) {
      this.tracingService.addMetadata(traceContext.traceId, metadata);
    }
  }

  /**
   * Get all active WebSocket connections with trace info
   */
  getActiveConnections(): Map<string, TraceContext> {
    return new Map(this.socketTraceMap);
  }

  /**
   * Get active connection count
   */
  getActiveConnectionCount(): number {
    return this.socketTraceMap.size;
  }
}
