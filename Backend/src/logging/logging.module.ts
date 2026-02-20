import { Module, Global, MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { StructuredLogger } from './structured-logger.service';
import { CorrelationIdMiddleware } from './correlation-id.middleware';
import { ErrorTrackingService } from './error-tracking.service';
import { MetricsService } from './metrics.service';

@Global()
@Module({
  providers: [
    StructuredLogger,
    ErrorTrackingService,
    MetricsService,
  ],
  exports: [
    StructuredLogger,
    ErrorTrackingService,
    MetricsService,
  ],
})
export class LoggingModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(CorrelationIdMiddleware)
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}
