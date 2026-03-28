import * as cookieParser from 'cookie-parser';

import { ClsMiddleware, CorrelationIdMiddleware, StructuredLoggerService } from './logging';

import { AppModule } from './app.module';
import { ApplicationStateService } from './lifecycle/application-state.service';
import { AuditInterceptor } from './audit';
import { ConfigService } from '@nestjs/config';
import { InflightRequestMiddleware } from './lifecycle/inflight-request.middleware';
import { NestExpressApplication } from '@nestjs/platform-express';
import { NestFactory } from '@nestjs/core';
import { RedisIoAdapter } from './websocket/adapters/redis-io.adapter';
import { TenantQuotaMiddleware } from './quota/tenant-quota.middleware';
import { UserThrottlerGuard } from './common/guards/user-throttler.guard';
import { ValidationPipe } from '@nestjs/common';
import { inputSanitizationMiddleware } from './security/sanitization/input-sanitization.middleware';

async function bootstrap() {
  // Create app with buffer logs to ensure we can use our custom logger
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    bufferLogs: true,
  });

  const configService = app.get(ConfigService);
  const logger = app.get(StructuredLoggerService);
  const clsMiddleware = app.get(ClsMiddleware);
  const correlationIdMiddleware = app.get(CorrelationIdMiddleware);
  const inflightRequestMiddleware = app.get(InflightRequestMiddleware);
  const appState = app.get(ApplicationStateService);
  const userThrottlerGuard = app.get(UserThrottlerGuard);
  const tenantQuotaMiddleware = app.get(TenantQuotaMiddleware);

  // Use structured logger
  app.useLogger(logger);

  // CLS middleware must be first to set up async context
  app.use(clsMiddleware.getMiddleware());
  app.use(inflightRequestMiddleware.use.bind(inflightRequestMiddleware));

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // API prefix
  const apiPrefix = configService.get<string>('API_PREFIX', 'api/v1');
  app.setGlobalPrefix(apiPrefix);

  // Global middleware
  app.use(cookieParser());

  // Global input sanitization (security hardening)
  app.use(inputSanitizationMiddleware);

  // Tenant quota enforcement (API-call quotas)
  app.use(tenantQuotaMiddleware.use.bind(tenantQuotaMiddleware));

  // Correlation ID middleware for all routes
  app.use(correlationIdMiddleware.use.bind(correlationIdMiddleware));

  // WebSocket adapter
  const redisIoAdapter = new RedisIoAdapter(app);
  await redisIoAdapter.connectToRedis();
  app.useWebSocketAdapter(redisIoAdapter);

  // CORS
  app.enableCors({
    origin: true,
    credentials: true,
  });

  // Global rate limiting guard (user/IP-based)
  app.useGlobalGuards(userThrottlerGuard);

  await appState.verifyStartupDependencies();

  // Global audit interceptor for comprehensive action logging
  const auditInterceptor = app.get(AuditInterceptor);
  app.useGlobalInterceptors(auditInterceptor);

  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);
  appState.markReady();

  logger.log(`Application is running on: http://localhost:${port}/${apiPrefix}`, 'Bootstrap');
  logger.log(`Environment: ${configService.get<string>('NODE_ENV', 'development')}`, 'Bootstrap');
  logger.log(`Log level: ${configService.get<string>('LOG_LEVEL', 'info')}`, 'Bootstrap');
  logger.log(`Audit logging: enabled`, 'Bootstrap');
  logger.log(
    `Deployment slot: ${configService.get<string>('DEPLOYMENT_SLOT', 'standalone')} release=${configService.get<string>('RELEASE_VERSION', 'local')}`,
    'Bootstrap',
  );

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) {
      return;
    }

    shuttingDown = true;
    logger.warn(`Received ${signal}. Starting graceful shutdown.`, 'Bootstrap');

    try {
      await appState.beginDrain(signal);
      await appState.waitForInflightRequests();
      await app.close();
      process.exit(0);
    } catch (error) {
      logger.error(error, undefined, 'Bootstrap');
      process.exit(1);
    }
  };

  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));
}

bootstrap();
