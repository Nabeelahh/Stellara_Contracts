import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { RedisIoAdapter } from './websocket/redis-io.adapter';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { ThrottleGuard } from './throttle/throttle.guard';
import { StructuredLogger } from './logging/structured-logger.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // swap out Nest's default logger with our structured implementation
  const logger = app.get(StructuredLogger);
  app.useLogger(logger);

  // Enable validation globally
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Configure Swagger
  const config = new DocumentBuilder()
    .setTitle('Stellara API')
    .setDescription('API for authentication, monitoring Stellar network events, and delivering webhooks')
    .setVersion('1.0')
    .addTag('Authentication')
    .addTag('Stellar Monitor')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  const redisIoAdapter = new RedisIoAdapter(app);
  await redisIoAdapter.connectToRedis();

  app.useWebSocketAdapter(redisIoAdapter);
  app.useGlobalGuards(app.get(ThrottleGuard));

  // register global exception filter so every error passes through structured logging
  app.useGlobalFilters(app.get(require('./logging/all-exceptions.filter').AllExceptionsFilter));

  // expose Prometheus metrics on a simple endpoint
  const metricsService = app.get(require('./logging/metrics.service').MetricsService);
  app.get('/metrics', async (_req, res) => {
    res.set('Content-Type', 'text/plain');
    res.send(await metricsService.getMetrics());
  });

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
