import { ConfigModule, ConfigService } from '@nestjs/config';
import { DynamicModule, Global, Module, Provider } from '@nestjs/common';

import { AsyncContextService } from './services/async-context.service';
import { ClsMiddleware } from './middleware/cls-middleware';
import { CorrelationIdMiddleware } from './middleware/correlation-id.middleware';
import { LoggingModuleOptions } from './interfaces/logging-module-options.interface';
import { RequestLoggingInterceptor } from './interceptors/request-logging.interceptor';
import { StructuredLoggerService } from './services/structured-logger.service';

@Global()
@Module({})
export class LoggingModule {
  static forRoot(options: LoggingModuleOptions = {}): DynamicModule {
    const providers: Provider[] = [
      AsyncContextService,
      ClsMiddleware,
      {
        provide: 'LOGGER_SERVICE',
        useClass: options.loggerService || StructuredLoggerService,
      },
      {
        provide: 'LOGGING_OPTIONS',
        useValue: options,
      },
      {
        provide: StructuredLoggerService,
        useFactory: (configService: ConfigService, asyncContext: AsyncContextService) => {
          return new StructuredLoggerService(configService, asyncContext, options.defaultContext);
        },
        inject: [ConfigService, AsyncContextService],
      },
      CorrelationIdMiddleware,
      RequestLoggingInterceptor,
    ];

    return {
      module: LoggingModule,
      imports: [ConfigModule],
      providers,
      exports: [
        AsyncContextService,
        StructuredLoggerService,
        CorrelationIdMiddleware,
        RequestLoggingInterceptor,
        'LOGGER_SERVICE',
        ClsMiddleware,
      ],
      global: true,
    };
  }

  static forRootAsync(options: {
    useFactory: (...args: any[]) => Promise<LoggingModuleOptions> | LoggingModuleOptions;
    inject?: any[];
  }): DynamicModule {
    const providers: Provider[] = [
      AsyncContextService,
      ClsMiddleware,
      {
        provide: 'LOGGER_SERVICE',
        useClass: StructuredLoggerService,
      },
      {
        provide: 'LOGGING_OPTIONS',
        useFactory: options.useFactory,
        inject: options.inject || [],
      },
      {
        provide: StructuredLoggerService,
        useFactory: (configService: ConfigService, asyncContext: AsyncContextService) => {
          return new StructuredLoggerService(configService, asyncContext);
        },
        inject: [ConfigService, AsyncContextService],
      },
      CorrelationIdMiddleware,
      RequestLoggingInterceptor,
    ];

    return {
      module: LoggingModule,
      imports: [ConfigModule],
      providers,
      exports: [
        AsyncContextService,
        StructuredLoggerService,
        CorrelationIdMiddleware,
        RequestLoggingInterceptor,
        'LOGGER_SERVICE',
        ClsMiddleware,
      ],
      global: true,
    };
  }
}
