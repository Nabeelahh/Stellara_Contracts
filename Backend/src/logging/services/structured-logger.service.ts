import { Injectable, LoggerService, Optional, Inject, Scope } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import pino from 'pino';
import { AsyncContextService } from './async-context.service';
import { LogContext } from '../interfaces/logger.interface';

@Injectable({ scope: Scope.DEFAULT })
export class StructuredLoggerService implements LoggerService {
  private pino: pino.Logger;
  private context?: string;
  private serviceName: string;
  private environment: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly asyncContext: AsyncContextService,
    @Optional() context?: string,
  ) {
    this.context = context;
    this.serviceName = this.configService.get<string>('SERVICE_NAME', 'stellara-api');
    this.environment = this.configService.get<string>('NODE_ENV', 'development');

    const isDevelopment = this.environment === 'development';
    const prettyPrint = this.configService.get<boolean>('LOG_PRETTY_PRINT', isDevelopment);
    const logLevel = this.configService.get<string>('LOG_LEVEL', isDevelopment ? 'debug' : 'info');

    // Configure pino transport
    const transport = prettyPrint
      ? {
          target: 'pino-pretty',
          options: {
            colorize: true,
            levelFirst: true,
            translateTime: 'SYS:standard',
            ignore: 'pid,hostname',
            messageFormat: '{msg}',
          },
        }
      : undefined;

    this.pino = pino.pino({
      level: logLevel,
      transport,
      timestamp: pino.pino.stdTimeFunctions.isoTime,
      formatters: {
        level: (label) => ({ level: label }),
        bindings: () => ({}),
      },
      serializers: {
        error: pino.stdSerializers.err,
        request: pino.stdSerializers.req,
        response: pino.stdSerializers.res,
      },
      redact: {
        paths: [
          'password',
          'passwordConfirm',
          'hashedRefreshToken',
          'accessToken',
          'refreshToken',
          'token',
          'authorization',
          'cookie',
          '*.password',
          '*.passwordConfirm',
          '*.hashedRefreshToken',
          '*.accessToken',
          '*.refreshToken',
          'req.headers.authorization',
          'req.headers.cookie',
        ],
        censor: '[REDACTED]',
      },
      base: {
        service: this.serviceName,
        env: this.environment,
      },
    });
  }

  setContext(context: string): void {
    this.context = context;
  }

  log(message: any, context?: string): void {
    this.writeLog('info', message, context);
  }

  error(message: any, trace?: string, context?: string): void {
    const logContext = this.getLogContext();

    if (message instanceof Error) {
      this.pino.error(
        {
          ...logContext,
          context: context || this.context,
          error: message,
          trace,
        },
        message.message,
      );
    } else {
      this.pino.error(
        {
          ...logContext,
          context: context || this.context,
          trace,
        },
        this.formatMessage(message),
      );
    }
  }

  warn(message: any, context?: string): void {
    this.writeLog('warn', message, context);
  }

  debug(message: any, context?: string): void {
    this.writeLog('debug', message, context);
  }

  verbose(message: any, context?: string): void {
    this.writeLog('trace', message, context);
  }

  fatal(message: any, trace?: string, context?: string): void {
    const logContext = this.getLogContext();

    if (message instanceof Error) {
      this.pino.fatal(
        {
          ...logContext,
          context: context || this.context,
          error: message,
          trace,
        },
        message.message,
      );
    } else {
      this.pino.fatal(
        {
          ...logContext,
          context: context || this.context,
          trace,
        },
        this.formatMessage(message),
      );
    }
  }

  /**
   * Log with additional context data
   */
  logWithContext(
    level: 'info' | 'error' | 'warn' | 'debug' | 'trace' | 'fatal',
    message: string,
    additionalContext?: LogContext,
  ): void {
    const logContext = this.getLogContext();
    const mergedContext = { ...logContext, ...additionalContext };

    this.pino[level]({ ...mergedContext, context: this.context }, message);
  }

  /**
   * Start a performance trace
   */
  startTrace(
    name: string,
    metadata?: Record<string, any>,
  ): { end: (additionalMetadata?: Record<string, any>) => void } {
    const startTime = Date.now();
    const startHrTime = process.hrtime.bigint();

    return {
      end: (additionalMetadata?: Record<string, any>) => {
        const endTime = Date.now();
        const endHrTime = process.hrtime.bigint();
        const durationMs = endTime - startTime;
        const durationNs = Number(endHrTime - startHrTime) / 1_000_000;

        const logContext = this.getLogContext();

        this.pino.info(
          {
            ...logContext,
            context: this.context,
            trace: {
              name,
              startTime,
              endTime,
              durationMs,
              durationNs: durationNs.toFixed(3),
              metadata: { ...metadata, ...additionalMetadata },
            },
          },
          `Trace: ${name} completed in ${durationMs}ms`,
        );
      },
    };
  }

  /**
   * Create a child logger with additional context
   */
  child(context: string, additionalContext?: LogContext): StructuredLoggerService {
    const childLogger = new StructuredLoggerService(this.configService, this.asyncContext, context);

    // Create child pino logger with merged context
    childLogger.pino = this.pino.child({
      context,
      ...additionalContext,
    });

    return childLogger;
  }

  private writeLog(
    level: 'info' | 'warn' | 'debug' | 'trace',
    message: any,
    context?: string,
  ): void {
    const logContext = this.getLogContext();
    const logData = {
      ...logContext,
      context: context || this.context,
    };

    if (typeof message === 'object') {
      this.pino[level]({ ...logData, ...message }, message.msg || 'Log message');
    } else {
      this.pino[level](logData, this.formatMessage(message));
    }
  }

  private formatMessage(message: any): string {
    if (typeof message === 'string') {
      return message;
    }
    if (typeof message === 'object') {
      return JSON.stringify(message);
    }
    return String(message);
  }

  private getLogContext(): LogContext {
    return {
      correlationId: this.asyncContext.getCorrelationId(),
      userId: this.asyncContext.getUserId(),
      tenantId: this.asyncContext.getTenantId(),
      requestId: this.asyncContext.getRequestId(),
    };
  }

  /**
   * Get raw pino logger for advanced usage
   */
  getPino(): pino.Logger {
    return this.pino;
  }

  /**
   * Flush logs (useful for external log shipping)
   */
  async flush(): Promise<void> {
    return new Promise((resolve) => {
      this.pino.flush(() => resolve());
    });
  }
}
