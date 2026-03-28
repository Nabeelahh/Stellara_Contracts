import { StructuredLoggerService } from '../services/structured-logger.service';

/**
 * Decorator to inject a logger into a class with the class name as context
 *
 * Usage:
 * ```
 * @Injectable()
 * @WithLogger()
 * export class MyService {
 *   constructor(private readonly logger: StructuredLoggerService) {}
 *
 *   myMethod() {
 *     this.logger.log('Hello from MyService');
 *   }
 * }
 * ```
 */
export function WithLogger() {
  return function <T extends new (...args: any[]) => any>(constructor: T) {
    return class extends constructor {
      logger: StructuredLoggerService;

      constructor(...args: any[]) {
        super(...args);
        // Try to get logger from injected services
        const loggerIndex = args.findIndex((arg) => arg instanceof StructuredLoggerService);

        if (loggerIndex !== -1) {
          this.logger = args[loggerIndex];
        } else {
          // Create a new logger instance if none found
          // This will be properly configured when the service is instantiated
          this.logger = args.find(
            (arg) => arg?.constructor?.name === 'StructuredLoggerService',
          ) as StructuredLoggerService;
        }

        if (this.logger) {
          this.logger.setContext(constructor.name);
        }
      }
    };
  };
}

/**
 * Method decorator to log method entry and exit with timing
 */
export function LogMethod(
  options: {
    level?: 'debug' | 'info' | 'log';
    logArgs?: boolean;
    logResult?: boolean;
  } = {},
) {
  const { level = 'debug', logArgs = false, logResult = false } = options;

  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    const className = target.constructor.name;

    descriptor.value = async function (...args: any[]) {
      const logger: StructuredLoggerService = (this as any).logger;
      const startTime = Date.now();

      const logData: any = {
        method: `${className}.${propertyKey}`,
        startTime: new Date(startTime).toISOString(),
      };

      if (logArgs) {
        logData.args = args;
      }

      if (logger) {
        logger[level]?.call(logger, `Entering ${className}.${propertyKey}`, logData);
      }

      try {
        const result = await originalMethod.apply(this, args);
        const endTime = Date.now();
        const duration = endTime - startTime;

        if (logger) {
          const exitLogData: any = {
            method: `${className}.${propertyKey}`,
            durationMs: duration,
          };

          if (logResult) {
            exitLogData.result = result;
          }

          logger[level]?.call(logger, `Exiting ${className}.${propertyKey}`, exitLogData);
        }

        return result;
      } catch (error) {
        const endTime = Date.now();
        const duration = endTime - startTime;

        if (logger) {
          logger.error?.call(
            logger,
            `Error in ${className}.${propertyKey}: ${error.message}`,
            error.stack,
            {
              method: `${className}.${propertyKey}`,
              durationMs: duration,
              error: {
                name: error.name,
                message: error.message,
              },
            },
          );
        }

        throw error;
      }
    };

    return descriptor;
  };
}

/**
 * Method decorator to trace method execution with performance metrics
 */
export function Trace(operationName?: string) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    const className = target.constructor.name;
    const name = operationName || `${className}.${propertyKey}`;

    descriptor.value = async function (...args: any[]) {
      const logger: StructuredLoggerService = (this as any).logger;

      if (logger) {
        const trace = logger.startTrace(name, {
          class: className,
          method: propertyKey,
        });

        try {
          const result = await originalMethod.apply(this, args);
          trace.end({ success: true });
          return result;
        } catch (error) {
          trace.end({ success: false, error: error.message });
          throw error;
        }
      } else {
        return originalMethod.apply(this, args);
      }
    };

    return descriptor;
  };
}
