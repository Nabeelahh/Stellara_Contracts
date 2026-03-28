import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';
export type CircuitOverrideMode = 'AUTO' | 'FORCE_OPEN' | 'FORCE_CLOSED';

export type CircuitConfig = {
  failureThreshold: number;
  failureWindowMs: number;
  openTimeoutMs: number;
  halfOpenMaxCalls: number;
  halfOpenSuccessThreshold: number;
};

export type CircuitExecutionOptions<T> = {
  fallback?: (error: Error) => Promise<T> | T;
  config?: Partial<CircuitConfig>;
};

type CircuitRuntime = {
  name: string;
  state: CircuitState;
  override: CircuitOverrideMode;
  config: CircuitConfig;
  failureTimestamps: number[];
  consecutiveHalfOpenSuccesses: number;
  halfOpenAllowedCalls: number;
  halfOpenInFlight: number;
  openedAt: number | null;
  lastFailureAt: number | null;
  lastFailureReason: string | null;
  totalRequests: number;
  totalSuccesses: number;
  totalFailures: number;
  totalRejected: number;
  totalFallbacks: number;
  transitions: number;
  lastOverrideAt: number | null;
  lastOverrideReason: string | null;
};

@Injectable()
export class CircuitBreakerService {
  private readonly logger = new Logger(CircuitBreakerService.name);
  private readonly circuits = new Map<string, CircuitRuntime>();

  private readonly defaultConfig: CircuitConfig = {
    failureThreshold: 5,
    failureWindowMs: 10_000,
    openTimeoutMs: 30_000,
    halfOpenMaxCalls: 10,
    halfOpenSuccessThreshold: 3,
  };

  register(name: string, config?: Partial<CircuitConfig>): void {
    this.getOrCreateCircuit(name, config);
  }

  async execute<T>(
    name: string,
    action: () => Promise<T>,
    options?: CircuitExecutionOptions<T>,
  ): Promise<T> {
    const circuit = this.getOrCreateCircuit(name, options?.config);
    circuit.totalRequests += 1;

    if (circuit.override === 'FORCE_OPEN') {
      circuit.totalRejected += 1;
      return this.handleRejectedRequest(name, circuit, new Error('Circuit forced open'), options?.fallback);
    }

    if (circuit.override !== 'FORCE_CLOSED') {
      if (circuit.state === 'OPEN') {
        const canProbeHalfOpen =
          circuit.openedAt !== null && Date.now() - circuit.openedAt >= circuit.config.openTimeoutMs;

        if (!canProbeHalfOpen) {
          circuit.totalRejected += 1;
          return this.handleRejectedRequest(
            name,
            circuit,
            new Error('Circuit open and timeout window not elapsed'),
            options?.fallback,
          );
        }

        this.transitionState(circuit, 'HALF_OPEN', 'open-timeout-elapsed');
      }

      if (circuit.state === 'HALF_OPEN') {
        if (circuit.halfOpenInFlight >= circuit.halfOpenAllowedCalls) {
          circuit.totalRejected += 1;
          return this.handleRejectedRequest(
            name,
            circuit,
            new Error('Half-open probe capacity reached'),
            options?.fallback,
          );
        }
        circuit.halfOpenInFlight += 1;
      }
    }

    try {
      const result = await action();
      circuit.totalSuccesses += 1;
      this.onSuccess(circuit);
      return result;
    } catch (error) {
      const normalizedError = this.toError(error);
      circuit.totalFailures += 1;
      this.onFailure(circuit, normalizedError);

      if (options?.fallback) {
        circuit.totalFallbacks += 1;
        return options.fallback(normalizedError);
      }

      throw normalizedError;
    } finally {
      if (circuit.state === 'HALF_OPEN' && circuit.halfOpenInFlight > 0) {
        circuit.halfOpenInFlight -= 1;
      }
    }
  }

  setOverride(name: string, mode: CircuitOverrideMode, reason?: string): CircuitRuntime {
    const circuit = this.getOrCreateCircuit(name);
    circuit.override = mode;
    circuit.lastOverrideAt = Date.now();
    circuit.lastOverrideReason = reason ?? null;

    if (mode === 'FORCE_CLOSED') {
      this.transitionState(circuit, 'CLOSED', 'manual-force-closed');
    }
    if (mode === 'FORCE_OPEN') {
      this.transitionState(circuit, 'OPEN', 'manual-force-open');
    }

    return this.snapshotCircuit(circuit);
  }

  reset(name: string): CircuitRuntime {
    const circuit = this.getOrCreateCircuit(name);
    circuit.state = 'CLOSED';
    circuit.override = 'AUTO';
    circuit.failureTimestamps = [];
    circuit.consecutiveHalfOpenSuccesses = 0;
    circuit.halfOpenAllowedCalls = 1;
    circuit.halfOpenInFlight = 0;
    circuit.openedAt = null;
    circuit.lastFailureAt = null;
    circuit.lastFailureReason = null;
    circuit.transitions += 1;
    this.logger.log(`Circuit ${name} reset to CLOSED`);
    return this.snapshotCircuit(circuit);
  }

  getCircuit(name: string): CircuitRuntime {
    const circuit = this.getOrCreateCircuit(name);
    return this.snapshotCircuit(circuit);
  }

  getAllCircuits(): CircuitRuntime[] {
    return Array.from(this.circuits.values())
      .map((circuit) => this.snapshotCircuit(circuit))
      .sort((left, right) => left.name.localeCompare(right.name));
  }

  private getOrCreateCircuit(name: string, config?: Partial<CircuitConfig>): CircuitRuntime {
    const existing = this.circuits.get(name);
    if (existing) {
      if (config) {
        existing.config = this.mergeConfig(existing.config, config);
      }
      return existing;
    }

    const created: CircuitRuntime = {
      name,
      state: 'CLOSED',
      override: 'AUTO',
      config: this.mergeConfig(this.defaultConfig, config),
      failureTimestamps: [],
      consecutiveHalfOpenSuccesses: 0,
      halfOpenAllowedCalls: 1,
      halfOpenInFlight: 0,
      openedAt: null,
      lastFailureAt: null,
      lastFailureReason: null,
      totalRequests: 0,
      totalSuccesses: 0,
      totalFailures: 0,
      totalRejected: 0,
      totalFallbacks: 0,
      transitions: 0,
      lastOverrideAt: null,
      lastOverrideReason: null,
    };

    this.circuits.set(name, created);
    this.logger.log(`Registered circuit ${name}`);
    return created;
  }

  private onSuccess(circuit: CircuitRuntime): void {
    this.trimFailures(circuit);

    if (circuit.state !== 'HALF_OPEN') {
      return;
    }

    circuit.consecutiveHalfOpenSuccesses += 1;
    circuit.halfOpenAllowedCalls = Math.min(
      circuit.config.halfOpenMaxCalls,
      circuit.halfOpenAllowedCalls + 1,
    );

    if (circuit.consecutiveHalfOpenSuccesses >= circuit.config.halfOpenSuccessThreshold) {
      this.transitionState(circuit, 'CLOSED', 'half-open-success-threshold-reached');
    }
  }

  private onFailure(circuit: CircuitRuntime, error: Error): void {
    circuit.lastFailureAt = Date.now();
    circuit.lastFailureReason = error.message;

    if (circuit.state === 'HALF_OPEN') {
      this.transitionState(circuit, 'OPEN', 'half-open-probe-failure');
      return;
    }

    if (circuit.state === 'OPEN') {
      return;
    }

    circuit.failureTimestamps.push(Date.now());
    this.trimFailures(circuit);

    if (circuit.failureTimestamps.length >= circuit.config.failureThreshold) {
      this.transitionState(circuit, 'OPEN', 'failure-threshold-reached');
    }
  }

  private trimFailures(circuit: CircuitRuntime): void {
    const minTimestamp = Date.now() - circuit.config.failureWindowMs;
    circuit.failureTimestamps = circuit.failureTimestamps.filter((timestamp) => timestamp >= minTimestamp);
  }

  private transitionState(circuit: CircuitRuntime, nextState: CircuitState, reason: string): void {
    if (circuit.state === nextState) {
      return;
    }

    const previous = circuit.state;
    circuit.state = nextState;
    circuit.transitions += 1;

    if (nextState === 'OPEN') {
      circuit.openedAt = Date.now();
      circuit.consecutiveHalfOpenSuccesses = 0;
      circuit.halfOpenAllowedCalls = 1;
      circuit.halfOpenInFlight = 0;
    }

    if (nextState === 'HALF_OPEN') {
      circuit.consecutiveHalfOpenSuccesses = 0;
      circuit.halfOpenAllowedCalls = 1;
      circuit.halfOpenInFlight = 0;
    }

    if (nextState === 'CLOSED') {
      circuit.failureTimestamps = [];
      circuit.openedAt = null;
      circuit.consecutiveHalfOpenSuccesses = 0;
      circuit.halfOpenAllowedCalls = 1;
      circuit.halfOpenInFlight = 0;
    }

    this.logger.warn(
      `Circuit ${circuit.name} transitioned ${previous} -> ${nextState} (reason=${reason})`,
    );
  }

  private async handleRejectedRequest<T>(
    name: string,
    circuit: CircuitRuntime,
    error: Error,
    fallback?: (error: Error) => Promise<T> | T,
  ): Promise<T> {
    this.logger.warn(
      `Circuit ${name} rejected request (state=${circuit.state}, override=${circuit.override}): ${error.message}`,
    );

    if (fallback) {
      circuit.totalFallbacks += 1;
      return fallback(error);
    }

    throw new ServiceUnavailableException(
      `External dependency is temporarily unavailable (${name} circuit ${circuit.state})`,
    );
  }

  private mergeConfig(base: CircuitConfig, override?: Partial<CircuitConfig>): CircuitConfig {
    if (!override) {
      return { ...base };
    }

    return {
      failureThreshold: Math.max(1, override.failureThreshold ?? base.failureThreshold),
      failureWindowMs: Math.max(1000, override.failureWindowMs ?? base.failureWindowMs),
      openTimeoutMs: Math.max(1000, override.openTimeoutMs ?? base.openTimeoutMs),
      halfOpenMaxCalls: Math.max(1, override.halfOpenMaxCalls ?? base.halfOpenMaxCalls),
      halfOpenSuccessThreshold: Math.max(
        1,
        override.halfOpenSuccessThreshold ?? base.halfOpenSuccessThreshold,
      ),
    };
  }

  private snapshotCircuit(circuit: CircuitRuntime): CircuitRuntime {
    return {
      ...circuit,
      config: { ...circuit.config },
      failureTimestamps: [...circuit.failureTimestamps],
    };
  }

  private toError(error: unknown): Error {
    if (error instanceof Error) {
      return error;
    }
    return new Error(String(error));
  }
}

