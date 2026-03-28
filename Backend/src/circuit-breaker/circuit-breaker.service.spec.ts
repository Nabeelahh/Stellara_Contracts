import { CircuitBreakerService } from './circuit-breaker.service';

describe('CircuitBreakerService', () => {
  let service: CircuitBreakerService;

  beforeEach(() => {
    service = new CircuitBreakerService();
  });

  it('stores override reason and timestamp on manual override', () => {
    const result = service.setOverride('stellar-rpc', 'FORCE_OPEN', 'maintenance window');

    expect(result.override).toBe('FORCE_OPEN');
    expect(result.lastOverrideReason).toBe('maintenance window');
    expect(typeof result.lastOverrideAt).toBe('number');
  });

  it('uses fallback when forced open', async () => {
    service.setOverride('external-webhooks', 'FORCE_OPEN', 'dependency outage');

    const value = await service.execute(
      'external-webhooks',
      async () => 'should-not-run',
      { fallback: async () => 'fallback-ok' },
    );

    expect(value).toBe('fallback-ok');
    const state = service.getCircuit('external-webhooks');
    expect(state.totalFallbacks).toBeGreaterThan(0);
    expect(state.totalRejected).toBeGreaterThan(0);
  });
});

