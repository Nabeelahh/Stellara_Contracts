import { resolveDistributedLockKeys } from './distributed-lock.decorator';

describe('resolveDistributedLockKeys', () => {
  it('resolves object placeholders for user lock keys', () => {
    const keys = resolveDistributedLockKeys('user:{id}', {
      args: [{ id: 'user-123' }],
      instance: {},
      methodName: 'SessionService.createSession',
    });

    expect(keys).toEqual(['user:user-123']);
  });

  it('falls back to the first primitive argument for id placeholders', () => {
    const keys = resolveDistributedLockKeys('trade:{id}', {
      args: ['trade-456', { ignored: true }],
      instance: {},
      methodName: 'TradeService.settleTrade',
    });

    expect(keys).toEqual(['trade:trade-456']);
  });

  it('supports multiple lock keys and de-duplicates them', () => {
    const keys = resolveDistributedLockKeys(['user:{id}', 'trade:{trade.id}', 'user:{id}'], {
      args: [{ id: 'user-123' }, { trade: { id: 'trade-456' } }],
      instance: {},
      methodName: 'SettlementService.process',
    });

    expect(keys).toEqual(['user:user-123', 'trade:trade-456']);
  });
});
