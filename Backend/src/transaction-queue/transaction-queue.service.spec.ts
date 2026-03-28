import { TransactionQueueService } from './transaction-queue.service';

describe('TransactionQueueService', () => {
  const mockConfigService = {
    get: jest.fn((key: string, fallback: unknown) => fallback),
  };

  const mockGateway = {
    submitTransaction: jest.fn(),
    getTransactionStatus: jest.fn(),
    bumpFee: jest.fn(),
  };

  const mockPrisma = {
    blockchainNonceState: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
  };

  let service: TransactionQueueService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new TransactionQueueService(
      mockPrisma as any,
      mockConfigService as any,
      mockGateway as any,
    );
  });

  it('classifies nonce errors with more precision', () => {
    const classify = (service as any).classifyNonceError.bind(service);
    expect(classify('tx failed: sequence number too low')).toBe('NONCE_TOO_LOW');
    expect(classify('invalid nonce too high')).toBe('NONCE_TOO_HIGH');
    expect(classify('duplicate transaction')).toBe('NONCE_DUPLICATE');
    expect(classify('random network timeout')).toBe('NONE');
  });

  it('rewinds nonce on NONCE_TOO_HIGH when state is ahead', async () => {
    mockPrisma.blockchainNonceState.findUnique.mockResolvedValue({
      signerAddress: 'GABC',
      nextNonce: BigInt(12),
      lastUsedNonce: BigInt(10),
    });

    await (service as any).recoverNonceState('GABC', BigInt(7), 'NONCE_TOO_HIGH');

    expect(mockPrisma.blockchainNonceState.update).toHaveBeenCalledWith({
      where: { signerAddress: 'GABC' },
      data: {
        nextNonce: BigInt(7),
        lastUsedNonce: BigInt(10),
      },
    });
  });
});

