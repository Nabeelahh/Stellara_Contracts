import { DataRetentionService } from './data-retention.service';

describe('DataRetentionService', () => {
  const mockPrisma = {
    dataRetentionRule: {
      findMany: jest.fn(),
    },
    retentionExecution: {
      findMany: jest.fn(),
    },
    legalHold: {
      count: jest.fn(),
    },
  };

  const mockObjectStorage = {};
  const mockRedisService = {};
  const mockConfigService = {
    get: jest.fn((_: string, fallback: unknown) => fallback),
  };
  const mockAuditService = {};

  let service: DataRetentionService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new DataRetentionService(
      mockPrisma as any,
      mockObjectStorage as any,
      mockRedisService as any,
      mockConfigService as any,
      mockAuditService as any,
    );
  });

  it('reports missing required baseline rules in compliance report', async () => {
    mockPrisma.dataRetentionRule.findMany.mockResolvedValue([
      { tenantId: null, dataType: 'TRADES' },
    ]);
    mockPrisma.retentionExecution.findMany.mockResolvedValue([]);
    mockPrisma.legalHold.count.mockResolvedValueOnce(0).mockResolvedValueOnce(0);

    const report = await service.getComplianceReport(30);

    expect(report['requiredRulesCompliant']).toBe(false);
    expect(report['missingRequiredRules']).toEqual(expect.arrayContaining(['LOGS', 'SESSIONS']));
  });
});

