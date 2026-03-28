import { RealtimeAnalyticsService } from './realtime-analytics.service';

describe('RealtimeAnalyticsService', () => {
  const mockPrisma = {
    realtimeMetricRollup: {
      findMany: jest.fn(),
    },
  };
  const mockGateway = {
    broadcastGlobal: jest.fn(),
    emitRollupRefresh: jest.fn(),
  };

  let service: RealtimeAnalyticsService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new RealtimeAnalyticsService(mockPrisma as any, mockGateway as any);
  });

  it('exports CSV with expected content type', async () => {
    mockPrisma.realtimeMetricRollup.findMany.mockResolvedValue([
      {
        bucket: 'M1',
        metricName: 'trade_count',
        metricValue: 42,
        bucketStart: new Date('2026-01-01T00:00:00.000Z'),
        bucketEnd: new Date('2026-01-01T00:01:00.000Z'),
        dimensions: {},
        createdAt: new Date('2026-01-01T00:01:00.000Z'),
      },
    ]);

    const out = await service.exportRollups({ format: 'csv' } as any);
    expect(out.format).toBe('csv');
    expect(out.contentType).toBe('text/csv');
    expect(out.content).toContain('metricName');
  });

  it('exports Excel-style tab-delimited payload when requested', async () => {
    mockPrisma.realtimeMetricRollup.findMany.mockResolvedValue([]);

    const out = await service.exportRollups({ format: 'excel' } as any);
    expect(out.format).toBe('excel');
    expect(out.contentType).toBe('application/vnd.ms-excel');
  });
});

