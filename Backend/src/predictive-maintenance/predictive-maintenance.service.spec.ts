// src/predictive-maintenance/predictive-maintenance.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { PredictiveMaintenanceService } from './predictive-maintenance.service';
import { PrismaService } from '../prisma.service';

describe('PredictiveMaintenanceService', () => {
  let service: PredictiveMaintenanceService;
  let prisma: PrismaService;
  let config: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PredictiveMaintenanceService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              const config = {
                'SLACK_WEBHOOK_URL': 'https://hooks.slack.com/test',
                'PAGERDUTY_ROUTING_KEY': 'test-key',
                'PREDICTION_CONFIDENCE_THRESHOLD': '0.8',
                'ANOMALY_DETECTION_SIGMA': '3',
              };
              return config[key];
            }),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            systemMetric: {
              create: jest.fn(),
              findMany: jest.fn(),
              aggregate: jest.fn(),
            },
            metricPrediction: {
              create: jest.fn(),
              findMany: jest.fn(),
              update: jest.fn(),
            },
            maintenanceTicket: {
              create: jest.fn(),
              findMany: jest.fn(),
            },
            maintenanceNotification: {
              create: jest.fn(),
            },
            mLModel: {
              findFirst: jest.fn(),
              create: jest.fn(),
            },
          },
        },
      ],
    }).compile();

    service = module.get<PredictiveMaintenanceService>(PredictiveMaintenanceService);
    prisma = module.get<PrismaService>(PrismaService);
    config = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('gatherSystemMetrics', () => {
    it('should collect system metrics', async () => {
      const metrics = await service['gatherSystemMetrics']();

      expect(metrics).toHaveProperty('cpu');
      expect(metrics).toHaveProperty('memory');
      expect(metrics).toHaveProperty('disk');
      expect(metrics).toHaveProperty('connections');

      expect(metrics.cpu).toHaveProperty('usage');
      expect(metrics.memory).toHaveProperty('usage');
      expect(metrics.disk).toHaveProperty('usage');
    });
  });

  describe('detectStatisticalAnomaly', () => {
    it('should detect anomalies using 3-sigma rule', () => {
      const values = [10, 12, 11, 13, 10, 50]; // 50 is an outlier
      const mean = 11;
      const stdDev = 1.5;

      const result = service['detectStatisticalAnomaly'](values, mean, stdDev);

      expect(result.isAnomaly).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.99);
    });

    it('should not detect anomaly for normal values', () => {
      const values = [10, 11, 12, 11, 10, 11];
      const mean = 11;
      const stdDev = 0.8;

      const result = service['detectStatisticalAnomaly'](values, mean, stdDev);

      expect(result.isAnomaly).toBe(false);
      expect(result.confidence).toBeLessThan(0.5);
    });
  });

  describe('forecastCapacity', () => {
    it('should forecast linear trend', () => {
      const data = [
        { timestamp: new Date('2024-01-01'), value: 10 },
        { timestamp: new Date('2024-01-02'), value: 12 },
        { timestamp: new Date('2024-01-03'), value: 14 },
        { timestamp: new Date('2024-01-04'), value: 16 },
      ];

      const result = service['forecastCapacity'](data, 7);

      expect(result).toHaveProperty('predictedValue');
      expect(result).toHaveProperty('confidence');
      expect(result).toHaveProperty('daysUntilThreshold');
      expect(result.predictedValue).toBeGreaterThan(16); // Should predict upward trend
    });
  });

  describe('getSystemHealth', () => {
    it('should return system health status', async () => {
      const mockMetrics = {
        cpu: { usage: 45 },
        memory: { usage: 60 },
        disk: { usage: 70 },
        connections: { active: 50, max: 100 },
      };

      jest.spyOn(service as any, 'getCurrentMetrics').mockResolvedValue(mockMetrics);

      const health = await service.getSystemHealth();

      expect(health).toHaveProperty('status');
      expect(health).toHaveProperty('metrics');
      expect(health).toHaveProperty('lastUpdated');
      expect(health.status).toBe('healthy');
    });
  });
});