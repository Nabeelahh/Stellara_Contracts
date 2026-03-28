// src/predictive-maintenance/predictive-maintenance.controller.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { PredictiveMaintenanceController } from './predictive-maintenance.controller';
import { PredictiveMaintenanceService } from './predictive-maintenance.service';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma.service';

describe('PredictiveMaintenanceController', () => {
  let controller: PredictiveMaintenanceController;
  let service: PredictiveMaintenanceService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [PredictiveMaintenanceController],
      providers: [
        {
          provide: PredictiveMaintenanceService,
          useValue: {
            getSystemHealth: jest.fn(),
            getCurrentMetrics: jest.fn(),
            getActivePredictions: jest.fn(),
            getDetectedAnomalies: jest.fn(),
            getMaintenanceTickets: jest.fn(),
            performFullAnalysis: jest.fn(),
            getCapacityForecasts: jest.fn(),
            getModelPerformance: jest.fn(),
          },
        },
      ],
    }).compile();

    controller = module.get<PredictiveMaintenanceController>(PredictiveMaintenanceController);
    service = module.get<PredictiveMaintenanceService>(PredictiveMaintenanceService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getSystemHealth', () => {
    it('should return system health', async () => {
      const mockHealth = {
        status: 'healthy',
        metrics: { cpu: 45, memory: 60 },
        lastUpdated: new Date(),
      };

      jest.spyOn(service, 'getSystemHealth').mockResolvedValue(mockHealth);

      const result = await controller.getSystemHealth();
      expect(result).toEqual(mockHealth);
    });
  });

  describe('getCurrentMetrics', () => {
    it('should return current metrics', async () => {
      const mockMetrics = {
        cpu: { usage: 45 },
        memory: { usage: 60 },
        disk: { usage: 70 },
        connections: { active: 50, max: 100 },
      };

      jest.spyOn(service, 'getCurrentMetrics').mockResolvedValue(mockMetrics);

      const result = await controller.getCurrentMetrics();
      expect(result).toEqual(mockMetrics);
    });
  });

  describe('getActivePredictions', () => {
    it('should return active predictions', async () => {
      const mockPredictions = [
        {
          id: '1',
          type: 'cpu',
          riskLevel: 'high',
          confidence: 0.85,
          predictedAt: new Date(),
        },
      ];

      jest.spyOn(service, 'getActivePredictions').mockResolvedValue(mockPredictions);

      const result = await controller.getActivePredictions('cpu');
      expect(result).toEqual(mockPredictions);
    });
  });

  describe('getDetectedAnomalies', () => {
    it('should return detected anomalies', async () => {
      const mockAnomalies = [
        {
          id: '1',
          metricType: 'cpu',
          value: 95,
          threshold: 80,
          detectedAt: new Date(),
        },
      ];

      jest.spyOn(service, 'getDetectedAnomalies').mockResolvedValue(mockAnomalies);

      const result = await controller.getDetectedAnomalies(24);
      expect(result).toEqual(mockAnomalies);
    });
  });

  describe('getMaintenanceTickets', () => {
    it('should return maintenance tickets', async () => {
      const mockTickets = [
        {
          id: '1',
          title: 'High CPU Usage Detected',
          status: 'open',
          priority: 'high',
          createdAt: new Date(),
        },
      ];

      jest.spyOn(service, 'getMaintenanceTickets').mockResolvedValue(mockTickets);

      const result = await controller.getMaintenanceTickets('open');
      expect(result).toEqual(mockTickets);
    });
  });

  describe('triggerAnalysis', () => {
    it('should trigger analysis', async () => {
      const mockResult = { success: true, predictions: 5 };

      jest.spyOn(service, 'performFullAnalysis').mockResolvedValue(mockResult);

      const result = await controller.triggerAnalysis();
      expect(result).toEqual(mockResult);
    });
  });

  describe('getCapacityForecasts', () => {
    it('should return capacity forecasts', async () => {
      const mockForecasts = {
        disk: {
          predictedValue: 95,
          daysUntilThreshold: 5,
          confidence: 0.9,
        },
      };

      jest.spyOn(service, 'getCapacityForecasts').mockResolvedValue(mockForecasts);

      const result = await controller.getCapacityForecasts(7);
      expect(result).toEqual(mockForecasts);
    });
  });

  describe('getModelPerformance', () => {
    it('should return model performance', async () => {
      const mockPerformance = {
        accuracy: 0.85,
        precision: 0.82,
        recall: 0.88,
        lastUpdated: new Date(),
      };

      jest.spyOn(service, 'getModelPerformance').mockResolvedValue(mockPerformance);

      const result = await controller.getModelPerformance();
      expect(result).toEqual(mockPerformance);
    });
  });
});