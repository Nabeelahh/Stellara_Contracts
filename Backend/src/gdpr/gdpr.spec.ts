import { Test, TestingModule } from '@nestjs/testing';
import { DataExportService } from './services/data-export.service';
import { DataDeletionService } from './services/data-deletion.service';
import { ConsentManagementService } from './services/consent-management.service';
import { DataRetentionService } from './services/data-retention.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../auth/entities/user.entity';
import { WalletBinding } from '../auth/entities/wallet-binding.entity';
import { RefreshToken } from '../auth/entities/refresh-token.entity';
import { ApiToken } from '../auth/entities/api-token.entity';
import { AuditLog } from '../audit/audit.entity';
import { Consent, ConsentType } from './entities/consent.entity';
import { AuditService } from '../audit/audit.service';

describe('GDPR Services', () => {
  let dataExportService: DataExportService;
  let dataDeletionService: DataDeletionService;
  let consentManagementService: ConsentManagementService;
  let dataRetentionService: DataRetentionService;

  const mockUserRepository = {
    findOne: jest.fn(),
    update: jest.fn(),
  };

  const mockWalletRepository = {
    find: jest.fn(),
    update: jest.fn(),
  };

  const mockRefreshTokenRepository = {
    find: jest.fn(),
    update: jest.fn(),
  };

  const mockApiTokenRepository = {
    find: jest.fn(),
    update: jest.fn(),
  };

  const mockAuditLogRepository = {
    find: jest.fn(),
  };

  const mockConsentRepository = {
    find: jest.fn(),
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
  };

  const mockAuditService = {
    logAction: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DataExportService,
        DataDeletionService,
        ConsentManagementService,
        DataRetentionService,
        {
          provide: getRepositoryToken(User),
          useValue: mockUserRepository,
        },
        {
          provide: getRepositoryToken(WalletBinding),
          useValue: mockWalletRepository,
        },
        {
          provide: getRepositoryToken(RefreshToken),
          useValue: mockRefreshTokenRepository,
        },
        {
          provide: getRepositoryToken(ApiToken),
          useValue: mockApiTokenRepository,
        },
        {
          provide: getRepositoryToken(AuditLog),
          useValue: mockAuditLogRepository,
        },
        {
          provide: getRepositoryToken(Consent),
          useValue: mockConsentRepository,
        },
        {
          provide: AuditService,
          useValue: mockAuditService,
        },
      ],
    }).compile();

    dataExportService = module.get<DataExportService>(DataExportService);
    dataDeletionService = module.get<DataDeletionService>(DataDeletionService);
    consentManagementService = module.get<ConsentManagementService>(ConsentManagementService);
    dataRetentionService = module.get<DataRetentionService>(DataRetentionService);
  });

  describe('DataExportService', () => {
    it('should be defined', () => {
      expect(dataExportService).toBeDefined();
    });

    it('should export user data', async () => {
      const userId = 'test-user-id';
      const mockUser = { id: userId, email: 'test@example.com', isActive: true };
      
      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockWalletRepository.find.mockResolvedValue([]);
      mockRefreshTokenRepository.find.mockResolvedValue([]);
      mockApiTokenRepository.find.mockResolvedValue([]);
      mockAuditLogRepository.find.mockResolvedValue([]);
      mockConsentRepository.find.mockResolvedValue([]);

      const result = await dataExportService.exportUserData(userId);

      expect(result.user.id).toBe(userId);
      expect(result.user.email).toBe('test@example.com');
      expect(mockAuditService.logAction).toHaveBeenCalledWith(
        'DATA_EXPORT_REQUESTED',
        userId,
        userId,
        expect.any(Object)
      );
    });
  });

  describe('DataDeletionService', () => {
    it('should be defined', () => {
      expect(dataDeletionService).toBeDefined();
    });

    it('should request deletion', async () => {
      const userId = 'test-user-id';
      const mockUser = { id: userId, isActive: true };
      
      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockUserRepository.update.mockResolvedValue({ affected: 1 });

      const result = await dataDeletionService.requestDeletion(userId);

      expect(result.userId).toBe(userId);
      expect(result.status).toBe('pending');
      expect(mockAuditService.logAction).toHaveBeenCalledWith(
        'DELETION_REQUESTED',
        userId,
        userId,
        expect.any(Object)
      );
    });
  });

  describe('ConsentManagementService', () => {
    it('should be defined', () => {
      expect(consentManagementService).toBeDefined();
    });

    it('should grant consent', async () => {
      const userId = 'test-user-id';
      const consentData = {
        consentType: ConsentType.DATA_PROCESSING,
        granted: true,
      };
      
      mockConsentRepository.findOne.mockResolvedValue(null);
      mockConsentRepository.create.mockReturnValue({
        id: 'consent-id',
        userId,
        consentType: 'data_processing',
        status: 'granted',
      });
      mockConsentRepository.save.mockResolvedValue({
        id: 'consent-id',
        userId,
        consentType: 'data_processing',
        status: 'granted',
      });

      const result = await consentManagementService.grantConsent(userId, consentData);

      expect(result.status).toBe('granted');
      expect(mockAuditService.logAction).toHaveBeenCalledWith(
        'CONSENT_GRANTED',
        userId,
        expect.any(String),
        expect.any(Object)
      );
    });
  });

  describe('DataRetentionService', () => {
    it('should be defined', () => {
      expect(dataRetentionService).toBeDefined();
    });

    it('should get retention policies', async () => {
      const result = await dataRetentionService.getRetentionPolicies();

      expect(result).toHaveLength(4);
      expect(result[0].entity).toBe('audit_logs');
      expect(result[0].retentionDays).toBe(730);
    });
  });
});