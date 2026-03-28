import { Test, TestingModule } from '@nestjs/testing';
import { RegulatoryArbitrageDetectionService } from '../services/regulatory-arbitrage-detection.service';
import { JurisdictionInferenceService } from '../services/jurisdiction-inference.service';
import { PatternRecognitionService } from '../services/pattern-recognition.service';
import { CrossBorderFlowAnalysisService } from '../services/cross-border-flow-analysis.service';
import { EvasionTechniqueLibraryService } from '../services/evasion-technique-library.service';
import { DetectionRulesEngineService } from '../services/detection-rules-engine.service';
import { AlertingReportingService } from '../services/alerting-reporting.service';
import { ComplianceTeamIntegrationService } from '../services/compliance-team-integration.service';
import { TaxAuthorityCollaborationService } from '../services/tax-authority-collaboration.service';
import { 
  JurisdictionProfile,
  UserBehavior,
  CrossBorderFlow,
  EvasionTechnique,
  ComplianceAlert,
  RiskLevel,
  AlertType,
  TransactionType,
  FlowPurpose
} from '../interfaces/regulatory-arbitrage.interface';

describe('RegulatoryArbitrageDetectionService', () => {
  let service: RegulatoryArbitrageDetectionService;
  let jurisdictionInference: jest.Mocked<JurisdictionInferenceService>;
  let patternRecognition: jest.Mocked<PatternRecognitionService>;
  let crossBorderFlowAnalysis: jest.Mocked<CrossBorderFlowAnalysisService>;
  let evasionTechniqueLibrary: jest.Mocked<EvasionTechniqueLibraryService>;
  let detectionRulesEngine: jest.Mocked<DetectionRulesEngineService>;
  let alertingReporting: jest.Mocked<AlertingReportingService>;
  let complianceTeamIntegration: jest.Mocked<ComplianceTeamIntegrationService>;
  let taxAuthorityCollaboration: jest.Mocked<TaxAuthorityCollaborationService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RegulatoryArbitrageDetectionService,
        {
          provide: JurisdictionInferenceService,
          useValue: {
            inferJurisdiction: jest.fn(),
          } as any,
        },
        {
          provide: PatternRecognitionService,
          useValue: {
            analyzeUserBehavior: jest.fn(),
          } as any,
        },
        {
          provide: CrossBorderFlowAnalysisService,
          useValue: {
            analyzeCrossBorderFlows: jest.fn(),
          } as any,
        },
        {
          provide: EvasionTechniqueLibraryService,
          useValue: {
            detectEvasionTechniques: jest.fn(),
          } as any,
        },
        {
          provide: DetectionRulesEngineService,
          useValue: {
            evaluateUser: jest.fn(),
          } as any,
        },
        {
          provide: AlertingReportingService,
          useValue: {
            createAlert: jest.fn(),
            getAlerts: jest.fn(),
          } as any,
        },
        {
          provide: ComplianceTeamIntegrationService,
          useValue: {
            assignAlert: jest.fn(),
            getTeamPerformance: jest.fn(),
          } as any,
        },
        {
          provide: TaxAuthorityCollaborationService,
          useValue: {
            reportToTaxAuthority: jest.fn(),
            syncWithTaxAuthority: jest.fn(),
          } as any,
        },
      ],
    }).compile();

    service = module.get<RegulatoryArbitrageDetectionService>(RegulatoryArbitrageDetectionService);
    jurisdictionInference = module.get(JurisdictionInferenceService);
    patternRecognition = module.get(PatternRecognitionService);
    crossBorderFlowAnalysis = module.get(CrossBorderFlowAnalysisService);
    evasionTechniqueLibrary = module.get(EvasionTechniqueLibraryService);
    detectionRulesEngine = module.get(DetectionRulesEngineService);
    alertingReporting = module.get(AlertingReportingService);
    complianceTeamIntegration = module.get(ComplianceTeamIntegrationService);
    taxAuthorityCollaboration = module.get(TaxAuthorityCollaborationService);
  });

  describe('analyzeUser', () => {
    it('should perform comprehensive user analysis', async () => {
      // Arrange
      const userId = 'user_123';
      const ipAddress = '192.168.1.1';
      const userAgent = 'Mozilla/5.0...';
      const behavior = createMockUserBehavior();
      const transactions = createMockTransactions();
      const networkData = createMockNetworkData();
      const deviceData = createMockDeviceData();

      const mockJurisdictionInference = createMockJurisdictionInference();
      const mockPatternAnalysis = createMockPatternAnalysis();
      const mockFlowAnalysis = createMockFlowAnalysis();
      const mockEvasionDetection = createMockEvasionDetection();
      const mockRuleEvaluation = createMockRuleEvaluation();

      jurisdictionInference.inferJurisdiction.mockResolvedValue(mockJurisdictionInference);
      patternRecognition.analyzeUserBehavior.mockResolvedValue(mockPatternAnalysis);
      crossBorderFlowAnalysis.analyzeCrossBorderFlows.mockResolvedValue(mockFlowAnalysis);
      evasionTechniqueLibrary.detectEvasionTechniques.mockResolvedValue(mockEvasionDetection);
      detectionRulesEngine.evaluateUser.mockResolvedValue(mockRuleEvaluation);

      // Act
      const result = await service.analyzeUser(
        userId,
        ipAddress,
        userAgent,
        behavior,
        transactions,
        networkData,
        deviceData
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.userId).toBe(userId);
      expect(result.jurisdictionInference).toEqual(mockJurisdictionInference);
      expect(result.patternAnalysis).toEqual(mockPatternAnalysis);
      expect(result.flowAnalysis).toEqual(mockFlowAnalysis);
      expect(result.evasionDetection).toEqual(mockEvasionDetection);
      expect(result.ruleEvaluation).toEqual(mockRuleEvaluation);
      expect(result.overallRiskScore).toBeGreaterThan(0);
      expect(result.recommendations).toBeDefined();
      expect(result.alerts).toBeDefined();

      expect(jurisdictionInference.inferJurisdiction).toHaveBeenCalledWith(
        userId,
        ipAddress,
        userAgent,
        behavior
      );
      expect(patternRecognition.analyzeUserBehavior).toHaveBeenCalledWith(behavior);
      expect(crossBorderFlowAnalysis.analyzeCrossBorderFlows).toHaveBeenCalledWith(
        userId,
        transactions
      );
      expect(evasionTechniqueLibrary.detectEvasionTechniques).toHaveBeenCalledWith(
        behavior,
        transactions,
        networkData,
        deviceData
      );
      expect(detectionRulesEngine.evaluateUser).toHaveBeenCalledWith(
        userId,
        behavior,
        transactions,
        networkData,
        deviceData
      );
    });

    it('should handle analysis errors gracefully', async () => {
      // Arrange
      const userId = 'user_123';
      const error = new Error('Analysis failed');
      
      jurisdictionInference.inferJurisdiction.mockRejectedValue(error);

      // Act
      const result = await service.analyzeUser(
        userId,
        '192.168.1.1',
        'Mozilla/5.0...',
        createMockUserBehavior(),
        createMockTransactions(),
        createMockNetworkData(),
        createMockDeviceData()
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.errors).toContain(error.message);
      expect(result.success).toBe(false);
    });
  });

  describe('detectRegulatoryArbitrage', () => {
    it('should detect regulatory arbitrage patterns', async () => {
      // Arrange
      const userId = 'user_123';
      const transactions = createMockTransactions();
      const mockFlowAnalysis = createMockFlowAnalysis();
      const mockArbitrageDetections = createMockArbitrageDetections();

      crossBorderFlowAnalysis.analyzeCrossBorderFlows.mockResolvedValue(mockFlowAnalysis);

      // Act
      const result = await service.detectRegulatoryArbitrage(userId, transactions);

      // Assert
      expect(result).toBeDefined();
      expect(result.detected).toBe(mockArbitrageDetections.length > 0);
      expect(result.arbitrageTypes).toContain('regulatory');
      expect(result.riskScore).toBeGreaterThan(50);
      expect(result.evidence).toBeDefined();
      expect(result.recommendations).toBeDefined();
    });

    it('should identify jurisdiction shopping', async () => {
      // Arrange
      const transactions = createJurisdictionShoppingTransactions();
      const mockFlowAnalysis = createMockFlowAnalysis();

      crossBorderFlowAnalysis.analyzeCrossBorderFlows.mockResolvedValue(mockFlowAnalysis);

      // Act
      const result = await service.detectRegulatoryArbitrage('user_123', transactions);

      // Assert
      expect(result.detected).toBe(true);
      expect(result.arbitrageTypes).toContain('jurisdiction_shopping');
      expect(result.jurisdictions.length).toBeGreaterThan(2);
    });

    it('should identify treaty shopping', async () => {
      // Arrange
      const transactions = createTreatyShoppingTransactions();
      const mockFlowAnalysis = createMockFlowAnalysis();

      crossBorderFlowAnalysis.analyzeCrossBorderFlows.mockResolvedValue(mockFlowAnalysis);

      // Act
      const result = await service.detectRegulatoryArbitrage('user_123', transactions);

      // Assert
      expect(result.detected).toBe(true);
      expect(result.arbitrageTypes).toContain('treaty_shopping');
      expect(result.treatyExploitation).toBeDefined();
    });
  });

  describe('generateComplianceReport', () => {
    it('should generate comprehensive compliance report', async () => {
      // Arrange
      const filters = {
        dateRange: {
          start: new Date('2023-01-01'),
          end: new Date('2023-12-31')
        },
        severity: RiskLevel.HIGH
      };

      const mockAlerts = createMockAlerts();
      const mockReport = createMockComplianceReport();

      alertingReporting.getAlerts.mockResolvedValue({
        alerts: mockAlerts,
        totalCount: mockAlerts.length,
        filteredCount: mockAlerts.filter(a => a.severity === RiskLevel.HIGH).length
      });

      alertingReporting.generateComplianceReport.mockResolvedValue(mockReport);

      // Act
      const result = await service.generateComplianceReport(filters);

      // Assert
      expect(result).toBeDefined();
      expect(result.reportId).toBeDefined();
      expect(result.generatedAt).toBeInstanceOf(Date);
      expect(result.summary).toBeDefined();
      expect(result.details).toBeDefined();
      expect(result.recommendations).toBeDefined();

      expect(alertingReporting.getAlerts).toHaveBeenCalledWith(filters);
      expect(alertingReporting.generateComplianceReport).toHaveBeenCalled();
    });

    it('should handle report generation errors', async () => {
      // Arrange
      const filters = { severity: RiskLevel.CRITICAL };
      const error = new Error('Report generation failed');
      
      alertingReporting.generateComplianceReport.mockRejectedValue(error);

      // Act
      const result = await service.generateComplianceReport(filters);

      // Assert
      expect(result).toBeDefined();
      expect(result.errors).toContain(error.message);
      expect(result.success).toBe(false);
    });
  });

  describe('escalateAlert', () => {
    it('should escalate high-priority alerts', async () => {
      // Arrange
      const alertId = 'alert_123';
      const reason = 'Critical regulatory arbitrage detected';
      const escalatedTo = 'senior_compliance_officer';

      const mockAlert = createMockAlert();
      mockAlert.severity = RiskLevel.CRITICAL;

      alertingReporting.getAlertDetails.mockResolvedValue(mockAlert);
      complianceTeamIntegration.escalateAlert.mockResolvedValue({
        success: true,
        escalatedTo
      });

      // Act
      const result = await service.escalateAlert(alertId, reason);

      // Assert
      expect(result).toBeDefined();
      expect(result.success).toBe(true);
      expect(result.escalatedTo).toBe(escalatedTo);
      expect(result.escalatedAt).toBeInstanceOf(Date);

      expect(alertingReporting.getAlertDetails).toHaveBeenCalledWith(alertId);
      expect(complianceTeamIntegration.escalateAlert).toHaveBeenCalledWith(
        alertId,
        reason,
        escalatedTo
      );
    });

    it('should not escalate low-priority alerts', async () => {
      // Arrange
      const alertId = 'alert_123';
      const reason = 'Low risk activity';

      const mockAlert = createMockAlert();
      mockAlert.severity = RiskLevel.LOW;

      alertingReporting.getAlertDetails.mockResolvedValue(mockAlert);

      // Act
      const result = await service.escalateAlert(alertId, reason);

      // Assert
      expect(result).toBeDefined();
      expect(result.success).toBe(false);
      expect(result.reason).toContain('Alert severity too low for escalation');
    });
  });

  describe('reportToTaxAuthority', () => {
    it('should report to appropriate tax authority', async () => {
      // Arrange
      const authority = 'IRS';
      const alerts = createMockAlerts();
      const evidencePackage = createMockEvidencePackage();

      const mockSubmission = {
        success: true,
        reportId: 'report_123',
        submittedAt: new Date()
      };

      taxAuthorityCollaboration.reportToTaxAuthority.mockResolvedValue(mockSubmission);

      // Act
      const result = await service.reportToTaxAuthority(
        authority,
        alerts,
        evidencePackage
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.success).toBe(true);
      expect(result.reportId).toBe('report_123');
      expect(result.submittedAt).toBeInstanceOf(Date);

      expect(taxAuthorityCollaboration.reportToTaxAuthority).toHaveBeenCalledWith(
        authority,
        alerts,
        evidencePackage,
        'daily'
      );
    });

    it('should handle tax authority reporting errors', async () => {
      // Arrange
      const authority = 'IRS';
      const alerts = createMockAlerts();
      const evidencePackage = createMockEvidencePackage();
      const error = new Error('Tax authority API error');

      taxAuthorityCollaboration.reportToTaxAuthority.mockRejectedValue(error);

      // Act
      const result = await service.reportToTaxAuthority(
        authority,
        alerts,
        evidencePackage
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.success).toBe(false);
      expect(result.error).toBe(error.message);
    });
  });

  describe('getSystemHealth', () => {
    it('should return system health status', async () => {
      // Arrange
      const mockJurisdictionHealth = { status: 'healthy', responseTime: 150 };
      const mockPatternHealth = { status: 'healthy', accuracy: 0.95 };
      const mockFlowHealth = { status: 'healthy', processedFlows: 1000 };
      const mockEvasionHealth = { status: 'healthy', techniquesDetected: 50 };
      const mockRulesHealth = { status: 'healthy', activeRules: 25 };
      const mockAlertHealth = { status: 'healthy', activeAlerts: 10 };
      const mockTeamHealth = { status: 'healthy', availableMembers: 8 };
      const mockTaxHealth = { status: 'healthy', lastSync: new Date() };

      jurisdictionInference.getHealthStatus.mockResolvedValue(mockJurisdictionHealth);
      patternRecognition.getHealthStatus.mockResolvedValue(mockPatternHealth);
      crossBorderFlowAnalysis.getHealthStatus.mockResolvedValue(mockFlowHealth);
      evasionTechniqueLibrary.getHealthStatus.mockResolvedValue(mockEvasionHealth);
      detectionRulesEngine.getHealthStatus.mockResolvedValue(mockRulesHealth);
      alertingReporting.getHealthStatus.mockResolvedValue(mockAlertHealth);
      complianceTeamIntegration.getHealthStatus.mockResolvedValue(mockTeamHealth);
      taxAuthorityCollaboration.getHealthStatus.mockResolvedValue(mockTaxHealth);

      // Act
      const result = await service.getSystemHealth();

      // Assert
      expect(result).toBeDefined();
      expect(result.overallStatus).toBe('healthy');
      expect(result.services).toBeDefined();
      expect(result.services.jurisdictionInference).toEqual(mockJurisdictionHealth);
      expect(result.services.patternRecognition).toEqual(mockPatternHealth);
      expect(result.services.crossBorderFlowAnalysis).toEqual(mockFlowHealth);
      expect(result.services.evasionTechniqueLibrary).toEqual(mockEvasionHealth);
      expect(result.services.detectionRulesEngine).toEqual(mockRulesHealth);
      expect(result.services.alertingReporting).toEqual(mockAlertHealth);
      expect(result.services.complianceTeamIntegration).toEqual(mockTeamHealth);
      expect(result.services.taxAuthorityCollaboration).toEqual(mockTaxHealth);
      expect(result.lastCheck).toBeInstanceOf(Date);
    });
  });

  // Helper functions to create mock data
  function createMockUserBehavior(): UserBehavior {
    return {
      userId: 'user_123',
      sessionId: 'session_456',
      loginPattern: {
        frequency: 5,
        timeDistribution: [9, 10, 14, 15, 16, 17, 18],
        locations: [],
        devices: [],
        methods: ['password', '2fa'],
        riskScore: 25
      },
      transactionPattern: {
        volume: 50000,
        frequency: 10,
        averageAmount: 5000,
        amounts: [1000, 2000, 3000, 4000, 5000],
        currencies: ['USD', 'EUR'],
        destinations: ['account_1', 'account_2'],
        timeDistribution: [9, 10, 14, 15, 16],
        roundTripping: false,
        structuring: false,
        riskScore: 40
      },
      navigationPattern: {
        pages: ['/dashboard', '/transactions', '/profile'],
        flowSequences: [['/dashboard', '/transactions'], ['/transactions', '/profile']],
        timeOnPage: [30, 45, 60],
        scrollPatterns: [],
        clickPatterns: [],
        riskScore: 15
      },
      timePattern: {
        activeHours: [{ start: '09:00', end: '17:00' }],
        timezone: 'America/New_York',
        sessionDuration: 1800,
        activityBursts: [],
        riskScore: 20
      },
      riskIndicators: [],
      behaviorScore: 35,
      anomalies: []
    };
  }

  function createMockTransactions(): any[] {
    return [
      {
        id: 'tx_1',
        userId: 'user_123',
        amount: 1000,
        currency: 'USD',
        source: 'account_1',
        destination: 'account_2',
        type: TransactionType.TRANSFER,
        timestamp: new Date(),
        sourceJurisdiction: 'US',
        targetJurisdiction: 'GB'
      },
      {
        id: 'tx_2',
        userId: 'user_123',
        amount: 2000,
        currency: 'EUR',
        source: 'account_2',
        destination: 'account_3',
        type: TransactionType.EXCHANGE,
        timestamp: new Date(),
        sourceJurisdiction: 'GB',
        targetJurisdiction: 'DE'
      }
    ];
  }

  function createMockNetworkData(): any {
    return {
      ipAddress: '192.168.1.1',
      country: 'US',
      region: 'California',
      city: 'San Francisco',
      vpn: false,
      proxy: false,
      tor: false,
      privacyTools: []
    };
  }

  function createMockDeviceData(): any {
    return {
      fingerprint: 'device_fp_123',
      privacyTools: [],
      virtualization: false,
      mobile: false
    };
  }

  function createMockJurisdictionInference(): any {
    return {
      userId: 'user_123',
      primaryJurisdiction: {
        id: 'us',
        name: 'United States',
        isoCode: 'US',
        region: 'North America',
        regulatoryFramework: 'complex',
        taxJurisdiction: true,
        riskLevel: RiskLevel.MEDIUM
      } as JurisdictionProfile,
      confidenceScores: {
        geolocation: 0.8,
        device: 0.7,
        behavior: 0.6,
        overall: 0.7
      },
      riskScore: 35
    };
  }

  function createMockPatternAnalysis(): any {
    return {
      riskScore: 45,
      riskIndicators: [
        {
          type: 'unusual_login_pattern',
          severity: RiskLevel.MEDIUM,
          confidence: 0.7,
          description: 'Unusual login pattern detected'
        }
      ],
      anomalies: [],
      patternMatches: [],
      suspiciousActivities: []
    };
  }

  function createMockFlowAnalysis(): any {
    return {
      arbitrageDetections: [
        {
          id: 'arb_1',
          userId: 'user_123',
          type: 'regulatory',
          jurisdictions: ['US', 'GB'],
          transactions: ['tx_1', 'tx_2'],
          amount: 3000,
          currency: 'USD',
          profit: 500,
          riskScore: 75,
          detected: new Date()
        }
      ],
      suspiciousFlows: [],
      riskScore: 75,
      analysis: {
        totalFlows: 2,
        crossBorderTransactions: 2,
        uniqueJurisdictions: ['US', 'GB', 'DE'],
        averageRiskScore: 60,
        arbitrageOpportunities: 1
      }
    };
  }

  function createMockEvasionDetection(): any {
    return {
      detectedTechniques: [
        {
          id: 'privacy_obfuscation',
          name: 'Privacy Obfuscation',
          category: 'privacy_obfuscation',
          riskScore: 60,
          severity: RiskLevel.MEDIUM
        } as EvasionTechnique
      ],
      riskScore: 60,
      recommendations: [
        {
          type: 'enhanced_monitoring',
          priority: 'medium',
          description: 'Implement enhanced monitoring'
        }
      ]
    };
  }

  function createMockRuleEvaluation(): any {
    return {
      triggeredRules: [
        {
          id: 'rule_1',
          name: 'Privacy Tool Detection',
          weight: 0.7,
          enabled: true
        }
      ],
      riskScore: 70,
      recommendations: [
        {
          type: 'investigation',
          priority: 'high',
          description: 'Conduct investigation'
        }
      ],
      alerts: []
    };
  }

  function createMockAlerts(): ComplianceAlert[] {
    return [
      {
        id: 'alert_1',
        userId: 'user_123',
        type: AlertType.REGULATORY_ARBITRAGE,
        severity: RiskLevel.HIGH,
        title: 'Regulatory Arbitrage Detected',
        description: 'User engaged in regulatory arbitrage',
        evidence: {} as any,
        jurisdiction: 'US',
        regulations: ['AML', 'KYC'],
        recommendations: [],
        detected: new Date(),
        status: 'open'
      } as ComplianceAlert,
      {
        id: 'alert_2',
        userId: 'user_456',
        type: AlertType.TAX_EVASION,
        severity: RiskLevel.CRITICAL,
        title: 'Tax Evasion Suspected',
        description: 'User attempted tax evasion',
        evidence: {} as any,
        jurisdiction: 'GB',
        regulations: ['Tax Law'],
        recommendations: [],
        detected: new Date(),
        status: 'open'
      } as ComplianceAlert
    ];
  }

  function createMockComplianceReport(): any {
    return {
      reportId: 'report_123',
      generatedAt: new Date(),
      summary: {
        totalAlerts: 10,
        severityBreakdown: {
          [RiskLevel.LOW]: 2,
          [RiskLevel.MEDIUM]: 3,
          [RiskLevel.HIGH]: 4,
          [RiskLevel.CRITICAL]: 1
        },
        typeBreakdown: {
          [AlertType.REGULATORY_ARBITRAGE]: 3,
          [AlertType.TAX_EVASION]: 2,
          [AlertType.JURISDICTION_JUMPING]: 5
        }
      },
      details: {
        alerts: createMockAlerts(),
        trends: {},
        patterns: {},
        hotspots: {}
      },
      recommendations: [
        {
          type: 'investigation',
          priority: 'high',
          description: 'Investigate high-risk alerts'
        }
      ]
    };
  }

  function createMockAlert(): ComplianceAlert {
    return {
      id: 'alert_123',
      userId: 'user_123',
      type: AlertType.SUSPICIOUS_PATTERN,
      severity: RiskLevel.MEDIUM,
      title: 'Suspicious Pattern',
      description: 'Suspicious activity pattern detected',
      evidence: {} as any,
      jurisdiction: 'US',
      regulations: [],
      recommendations: [],
      detected: new Date(),
      status: 'open'
    } as ComplianceAlert;
  }

  function createJurisdictionShoppingTransactions(): any[] {
    return [
      {
        id: 'tx_1',
        sourceJurisdiction: 'US',
        targetJurisdiction: 'GB',
        amount: 5000,
        timestamp: new Date()
      },
      {
        id: 'tx_2',
        sourceJurisdiction: 'GB',
        targetJurisdiction: 'DE',
        amount: 4500,
        timestamp: new Date()
      },
      {
        id: 'tx_3',
        sourceJurisdiction: 'DE',
        targetJurisdiction: 'US',
        amount: 4800,
        timestamp: new Date()
      }
    ];
  }

  function createTreatyShoppingTransactions(): any[] {
    return [
      {
        id: 'tx_1',
        sourceJurisdiction: 'US',
        targetJurisdiction: 'IE',
        amount: 10000,
        timestamp: new Date(),
        treatyBenefit: 'US-IE tax treaty'
      },
      {
        id: 'tx_2',
        sourceJurisdiction: 'IE',
        targetJurisdiction: 'US',
        amount: 9500,
        timestamp: new Date(),
        treatyBenefit: 'US-IE tax treaty'
      }
    ];
  }

  function createMockEvidencePackage(): any {
    return {
      transactionIds: ['tx_1', 'tx_2'],
      ipAddresses: ['192.168.1.1', '10.0.0.1'],
      deviceFingerprints: ['fp_1', 'fp_2'],
      behavioralData: {},
      crossBorderFlows: [],
      evasionTechniques: [],
      riskScores: [],
      timestamps: [new Date()],
      screenshots: [],
      logs: ['log_1', 'log_2']
    };
  }
});
