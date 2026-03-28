import { Module } from '@nestjs/common';
import { RegulatoryArbitrageDetectionController } from './controllers/regulatory-arbitrage.controller';
import { RegulatoryArbitrageDetectionService } from './services/regulatory-arbitrage-detection.service';
import { JurisdictionInferenceService } from './services/jurisdiction-inference.service';
import { PatternRecognitionService } from './services/pattern-recognition.service';
import { CrossBorderFlowAnalysisService } from './services/cross-border-flow-analysis.service';
import { EvasionTechniqueLibraryService } from './services/evasion-technique-library.service';
import { DetectionRulesEngineService } from './services/detection-rules-engine.service';
import { AlertingReportingService } from './services/alerting-reporting.service';
import { ComplianceTeamIntegrationService } from './services/compliance-team-integration.service';
import { TaxAuthorityCollaborationService } from './services/tax-authority-collaboration.service';

@Module({
  controllers: [RegulatoryArbitrageDetectionController],
  providers: [
    RegulatoryArbitrageDetectionService,
    JurisdictionInferenceService,
    PatternRecognitionService,
    CrossBorderFlowAnalysisService,
    EvasionTechniqueLibraryService,
    DetectionRulesEngineService,
    AlertingReportingService,
    ComplianceTeamIntegrationService,
    TaxAuthorityCollaborationService
  ],
  exports: [
    RegulatoryArbitrageDetectionService,
    JurisdictionInferenceService,
    PatternRecognitionService,
    CrossBorderFlowAnalysisService,
    EvasionTechniqueLibraryService,
    DetectionRulesEngineService,
    AlertingReportingService,
    ComplianceTeamIntegrationService,
    TaxAuthorityCollaborationService
  ]
})
export class RegulatoryArbitrageModule {}
