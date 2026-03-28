import { Module } from '@nestjs/common';
import { AutonomousAgentController } from './controllers/autonomous-agent.controller';
import { AutonomousAgentService } from './services/autonomous-agent.service';
import { UtilityFunctionService } from './services/utility-function.service';
import { NegotiationService } from './services/negotiation.service';
import { GameTheoryService } from './services/game-theory.service';
import { ReinforcementLearningService } from './services/reinforcement-learning.service';
import { SimulationService } from './services/simulation.service';
import { ExplainableAIService } from './services/explainable-ai.service';
import { EthicalGuardrailsService } from './services/ethical-guardrails.service';
import { SmartContractIntegrationService } from './services/smart-contract-integration.service';

@Module({
  controllers: [AutonomousAgentController],
  providers: [
    AutonomousAgentService,
    UtilityFunctionService,
    NegotiationService,
    GameTheoryService,
    ReinforcementLearningService,
    SimulationService,
    ExplainableAIService,
    EthicalGuardrailsService,
    SmartContractIntegrationService,
  ],
  exports: [
    AutonomousAgentService,
    UtilityFunctionService,
    NegotiationService,
    GameTheoryService,
    ReinforcementLearningService,
    SimulationService,
    ExplainableAIService,
    EthicalGuardrailsService,
    SmartContractIntegrationService,
  ],
})
export class AutonomousAgentsModule {}
