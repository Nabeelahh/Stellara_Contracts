import { 
  Controller, 
  Get, 
  Post, 
  Body, 
  Param, 
  Query,
  HttpCode,
  HttpStatus
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiQuery } from '@nestjs/swagger';
import { 
  Agent,
  AgentType,
  UtilityType,
  MarketConditions,
  AgentState,
  NegotiationTerms,
  RLModel,
  SimulationEnvironment,
  EthicalReport
} from '../interfaces/agent.interface';
import { AutonomousAgentService } from '../services/autonomous-agent.service';
import { UtilityFunctionService } from '../services/utility-function.service';
import { NegotiationService } from '../services/negotiation.service';
import { GameTheoryService } from '../services/game-theory.service';
import { ReinforcementLearningService } from '../services/reinforcement-learning.service';
import { SimulationService } from '../services/simulation.service';
import { ExplainableAIService } from '../services/explainable-ai.service';
import { EthicalGuardrailsService } from '../services/ethical-guardrails.service';
import { SmartContractIntegrationService } from '../services/smart-contract-integration.service';

@ApiTags('Autonomous Agents')
@Controller('autonomous-agents')
export class AutonomousAgentController {
  constructor(
    private readonly agentService: AutonomousAgentService,
    private readonly utilityFunctionService: UtilityFunctionService,
    private readonly negotiationService: NegotiationService,
    private readonly gameTheoryService: GameTheoryService,
    private readonly rlService: ReinforcementLearningService,
    private readonly simulationService: SimulationService,
    private readonly explainableAIService: ExplainableAIService,
    private readonly ethicalGuardrailsService: EthicalGuardrailsService,
    private readonly smartContractService: SmartContractIntegrationService,
  ) {}

  @Post('agents')
  @ApiOperation({ summary: 'Create a new autonomous agent' })
  @ApiResponse({ status: 201, description: 'Agent created successfully' })
  async createAgent(@Body() createAgentDto: {
    name: string;
    type: AgentType;
    utilityFunction: any;
    initialResources: any[];
    config: any;
  }): Promise<Agent> {
    const utilityFunction = await this.utilityFunctionService.createUtilityFunction(
      createAgentDto.utilityFunction.name,
      createAgentDto.utilityFunction.type,
      createAgentDto.utilityFunction.parameters,
      createAgentDto.utilityFunction.weights,
      createAgentDto.utilityFunction.constraints,
      createAgentDto.utilityFunction.optimizationTarget
    );

    return this.agentService.createAgent(
      createAgentDto.name,
      createAgentDto.type,
      utilityFunction,
      createAgentDto.initialResources,
      createAgentDto.config
    );
  }

  @Get('agents')
  @ApiOperation({ summary: 'Get all autonomous agents' })
  @ApiResponse({ status: 200, description: 'Agents retrieved successfully' })
  async getAllAgents(): Promise<Agent[]> {
    return this.agentService.getAllAgents();
  }

  @Get('agents/:id')
  @ApiOperation({ summary: 'Get agent by ID' })
  @ApiParam({ name: 'id', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Agent retrieved successfully' })
  async getAgent(@Param('id') id: string): Promise<Agent | null> {
    return this.agentService.getAgent(id);
  }

  @Get('agents/:id/state')
  @ApiOperation({ summary: 'Get agent current state' })
  @ApiParam({ name: 'id', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Agent state retrieved successfully' })
  async getAgentState(@Param('id') id: string): Promise<AgentState | null> {
    return this.agentService.getAgentState(id);
  }

  @Post('agents/:id/decide')
  @ApiOperation({ summary: 'Make decision for agent' })
  @ApiParam({ name: 'id', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Decision made successfully' })
  async makeDecision(
    @Param('id') id: string,
    @Body() decisionDto: {
      marketConditions: MarketConditions;
      availableActions: string[];
    }
  ): Promise<{
    action: string;
    confidence: number;
    rationale: any;
  }> {
    return this.agentService.makeDecision(
      id,
      decisionDto.marketConditions,
      decisionDto.availableActions
    );
  }

  @Post('agents/:id/execute')
  @ApiOperation({ summary: 'Execute action for agent' })
  @ApiParam({ name: 'id', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Action executed successfully' })
  async executeAction(
    @Param('id') id: string,
    @Body() executionDto: {
      action: string;
      marketConditions: MarketConditions;
    }
  ): Promise<{
    success: boolean;
    newState: AgentState;
    executionDetails: any;
  }> {
    return this.agentService.executeAction(
      id,
      executionDto.action,
      executionDto.marketConditions
    );
  }

  @Post('agents/:id/negotiate')
  @ApiOperation({ summary: 'Initiate negotiation for agent' })
  @ApiParam({ name: 'id', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Negotiation initiated successfully' })
  async negotiate(
    @Param('id') id: string,
    @Body() negotiationDto: {
      counterpartyId: string;
      terms: NegotiationTerms;
      protocol: string;
    }
  ): Promise<{
    success: boolean;
    result?: any;
  }> {
    return this.agentService.negotiate(
      id,
      negotiationDto.counterpartyId,
      negotiationDto.terms,
      negotiationDto.protocol
    );
  }

  @Post('agents/:id/learn')
  @ApiOperation({ summary: 'Update agent learning from experience' })
  @ApiParam({ name: 'id', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Learning updated successfully' })
  async learn(
    @Param('id') id: string,
    @Body() experienceDto: {
      experience: any;
    }
  ): Promise<void> {
    return this.agentService.learn(id, experienceDto.experience);
  }

  @Post('agents/:id/reputation')
  @ApiOperation({ summary: 'Update agent reputation' })
  @ApiParam({ name: 'id', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Reputation updated successfully' })
  async updateReputation(
    @Param('id') id: string,
    @Body() reputationDto: {
      change: number;
    }
  ): Promise<void> {
    return this.agentService.updateAgentReputation(id, reputationDto.change);
  }

  @Post('agents/:id/deactivate')
  @ApiOperation({ summary: 'Deactivate agent' })
  @ApiParam({ name: 'id', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Agent deactivated successfully' })
  async deactivateAgent(@Param('id') id: string): Promise<void> {
    return this.agentService.deactivateAgent(id);
  }

  @Post('agents/:id/reactivate')
  @ApiOperation({ summary: 'Reactivate agent' })
  @ApiParam({ name: 'id', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Agent reactivated successfully' })
  async reactivateAgent(@Param('id') id: string): Promise<void> {
    return this.agentService.reactivateAgent(id);
  }

  // Utility Function Endpoints
  @Post('utility-functions')
  @ApiOperation({ summary: 'Create utility function' })
  @ApiResponse({ status: 201, description: 'Utility function created successfully' })
  async createUtilityFunction(@Body() createUtilityDto: {
    name: string;
    type: UtilityType;
    parameters: any[];
    weights: number[];
    constraints: any[];
    optimizationTarget: string;
  }): Promise<any> {
    return this.utilityFunctionService.createUtilityFunction(
      createUtilityDto.name,
      createUtilityDto.type,
      createUtilityDto.parameters,
      createUtilityDto.weights,
      createUtilityDto.constraints,
      createUtilityDto.optimizationTarget
    );
  }

  @Post('utility-functions/:agentId/calculate')
  @ApiOperation({ summary: 'Calculate utility for agent' })
  @ApiParam({ name: 'agentId', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Utility calculated successfully' })
  async calculateUtility(
    @Param('agentId') agentId: string,
    @Body() utilityDto: {
      state: AgentState;
      marketConditions: MarketConditions;
    }
  ): Promise<number> {
    const agent = this.agentService.getAgent(agentId);
    if (!agent) {
      throw new Error('Agent not found');
    }

    return this.utilityFunctionService.calculateUtility(agent, utilityDto.state, utilityDto.marketConditions);
  }

  // Negotiation Endpoints
  @Post('negotiations')
  @ApiOperation({ summary: 'Initiate negotiation' })
  @ApiResponse({ status: 201, description: 'Negotiation initiated successfully' })
  async initiateNegotiation(@Body() negotiationDto: {
    initiatorId: string;
    participantId: string;
    type: string;
    protocol: string;
    initialTerms: NegotiationTerms;
  }): Promise<any> {
    return this.negotiationService.initiateNegotiation(
      negotiationDto.initiatorId,
      negotiationDto.participantId,
      negotiationDto.type as any,
      negotiationDto.protocol as any,
      negotiationDto.initialTerms
    );
  }

  @Get('negotiations/:agentId')
  @ApiOperation({ summary: 'Get active negotiations for agent' })
  @ApiParam({ name: 'agentId', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Negotiations retrieved successfully' })
  async getAgentNegotiations(@Param('agentId') agentId: string): Promise<any[]> {
    return this.negotiationService.getActiveNegotiations(agentId);
  }

  @Get('negotiations/:agentId/history')
  @ApiOperation({ summary: 'Get negotiation history for agent' })
  @ApiParam({ name: 'agentId', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Negotiation history retrieved successfully' })
  async getNegotiationHistory(@Param('agentId') agentId: string): Promise<any[]> {
    return this.negotiationService.getNegotiationHistory(agentId);
  }

  // Game Theory Endpoints
  @Post('game-theory/scenarios')
  @ApiOperation({ summary: 'Create game theory scenario' })
  @ApiResponse({ status: 201, description: 'Scenario created successfully' })
  async createGameTheoryScenario(@Body() scenarioDto: {
    name: string;
    type: string;
    players: string[];
    payoffMatrix: any;
  }): Promise<any> {
    return this.gameTheoryService.createGameTheoryScenario(
      scenarioDto.name,
      scenarioDto.type as any,
      scenarioDto.players,
      scenarioDto.payoffMatrix
    );
  }

  @Post('game-theory/:scenarioId/nash-equilibrium')
  @ApiOperation({ summary: 'Find Nash equilibrium' })
  @ApiParam({ name: 'scenarioId', description: 'Scenario ID' })
  @ApiResponse({ status: 200, description: 'Nash equilibrium calculated successfully' })
  async findNashEquilibrium(@Param('scenarioId') scenarioId: string): Promise<any[]> {
    // This would fetch scenario and calculate equilibrium
    return this.gameTheoryService.findNashEquilibrium({} as any);
  }

  // Reinforcement Learning Endpoints
  @Post('rl/models')
  @ApiOperation({ summary: 'Create RL model' })
  @ApiResponse({ status: 201, description: 'RL model created successfully' })
  async createRLModel(@Body() modelDto: {
    agentId: string;
    algorithm: string;
    hyperparameters: any;
  }): Promise<RLModel> {
    return this.rlService.createRLModel(
      modelDto.agentId,
      modelDto.algorithm as any,
      modelDto.hyperparameters
    );
  }

  @Post('rl/models/:modelId/train')
  @ApiOperation({ summary: 'Train RL model' })
  @ApiParam({ name: 'modelId', description: 'Model ID' })
  @ApiResponse({ status: 200, description: 'Model trained successfully' })
  async trainRLModel(
    @Param('modelId') modelId: string,
    @Body() trainingDto: {
      experiences: any[];
      epochs: number;
    }
  ): Promise<any> {
    return this.rlService.trainModel(modelId, trainingDto.experiences, trainingDto.epochs);
  }

  @Post('rl/models/:modelId/select-action')
  @ApiOperation({ summary: 'Select action using RL model' })
  @ApiParam({ name: 'modelId', description: 'Model ID' })
  @ApiResponse({ status: 200, description: 'Action selected successfully' })
  async selectAction(
    @Param('modelId') modelId: string,
    @Body() actionDto: {
      state: number[];
      availableActions: string[];
    }
  ): Promise<{ action: string; confidence: number }> {
    return this.rlService.selectAction(modelId, actionDto.state, actionDto.availableActions);
  }

  // Simulation Endpoints
  @Post('simulations')
  @ApiOperation({ summary: 'Create simulation environment' })
  @ApiResponse({ status: 201, description: 'Simulation created successfully' })
  async createSimulation(@Body() simulationDto: {
    name: string;
    agentIds: string[];
    initialMarketConditions: MarketConditions;
    maxTimeSteps: number;
  }): Promise<SimulationEnvironment> {
    return this.simulationService.createSimulationEnvironment(
      simulationDto.name,
      simulationDto.agentIds,
      simulationDto.initialMarketConditions,
      simulationDto.maxTimeSteps
    );
  }

  @Post('simulations/:simulationId/run')
  @ApiOperation({ summary: 'Run simulation' })
  @ApiParam({ name: 'simulationId', description: 'Simulation ID' })
  @ApiResponse({ status: 200, description: 'Simulation completed successfully' })
  async runSimulation(
    @Param('simulationId') simulationId: string,
    @Body() runDto: { realTime?: boolean }
  ): Promise<any[]> {
    return this.simulationService.runSimulation(simulationId, runDto.realTime);
  }

  @Get('simulations/:simulationId/metrics')
  @ApiOperation({ summary: 'Get simulation metrics' })
  @ApiParam({ name: 'simulationId', description: 'Simulation ID' })
  @ApiResponse({ status: 200, description: 'Simulation metrics retrieved successfully' })
  async getSimulationMetrics(@Param('simulationId') simulationId: string): Promise<any> {
    return this.simulationService.getSimulationMetrics(simulationId);
  }

  // Explainable AI Endpoints
  @Post('explainable-ai/decision-rationale')
  @ApiOperation({ summary: 'Generate decision rationale' })
  @ApiResponse({ status: 200, description: 'Decision rationale generated successfully' })
  async generateDecisionRationale(@Body() rationaleDto: {
    agentId: string;
    currentState: AgentState;
    proposedAction: string;
    marketConditions: MarketConditions;
    alternatives?: any[];
  }): Promise<any> {
    const agent = this.agentService.getAgent(rationaleDto.agentId);
    if (!agent) {
      throw new Error('Agent not found');
    }

    return this.explainableAIService.generateDecisionRationale(
      agent,
      rationaleDto.currentState,
      rationaleDto.proposedAction,
      rationaleDto.marketConditions,
      rationaleDto.alternatives
    );
  }

  // Ethical Guardrails Endpoints
  @Post('ethical-guardrails/validate')
  @ApiOperation({ summary: 'Validate action against ethical constraints' })
  @ApiResponse({ status: 200, description: 'Action validated successfully' })
  async validateAction(@Body() validationDto: {
    agentId: string;
    proposedAction: string;
    terms: NegotiationTerms;
    marketConditions: MarketConditions;
    currentState: AgentState;
  }): Promise<{
    valid: boolean;
    violations: any[];
    recommendations: string[];
  }> {
    const agent = this.agentService.getAgent(validationDto.agentId);
    if (!agent) {
      throw new Error('Agent not found');
    }

    return this.ethicalGuardrailsService.validateAction(
      agent,
      validationDto.proposedAction,
      validationDto.terms,
      validationDto.marketConditions,
      validationDto.currentState
    );
  }

  @Get('ethical-guardrails/:agentId/report')
  @ApiOperation({ summary: 'Get ethical compliance report' })
  @ApiParam({ name: 'agentId', description: 'Agent ID' })
  @ApiQuery({ name: 'start', description: 'Report start date' })
  @ApiQuery({ name: 'end', description: 'Report end date' })
  @ApiResponse({ status: 200, description: 'Ethical report generated successfully' })
  async getEthicalReport(
    @Param('agentId') agentId: string,
    @Query('start') start: string,
    @Query('end') end: string
  ): Promise<EthicalReport> {
    return this.ethicalGuardrailsService.getEthicalReport(agentId, {
      start: new Date(start),
      end: new Date(end)
    });
  }

  // Smart Contract Integration Endpoints
  @Post('smart-contracts/execute-trade')
  @ApiOperation({ summary: 'Execute trade via smart contract' })
  @ApiResponse({ status: 200, description: 'Trade executed successfully' })
  async executeTrade(@Body() tradeDto: {
    agentId: string;
    terms: NegotiationTerms;
    network?: string;
  }): Promise<any> {
    return this.smartContractService.executeTrade(
      tradeDto.agentId,
      tradeDto.terms,
      tradeDto.network || 'ethereum'
    );
  }

  @Post('smart-contracts/execute-liquidity')
  @ApiOperation({ summary: 'Provide liquidity via smart contract' })
  @ApiResponse({ status: 200, description: 'Liquidity provided successfully' })
  async executeLiquidityProvision(@Body() liquidityDto: {
    agentId: string;
    terms: NegotiationTerms;
    network?: string;
  }): Promise<any> {
    return this.smartContractService.executeLiquidityProvision(
      liquidityDto.agentId,
      liquidityDto.terms,
      liquidityDto.network || 'ethereum'
    );
  }

  @Post('smart-contracts/approve-token')
  @ApiOperation({ summary: 'Approve token for smart contract interaction' })
  @ApiResponse({ status: 200, description: 'Token approved successfully' })
  async approveToken(@Body() approvalDto: {
    agentId: string;
    tokenAddress: string;
    spenderAddress: string;
    amount: string;
    network?: string;
  }): Promise<any> {
    return this.smartContractService.approveToken(
      approvalDto.tokenAddress,
      approvalDto.spenderAddress,
      approvalDto.amount,
      approvalDto.agentId,
      approvalDto.network || 'ethereum'
    );
  }

  @Get('smart-contracts/:txHash/status')
  @ApiOperation({ summary: 'Get transaction status' })
  @ApiParam({ name: 'txHash', description: 'Transaction hash' })
  @ApiResponse({ status: 200, description: 'Transaction status retrieved successfully' })
  async getTransactionStatus(
    @Param('txHash') txHash: string,
    @Query('network') network?: string
  ): Promise<string> {
    return this.smartContractService.getTransactionStatus(txHash, network || 'ethereum');
  }

  @Get('smart-contracts/:contractAddress/balance')
  @ApiOperation({ summary: 'Get contract balance' })
  @ApiParam({ name: 'contractAddress', description: 'Contract address' })
  @ApiParam({ name: 'agentId', description: 'Agent ID' })
  @ApiResponse({ status: 200, description: 'Contract balance retrieved successfully' })
  async getContractBalance(
    @Param('contractAddress') contractAddress: string,
    @Param('agentId') agentId: string,
    @Query('network') network?: string
  ): Promise<string> {
    return this.smartContractService.getContractBalance(contractAddress, agentId, network || 'ethereum');
  }
}
