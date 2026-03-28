import { Test, TestingModule } from '@nestjs/testing';
import { AutonomousAgentService } from '../services/autonomous-agent.service';
import { UtilityFunctionService } from '../services/utility-function.service';
import { NegotiationService } from '../services/negotiation.service';
import { GameTheoryService } from '../services/game-theory.service';
import { ReinforcementLearningService } from '../services/reinforcement-learning.service';
import { SimulationService } from '../services/simulation.service';
import { ExplainableAIService } from '../services/explainable-ai.service';
import { EthicalGuardrailsService } from '../services/ethical-guardrails.service';
import { SmartContractIntegrationService } from '../services/smart-contract-integration.service';
import { 
  Agent,
  AgentType,
  UtilityType,
  MarketConditions,
  AgentState
} from '../interfaces/agent.interface';

describe('AutonomousAgentService', () => {
  let service: AutonomousAgentService;
  let utilityFunctionService: UtilityFunctionService;
  let negotiationService: NegotiationService;
  let gameTheoryService: GameTheoryService;
  let rlService: ReinforcementLearningService;
  let simulationService: SimulationService;
  let explainableAIService: ExplainableAIService;
  let ethicalGuardrailsService: EthicalGuardrailsService;
  let smartContractService: SmartContractIntegrationService;

  beforeEach(async () => {
    const mockUtilityFunctionService = {
      createUtilityFunction: jest.fn(),
      validateUtilityFunction: jest.fn(),
      calculateUtility: jest.fn().mockResolvedValue(0.5)
    };

    const mockNegotiationService = {
      initiateNegotiation: jest.fn().mockResolvedValue({
        id: 'neg_123',
        participants: ['agent1', 'agent2'],
        type: 'trade',
        status: 'initiated',
        protocol: 'alternating_offers',
        messages: [],
        startTime: new Date()
      }),
      sendMessage: jest.fn().mockResolvedValue(undefined),
      getActiveNegotiations: jest.fn().mockReturnValue([])
    };

    const mockGameTheoryService = {
      findNashEquilibrium: jest.fn().mockReturnValue([{
        strategies: { agent1: 'cooperate', agent2: 'cooperate' },
        payoffs: { agent1: 3, agent2: 3 },
        stability: 0.9
      }]),
      createGameTheoryScenario: jest.fn()
    };

    const mockRLService = {
      createRLModel: jest.fn().mockResolvedValue({
        id: 'rl_model_123',
        agentId: 'agent_123',
        algorithm: 'q_learning',
        hyperparameters: {
          learningRate: 0.1,
          discountFactor: 0.95,
          explorationRate: 0.1,
          batchSize: 32,
          targetUpdateFrequency: 100,
          memorySize: 10000
        },
        performance: {
          averageReward: 0.1,
          maxReward: 0.5,
          minReward: -0.2,
          convergenceRate: 0.8,
          explorationRate: 0.1,
          totalEpisodes: 100
        },
        trainingData: [],
        modelState: { type: 'q_table', qTable: [], stateSpace: 100, actionSpace: 10 }
      }),
      selectAction: jest.fn().mockResolvedValue({ action: 'buy', confidence: 0.8 }),
      trainModel: jest.fn().mockResolvedValue({
        averageReward: 0.15,
        maxReward: 0.6,
        minReward: -0.1,
        convergenceRate: 0.85,
        explorationRate: 0.08,
        totalEpisodes: 150
      })
    };

    const mockSimulationService = {
      createSimulationEnvironment: jest.fn().mockResolvedValue({
        id: 'sim_123',
        name: 'Test Simulation',
        agents: ['agent1', 'agent2'],
        marketConditions: {
          price: { 'ETH': 2000, 'USDC': 1 },
          volatility: { 'ETH': 0.2, 'USDC': 0.05 },
          volume: { 'ETH': 1000000, 'USDC': 5000000 },
          liquidity: { 'ETH': 500000, 'USDC': 2000000 },
          interestRates: { 'USDC': 0.05 }
        },
        timeStep: 0,
        maxTimeSteps: 1000,
        currentState: {
          timeStep: 0,
          agentStates: {},
          marketState: {} as MarketConditions,
          transactions: [],
          negotiations: []
        },
        history: []
      }),
      runSimulation: jest.fn().mockResolvedValue([])
    };

    const mockExplainableAIService = {
      generateDecisionRationale: jest.fn().mockResolvedValue({
        primaryFactor: 'Expected utility',
        factors: [{
          name: 'Profit potential',
          weight: 0.6,
          value: 0.1,
          impact: 'positive'
        }],
        confidence: 0.8,
        ethicalConsiderations: [{
          type: 'fairness',
          constraint: 'No market manipulation',
          satisfied: true,
          impact: 0.9
        }],
        alternatives: [],
        reasoning: 'Decision based on utility maximization'
      })
    };

    const mockEthicalGuardrailsService = {
      validateAction: jest.fn().mockResolvedValue({
        valid: true,
        violations: [],
        recommendations: []
      }),
      enforceEthicalConstraints: jest.fn().mockResolvedValue({
        allowed: true,
        enforcementActions: []
      }),
      getEthicalReport: jest.fn().mockResolvedValue({
        agentId: 'agent_123',
        timeRange: { start: new Date(), end: new Date() },
        totalActions: 10,
        violations: [],
        complianceScore: 0.95,
        recommendations: [],
        generatedAt: new Date()
      })
    };

    const mockSmartContractService = {
      executeTrade: jest.fn().mockResolvedValue({
        contractAddress: '0x1234567890123456789012345678901234567890',
        abi: [],
        functionName: 'transfer',
        parameters: [],
        gasEstimate: 50000,
        executionStatus: 'success'
      }),
      getTransactionStatus: jest.fn().mockResolvedValue('success')
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AutonomousAgentService,
        { provide: UtilityFunctionService, useValue: mockUtilityFunctionService },
        { provide: NegotiationService, useValue: mockNegotiationService },
        { provide: GameTheoryService, useValue: mockGameTheoryService },
        { provide: ReinforcementLearningService, useValue: mockRLService },
        { provide: SimulationService, useValue: mockSimulationService },
        { provide: ExplainableAIService, useValue: mockExplainableAIService },
        { provide: EthicalGuardrailsService, useValue: mockEthicalGuardrailsService },
        { provide: SmartContractIntegrationService, useValue: mockSmartContractService }
      ]
    }).compile();

    service = module.get<AutonomousAgentService>(AutonomousAgentService);
    utilityFunctionService = module.get<UtilityFunctionService>(UtilityFunctionService);
    negotiationService = module.get<NegotiationService>(NegotiationService);
    gameTheoryService = module.get<GameTheoryService>(GameTheoryService);
    rlService = module.get<ReinforcementLearningService>(ReinforcementLearningService);
    simulationService = module.get<SimulationService>(SimulationService);
    explainableAIService = module.get<ExplainableAIService>(ExplainableAIService);
    ethicalGuardrailsService = module.get<EthicalGuardrailsService>(EthicalGuardrailsService);
    smartContractService = module.get<SmartContractIntegrationService>(SmartContractIntegrationService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createAgent', () => {
    it('should create an agent with valid parameters', async () => {
      const utilityFunction = {
        id: 'util_123',
        name: 'Profit Maximizer',
        type: UtilityType.PROFIT_MAXIMIZATION,
        parameters: [
          { name: 'profit', type: 'profit', value: 0, description: 'Profit metric' }
        ],
        weights: [1],
        constraints: [],
        optimizationTarget: 'maximize'
      };

      const initialResources = [
        {
          id: 'capital_1',
          type: 'capital',
          amount: 10000,
          currency: 'USD',
          availability: 'available'
        }
      ];

      const agent = await service.createAgent(
        'Test Agent',
        AgentType.MARKET_MAKER,
        utilityFunction,
        initialResources,
        { maxRisk: 0.1 }
      );

      expect(agent).toBeDefined();
      expect(agent.id).toMatch(/^agent_\d+_[a-z0-9]+$/);
      expect(agent.name).toBe('Test Agent');
      expect(agent.type).toBe(AgentType.MARKET_MAKER);
      expect(agent.status).toBe('active');
      expect(agent.reputation).toBe(0.5);
      expect(agent.resources).toEqual(initialResources);
    });

    it('should initialize agent state correctly', async () => {
      const utilityFunction = {
        id: 'util_123',
        name: 'Risk Minimizer',
        type: UtilityType.RISK_MINIMIZATION,
        parameters: [],
        weights: [],
        constraints: [],
        optimizationTarget: 'minimize'
      };

      const agent = await service.createAgent(
        'Test Agent',
        AgentType.ARBITRAGEUR,
        utilityFunction,
        [],
        {}
      );

      const agentState = service.getAgentState(agent.id);
      expect(agentState).toBeDefined();
      expect(agentState.resources).toEqual([]);
      expect(agentState.positions).toEqual([]);
      expect(agentState.utility).toBe(0);
      expect(agentState.lastAction).toBe('initialize');
    });
  });

  describe('makeDecision', () => {
    it('should make decision based on utility maximization', async () => {
      const agentId = 'test_agent_1';
      const agent = await service.createAgent(
        'Test Agent',
        AgentType.MARKET_MAKER,
        {
          id: 'util_123',
          name: 'Profit Maximizer',
          type: UtilityType.PROFIT_MAXIMIZATION,
          parameters: [],
          weights: [],
          constraints: [],
          optimizationTarget: 'maximize'
        },
        [],
        {}
      );

      const marketConditions: MarketConditions = {
        price: { 'ETH': 2000, 'USDC': 1 },
        volatility: { 'ETH': 0.2, 'USDC': 0.05 },
        volume: { 'ETH': 1000000, 'USDC': 5000000 },
        liquidity: { 'ETH': 500000, 'USDC': 2000000 },
        interestRates: { 'USDC': 0.05 }
      };

      const availableActions = ['buy', 'sell', 'hold'];

      const decision = await service.makeDecision(agentId, marketConditions, availableActions);

      expect(decision).toBeDefined();
      expect(decision.action).toBeDefined();
      expect(decision.confidence).toBeGreaterThanOrEqual(0);
      expect(decision.confidence).toBeLessThanOrEqual(1);
      expect(decision.rationale).toBeDefined();
    });

    it('should select action with highest utility', async () => {
      const agentId = 'test_agent_2';
      const agent = await service.createAgent(
        'Test Agent',
        AgentType.INVESTOR,
        {
          id: 'util_456',
          name: 'Balanced Investor',
          type: UtilityType.UTILITY_MAXIMIZATION,
          parameters: [],
          weights: [0.6, 0.3, 0.1],
          constraints: [],
          optimizationTarget: 'maximize'
        },
        [],
        {}
      );

      const marketConditions: MarketConditions = {
        price: { 'BTC': 50000, 'USDC': 1 },
        volatility: { 'BTC': 0.3, 'USDC': 0.05 },
        volume: { 'BTC': 500000, 'USDC': 5000000 },
        liquidity: { 'BTC': 200000, 'USDC': 2000000 },
        interestRates: { 'USDC': 0.05 }
      };

      const availableActions = ['buy', 'sell', 'provide_liquidity'];

      const decision = await service.makeDecision(agentId, marketConditions, availableActions);

      expect(utilityFunctionService.calculateUtility).toHaveBeenCalled();
      expect(decision.action).toBeDefined();
      expect(decision.confidence).toBeGreaterThan(0);
    });
  });

  describe('executeAction', () => {
    it('should execute buy action successfully', async () => {
      const agentId = 'test_agent_3';
      const agent = await service.createAgent(
        'Test Agent',
        AgentType.LIQUIDITY_PROVIDER,
        {
          id: 'util_789',
          name: 'Liquidity Provider',
          type: UtilityType.PROFIT_MAXIMIZATION,
          parameters: [],
          weights: [],
          constraints: [],
          optimizationTarget: 'maximize'
        },
        [
          {
            id: 'capital_1',
            type: 'capital',
            amount: 10000,
            currency: 'USD',
            availability: 'available'
          }
        ],
        {}
      );

      const marketConditions: MarketConditions = {
        price: { 'ETH': 2000, 'USDC': 1 },
        volatility: { 'ETH': 0.2, 'USDC': 0.05 },
        volume: { 'ETH': 1000000, 'USDC': 5000000 },
        liquidity: { 'ETH': 500000, 'USDC': 2000000 },
        interestRates: { 'USDC': 0.05 }
      };

      const result = await service.executeAction(agentId, 'buy', marketConditions);

      expect(result.success).toBe(true);
      expect(result.executionDetails).toBeDefined();
      expect(result.executionDetails.type).toBe('buy');
      expect(result.executionDetails.asset).toBe('ETH');
      expect(result.executionDetails.amount).toBeGreaterThan(0);
      expect(result.executionDetails.price).toBe(2000);
    });

    it('should handle insufficient capital gracefully', async () => {
      const agentId = 'test_agent_4';
      const agent = await service.createAgent(
        'Test Agent',
        AgentType.BORROWER,
        {
          id: 'util_101',
          name: 'Borrower',
          type: UtilityType.PROFIT_MAXIMIZATION,
          parameters: [],
          weights: [],
          constraints: [],
          optimizationTarget: 'maximize'
        },
        [
          {
            id: 'capital_1',
            type: 'capital',
            amount: 500, // Low capital
            currency: 'USD',
            availability: 'available'
          }
        ],
        {}
      );

      const marketConditions: MarketConditions = {
        price: { 'ETH': 2000, 'USDC': 1 },
        volatility: { 'ETH': 0.2, 'USDC': 0.05 },
        volume: { 'ETH': 1000000, 'USDC': 5000000 },
        liquidity: { 'ETH': 500000, 'USDC': 2000000 },
        interestRates: { 'USDC': 0.05 }
      };

      const result = await service.executeAction(agentId, 'buy', marketConditions);

      expect(result.success).toBe(false);
      expect(result.executionDetails.error).toContain('Insufficient capital');
    });
  });

  describe('negotiate', () => {
    it('should initiate negotiation successfully', async () => {
      const agentId = 'test_agent_5';
      const agent = await service.createAgent(
        'Test Agent',
        AgentType.MARKET_MAKER,
        {
          id: 'util_202',
          name: 'Negotiator',
          type: UtilityType.PROFIT_MAXIMIZATION,
          parameters: [],
          weights: [],
          constraints: [],
          optimizationTarget: 'maximize'
        },
        [],
        {}
      );

      const terms = {
        quantity: 100,
        asset: 'ETH',
        currency: 'USDC',
        price: 2000
      };

      const result = await service.negotiate(agentId, 'counterparty_123', terms, 'alternating_offers');

      expect(result).toBeDefined();
      expect(result.success).toBeDefined();
    });
  });

  describe('learn', () => {
    it('should update agent strategies based on experience', async () => {
      const agentId = 'test_agent_6';
      const agent = await service.createAgent(
        'Test Agent',
        AgentType.ARBITRAGEUR,
        {
          id: 'util_303',
          name: 'Learning Agent',
          type: UtilityType.PROFIT_MAXIMIZATION,
          parameters: [],
          weights: [],
          constraints: [],
          optimizationTarget: 'maximize'
        },
        [],
        {}
      );

      const experience = {
        action: 'buy',
        reward: 0.1,
        state: [1, 2, 3],
        nextState: [1, 2, 4],
        done: false
      };

      await service.learn(agentId, experience);

      expect(agent.strategies).toBeDefined();
    });
  });

  describe('agent lifecycle management', () => {
    it('should update agent reputation', async () => {
      const agentId = 'test_agent_7';
      const agent = await service.createAgent(
        'Test Agent',
        AgentType.MARKET_MAKER,
        {
          id: 'util_404',
          name: 'Reputable Agent',
          type: UtilityType.PROFIT_MAXIMIZATION,
          parameters: [],
          weights: [],
          constraints: [],
          optimizationTarget: 'maximize'
        },
        [],
        {}
      );

      const initialReputation = agent.reputation;
      await service.updateAgentReputation(agentId, 0.1);

      const updatedAgent = service.getAgent(agentId);
      expect(updatedAgent.reputation).toBe(initialReputation + 0.1);
      expect(updatedAgent.reputation).toBeLessThanOrEqual(1);
      expect(updatedAgent.reputation).toBeGreaterThanOrEqual(0);
    });

    it('should deactivate agent', async () => {
      const agentId = 'test_agent_8';
      const agent = await service.createAgent(
        'Test Agent',
        AgentType.INVESTOR,
        {
          id: 'util_505',
          name: 'Temporary Agent',
          type: UtilityType.PROFIT_MAXIMIZATION,
          parameters: [],
          weights: [],
          constraints: [],
          optimizationTarget: 'maximize'
        },
        [],
        {}
      );

      expect(agent.status).toBe('active');
      await service.deactivateAgent(agentId);

      const deactivatedAgent = service.getAgent(agentId);
      expect(deactivatedAgent.status).toBe('inactive');
    });

    it('should reactivate agent', async () => {
      const agentId = 'test_agent_9';
      const agent = await service.createAgent(
        'Test Agent',
        AgentType.LENDER,
        {
          id: 'util_606',
          name: 'Reactivatable Agent',
          type: UtilityType.PROFIT_MAXIMIZATION,
          parameters: [],
          weights: [],
          constraints: [],
          optimizationTarget: 'maximize'
        },
        [],
        {}
      );

      await service.deactivateAgent(agentId);
      expect(service.getAgent(agentId)?.status).toBe('inactive');

      await service.reactivateAgent(agentId);
      const reactivatedAgent = service.getAgent(agentId);
      expect(reactivatedAgent.status).toBe('active');
      expect(reactivatedAgent.lastActive).toBeInstanceOf(Date);
    });
  });

  describe('error handling', () => {
    it('should handle non-existent agent gracefully', async () => {
      const nonExistentAgentId = 'non_existent_agent';
      const marketConditions: MarketConditions = {
        price: { 'ETH': 2000 },
        volatility: { 'ETH': 0.2 },
        volume: { 'ETH': 1000000 },
        liquidity: { 'ETH': 500000 },
        interestRates: { 'USDC': 0.05 }
      };

      await expect(
        service.makeDecision(nonExistentAgentId, marketConditions, ['buy', 'sell'])
      ).rejects.toThrow('Agent non_existent_agent not found');
    });

    it('should handle invalid actions gracefully', async () => {
      const agentId = 'test_agent_10';
      await service.createAgent(
        'Test Agent',
        AgentType.MARKET_MAKER,
        {
          id: 'util_707',
          name: 'Error Test Agent',
          type: UtilityType.PROFIT_MAXIMIZATION,
          parameters: [],
          weights: [],
          constraints: [],
          optimizationTarget: 'maximize'
        },
        [],
        {}
      );

      const marketConditions: MarketConditions = {
        price: { 'ETH': 2000 },
        volatility: { 'ETH': 0.2 },
        volume: { 'ETH': 1000000 },
        liquidity: { 'ETH': 500000 },
        interestRates: { 'USDC': 0.05 }
      };

      const result = await service.executeAction(agentId, 'invalid_action', marketConditions);

      expect(result.success).toBe(false);
      expect(result.executionDetails.error).toContain('Unknown action');
    });
  });
});
