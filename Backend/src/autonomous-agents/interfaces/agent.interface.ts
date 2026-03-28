export interface Agent {
  id: string;
  name: string;
  type: AgentType;
  status: AgentStatus;
  utilityFunction: UtilityFunction;
  strategies: Strategy[];
  resources: Resource[];
  constraints: Constraint[];
  reputation: number;
  createdAt: Date;
  lastActive: Date;
}

export enum AgentType {
  MARKET_MAKER = 'market_maker',
  ARBITRAGEUR = 'arbitrageur',
  LIQUIDITY_PROVIDER = 'liquidity_provider',
  LENDER = 'lender',
  BORROWER = 'borrower',
  INVESTOR = 'investor',
  HEDGER = 'hedger'
}

export enum AgentStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended',
  TRAINING = 'training'
}

export interface UtilityFunction {
  id: string;
  name: string;
  type: UtilityType;
  parameters: UtilityParameter[];
  weights: number[];
  constraints: UtilityConstraint[];
  optimizationTarget: OptimizationTarget;
}

export enum UtilityType {
  PROFIT_MAXIMIZATION = 'profit_maximization',
  RISK_MINIMIZATION = 'risk_minimization',
  UTILITY_MAXIMIZATION = 'utility_maximization',
  SHARPE_RATIO = 'sharpe_ratio',
  SORTINO_RATIO = 'sortino_ratio',
  CUSTOM = 'custom'
}

export interface UtilityParameter {
  name: string;
  type: ParameterType;
  value: number;
  min?: number;
  max?: number;
  description: string;
}

export enum ParameterType {
  PROFIT = 'profit',
  RISK = 'risk',
  VOLUME = 'volume',
  VOLATILITY = 'volatility',
  LIQUIDITY = 'liquidity',
  TIME_HORIZON = 'time_horizon',
  CAPITAL = 'capital'
}

export interface UtilityConstraint {
  type: ConstraintType;
  value: number;
  description: string;
}

export enum ConstraintType {
  MAX_RISK = 'max_risk',
  MIN_RETURN = 'min_return',
  MAX_POSITION_SIZE = 'max_position_size',
  MIN_LIQUIDITY = 'min_liquidity',
  MAX_LEVERAGE = 'max_leverage',
  ETHICAL_BOUNDARY = 'ethical_boundary'
}

export enum OptimizationTarget {
  MAXIMIZE = 'maximize',
  MINIMIZE = 'minimize',
  EQUILIBRIUM = 'equilibrium'
}

export interface Strategy {
  id: string;
  name: string;
  type: StrategyType;
  parameters: StrategyParameter[];
  performance: StrategyPerformance;
  isActive: boolean;
}

export enum StrategyType {
  MARKET_MAKING = 'market_making',
  ARBITRAGE = 'arbitrage',
  YIELD_FARMING = 'yield_farming',
  LENDING = 'lending',
  HEDGING = 'hedging',
  LIQUIDITY_MINING = 'liquidity_mining',
  DYNAMIC_PRICING = 'dynamic_pricing'
}

export interface StrategyParameter {
  name: string;
  value: number;
  type: 'continuous' | 'discrete';
  min?: number;
  max?: number;
}

export interface StrategyPerformance {
  totalReturn: number;
  sharpeRatio: number;
  maxDrawdown: number;
  winRate: number;
  totalTrades: number;
  averageHoldingPeriod: number;
}

export interface Resource {
  id: string;
  type: ResourceType;
  amount: number;
  currency: string;
  availability: ResourceAvailability;
}

export enum ResourceType {
  CAPITAL = 'capital',
  TOKEN = 'token',
  NFT = 'nft',
  LIQUIDITY_POSITION = 'liquidity_position',
  CREDIT_LINE = 'credit_line',
  COMPUTATIONAL_POWER = 'computational_power'
}

export enum ResourceAvailability {
  AVAILABLE = 'available',
  LOCKED = 'locked',
  STAKED = 'staked',
  BORROWED = 'borrowed'
}

export interface Constraint {
  id: string;
  type: ConstraintType;
  value: number;
  isActive: boolean;
  description: string;
}

export interface Negotiation {
  id: string;
  participants: string[];
  type: NegotiationType;
  status: NegotiationStatus;
  protocol: NegotiationProtocol;
  messages: NegotiationMessage[];
  outcome?: NegotiationOutcome;
  startTime: Date;
  endTime?: Date;
}

export enum NegotiationType {
  TRADE = 'trade',
  LOAN = 'loan',
  PARTNERSHIP = 'partnership',
  LIQUIDITY_PROVISION = 'liquidity_provision',
  ARBITRAGE_COORDINATION = 'arbitrage_coordination'
}

export enum NegotiationStatus {
  INITIATED = 'initiated',
  IN_PROGRESS = 'in_progress',
  ACCEPTED = 'accepted',
  REJECTED = 'rejected',
  COUNTERED = 'countered',
  EXPIRED = 'expired',
  FAILED = 'failed'
}

export enum NegotiationProtocol {
  ALTERNATING_OFFERS = 'alternating_offers',
  SIMULTANEOUS_OFFERS = 'simultaneous_offers',
  MEDIATED = 'mediated',
  AUCTION = 'auction',
  BLIND_BID = 'blind_bid'
}

export interface NegotiationMessage {
  id: string;
  senderId: string;
  receiverId: string;
  type: MessageType;
  content: MessageContent;
  timestamp: Date;
  utility?: number;
  confidence?: number;
}

export enum MessageType {
  OFFER = 'offer',
  COUNTER_OFFER = 'counter_offer',
  ACCEPT = 'accept',
  REJECT = 'reject',
  QUERY = 'query',
  INFO = 'info',
  COMMIT = 'commit'
}

export interface MessageContent {
  terms: NegotiationTerms;
  rationale?: DecisionRationale;
  expiration?: Date;
}

export interface NegotiationTerms {
  price?: number;
  quantity: number;
  asset: string;
  currency: string;
  duration?: number;
  interestRate?: number;
  collateral?: string;
  conditions?: string[];
}

export interface NegotiationOutcome {
  type: OutcomeType;
  terms: NegotiationTerms;
  utility: { [agentId: string]: number };
  timestamp: Date;
  rationale?: DecisionRationale;
}

export enum OutcomeType {
  AGREEMENT = 'agreement',
  DISAGREEMENT = 'disagreement',
  TIMEOUT = 'timeout',
  EXTERNAL_INTERVENTION = 'external_intervention'
}

export interface GameTheoryScenario {
  id: string;
  name: string;
  type: GameType;
  players: string[];
  payoffMatrix: PayoffMatrix;
  nashEquilibria: NashEquilibrium[];
  dominantStrategies?: { [playerId: string]: string };
}

export enum GameType {
  PRISONERS_DILEMMA = 'prisoners_dilemma',
  COURNOT_DUOPOLY = 'cournot_duopoly',
  BERTRAND_DUOPOLY = 'bertrand_duopoly',
  STACKELBERG = 'stackelberg',
  AUCTION = 'auction',
  BARGAINING = 'bargaining',
  CUSTOM = 'custom'
}

export interface PayoffMatrix {
  players: string[];
  strategies: { [playerId: string]: string[] };
  payoffs: number[][][];
}

export interface NashEquilibrium {
  strategies: { [playerId: string]: string };
  payoffs: { [playerId: string]: number };
  stability: number;
}

export interface ReinforcementLearningState {
  agentId: string;
  state: number[];
  action: string;
  reward: number;
  nextState: number[];
  done: boolean;
  timestamp: Date;
}

export interface RLModel {
  id: string;
  agentId: string;
  algorithm: RLAlgorithm;
  hyperparameters: RLHyperparameters;
  performance: RLPerformance;
  trainingData: ReinforcementLearningState[];
  modelState: any;
}

export enum RLAlgorithm {
  Q_LEARNING = 'q_learning',
  DEEP_Q_NETWORK = 'deep_q_network',
  ACTOR_CRITIC = 'actor_critic',
  PPO = 'ppo',
  DDPG = 'ddpg',
  SAC = 'sac'
}

export interface RLHyperparameters {
  learningRate: number;
  discountFactor: number;
  explorationRate: number;
  batchSize: number;
  targetUpdateFrequency: number;
  memorySize: number;
  hiddenLayers?: number[];
}

export interface RLPerformance {
  averageReward: number;
  maxReward: number;
  minReward: number;
  convergenceRate: number;
  explorationRate: number;
  totalEpisodes: number;
}

export interface SimulationEnvironment {
  id: string;
  name: string;
  agents: string[];
  marketConditions: MarketConditions;
  timeStep: number;
  maxTimeSteps: number;
  currentState: SimulationState;
  history: SimulationState[];
}

export interface MarketConditions {
  price: { [asset: string]: number };
  volatility: { [asset: string]: number };
  volume: { [asset: string]: number };
  liquidity: { [asset: string]: number };
  interestRates: { [currency: string]: number };
}

export interface SimulationState {
  timeStep: number;
  agentStates: { [agentId: string]: AgentState };
  marketState: MarketConditions;
  transactions: Transaction[];
  negotiations: Negotiation[];
}

export interface AgentState {
  resources: Resource[];
  positions: Position[];
  utility: number;
  lastAction?: string;
  decisionRationale?: DecisionRationale;
}

export interface Position {
  id: string;
  asset: string;
  amount: number;
  entryPrice: number;
  currentPrice: number;
  unrealizedPnL: number;
  realizedPnL: number;
  timestamp: Date;
}

export interface Transaction {
  id: string;
  type: TransactionType;
  participants: string[];
  terms: NegotiationTerms;
  executionPrice: number;
  timestamp: Date;
  blockchainTxHash?: string;
  status: TransactionStatus;
}

export enum TransactionType {
  TRADE = 'trade',
  LOAN = 'loan',
  REPAYMENT = 'repayment',
  LIQUIDITY_PROVISION = 'liquidity_provision',
  LIQUIDITY_REMOVAL = 'liquidity_removal'
}

export enum TransactionStatus {
  PENDING = 'pending',
  CONFIRMED = 'confirmed',
  FAILED = 'failed',
  REVERTED = 'reverted'
}

export interface DecisionRationale {
  primaryFactor: string;
  factors: RationaleFactor[];
  confidence: number;
  ethicalConsiderations: EthicalConsideration[];
  alternatives: Alternative[];
  reasoning: string;
}

export interface RationaleFactor {
  name: string;
  weight: number;
  value: number;
  impact: 'positive' | 'negative' | 'neutral';
}

export interface EthicalConsideration {
  type: EthicalType;
  constraint: string;
  satisfied: boolean;
  impact: number;
}

export enum EthicalType {
  FAIRNESS = 'fairness',
  TRANSPARENCY = 'transparency',
  MARKET_MANIPULATION = 'market_manipulation',
  CONFLICT_OF_INTEREST = 'conflict_of_interest',
  SOCIAL_WELFARE = 'social_welfare',
  ENVIRONMENTAL_IMPACT = 'environmental_impact'
}

export interface Alternative {
  description: string;
  expectedUtility: number;
  risk: number;
  rejected: boolean;
  reason?: string;
}

export interface SmartContractIntegration {
  contractAddress: string;
  abi: any[];
  functionName: string;
  parameters: any[];
  gasEstimate: number;
  executionStatus: ExecutionStatus;
}

export enum ExecutionStatus {
  PENDING = 'pending',
  SUCCESS = 'success',
  FAILED = 'failed',
  OUT_OF_GAS = 'out_of_gas'
}

export interface AgentConfig {
  maxNegotiations: number;
  maxPositionSize: number;
  riskTolerance: number;
  learningRate: number;
  updateFrequency: number;
  ethicalConstraints: EthicalConstraint[];
}

export interface EthicalConstraint {
  type: EthicalType;
  threshold: number;
  action: 'block' | 'warn' | 'limit';
  description: string;
}
