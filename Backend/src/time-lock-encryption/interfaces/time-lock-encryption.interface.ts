export interface TimeLockEncryption {
  id: string;
  encryptedData: string;
  publicKey: string;
  proof: TimeLockProof;
  unlockTime: Date;
  createdAt: Date;
  algorithm: TimeLockAlgorithm;
  parameters: TimeLockParameters;
  metadata: TimeLockMetadata;
}

export interface TimeLockProof {
  commitment: string;
  challenge: string;
  response: string;
  verification: string;
  difficulty: number;
  sequentialSteps: number;
  parallelResistance: boolean;
}

export interface TimeLockParameters {
  timeSeconds: number;
  difficulty: number;
  securityLevel: SecurityLevel;
  keySize: number;
  hashIterations: number;
  primeSize?: number;
  groupOrder?: bigint;
}

export interface TimeLockMetadata {
  purpose: string;
  creator: string;
  description?: string;
  tags: string[];
  recipient?: string;
  conditions?: string[];
}

export enum TimeLockAlgorithm {
  RSA_TIME_LOCK = 'rsa_time_lock',
  PIETRZAK_VDF = 'pietrzak_vdf',
  WESOLOWSKI_VDF = 'wesolowski_vdf',
  CHIA_VDF = 'chia_vdf',
  HYBRID_VDF = 'hybrid_vdf'
}

export enum SecurityLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  MAXIMUM = 'maximum'
}

export interface VDFEvaluation {
  input: string;
  output: string;
  proof: string;
  difficulty: number;
  evaluationTime: number;
  sequentialSteps: number;
  y: bigint;
  x: bigint;
  proofBytes: Uint8Array;
}

export interface RSATimeLock {
  modulus: bigint;
  publicExponent: bigint;
  privateExponent: bigint;
  phi: bigint;
  timeLockParameter: bigint;
  encryptedMessage: bigint;
  proof: RSATimeLockProof;
}

export interface RSATimeLockProof {
  commitment: string;
  challenge: string;
  response: string;
  verification: string;
  timeBound: number;
  sequentialOperations: number;
}

export interface PietrzakVDF {
  group: VDFGroup;
  generator: bigint;
  x: bigint;
  y: bigint;
  proof: PietrzakProof;
  difficulty: number;
  t: number;
  lambda: bigint;
  mu: bigint;
}

export interface VDFGroup {
  name: string;
  prime: bigint;
  order: bigint;
  generator: bigint;
  securityParameter: number;
}

export interface PietrzakProof {
  y: bigint;
  proof: Uint8Array;
  l: bigint[];
  r: bigint[];
  challenges: string[];
  responses: string[];
}

export interface TimeLockResult {
  success: boolean;
  decryptedData?: string;
  verificationResult?: VerificationResult;
  error?: string;
  executionTime?: number;
  sequentialSteps?: number;
}

export interface VerificationResult {
  valid: boolean;
  proofValid: boolean;
  timeConstraintSatisfied: boolean;
  difficultyMet: boolean;
  verificationTime: number;
  details: string;
}

export interface SealedBid {
  id: string;
  auctionId: string;
  bidderId: string;
  encryptedBid: string;
  timeLockEncryption: TimeLockEncryption;
  revealTime: Date;
  amount: number;
  metadata: SealedBidMetadata;
}

export interface SealedBidMetadata {
  auctionType: string;
  minimumBid: number;
  bidCurrency: string;
  revealDeadline: Date;
  settlementTerms: string[];
}

export interface EscrowTransaction {
  id: string;
  timeLockEncryption: TimeLockEncryption;
  parties: EscrowParty[];
  conditions: EscrowCondition[];
  releaseTime: Date;
  status: EscrowStatus;
  createdAt: Date;
  blockchainTxHash?: string;
}

export interface EscrowParty {
  id: string;
  address: string;
  role: 'buyer' | 'seller' | 'arbiter';
  signature?: string;
  commitment?: string;
}

export interface EscrowCondition {
  type: string;
  parameter: string;
  operator: string;
  value: any;
  verified: boolean;
}

export enum EscrowStatus {
  PENDING = 'pending',
  LOCKED = 'locked',
  RELEASED = 'released',
  DISPUTED = 'disputed',
  REFUNDED = 'refunded',
  EXPIRED = 'expired'
}

export interface DeadMansSwitch {
  id: string;
  creatorId: string;
  beneficiaries: Beneficiary[];
  timeLockEncryption: TimeLockEncryption;
  checkInInterval: number;
  lastCheckIn?: Date;
  status: DeadMansSwitchStatus;
  triggerConditions: TriggerCondition[];
  createdAt: Date;
}

export interface Beneficiary {
  id: string;
  address: string;
  share: number;
  conditions?: string[];
  verified: boolean;
}

export interface TriggerCondition {
  type: 'time_elapsed' | 'no_check_in' | 'external_signal' | 'multi_signature';
  parameter: string;
  threshold: any;
  operator: string;
  satisfied: boolean;
}

export enum DeadMansSwitchStatus {
  ACTIVE = 'active',
  TRIGGERED = 'triggered',
  EXPIRED = 'expired',
  REVOKED = 'revoked'
}

export interface TimeLockConfig {
  defaultAlgorithm: TimeLockAlgorithm;
  defaultSecurityLevel: SecurityLevel;
  maxTimeLock: number;
  minTimeLock: number;
  supportedAlgorithms: TimeLockAlgorithm[];
  vdfParameters: VDFParameters;
  rsaParameters: RSAParameters;
}

export interface VDFParameters {
  defaultDifficulty: number;
  maxSequentialSteps: number;
  groupPrimeSize: number;
  proofSize: number;
  verificationComplexity: number;
}

export interface RSAParameters {
  defaultKeySize: number;
  minKeySize: number;
  maxKeySize: number;
  timeLockExponent: number;
  paddingScheme: string;
  hashFunction: string;
}

export interface SmartContractIntegration {
  contractAddress: string;
  abi: any[];
  functionName: string;
  parameters: any[];
  network: string;
  gasEstimate: number;
  deploymentStatus: DeploymentStatus;
}

export enum DeploymentStatus {
  PENDING = 'pending',
  DEPLOYED = 'deployed',
  VERIFIED = 'verified',
  FAILED = 'failed'
}

export interface TimeLockMetrics {
  totalEncryptions: number;
  totalDecryptions: number;
  averageUnlockTime: number;
  successRate: number;
  algorithmUsage: { [algorithm: string]: number };
  securityLevelDistribution: { [level: string]: number };
  averageDifficulty: number;
  totalComputationTime: number;
}

export interface TimeLockAuditLog {
  id: string;
  timestamp: Date;
  operation: 'encrypt' | 'decrypt' | 'verify' | 'deploy';
  userId: string;
  timeLockId: string;
  algorithm: TimeLockAlgorithm;
  success: boolean;
  executionTime: number;
  details: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface BatchTimeLockOperation {
  id: string;
  operations: TimeLockOperation[];
  totalExecutionTime: number;
  successCount: number;
  failureCount: number;
  createdAt: Date;
}

export interface TimeLockOperation {
  type: 'encrypt' | 'decrypt' | 'verify';
  data: string;
  parameters: TimeLockParameters;
  targetTime?: Date;
  priority: 'low' | 'medium' | 'high' | 'critical';
}

export interface TimeLockChallenge {
  id: string;
  timeLockId: string;
  challenger: string;
  challengeType: 'proof_correctness' | 'time_boundary' | 'sequential_computation';
  challengeData: string;
  responseDeadline: Date;
  status: 'pending' | 'responded' | 'expired' | 'invalid';
  createdAt: Date;
}

export interface TimeLockResponse {
  challengeId: string;
  responder: string;
  responseData: string;
  proof: string;
  verificationResult: VerificationResult;
  responseTime: Date;
  valid: boolean;
}

export interface DecryptionWitness {
  witness: string;
  partialDecryption: string;
  proofOfWork: string;
  sequentialSteps: number;
  difficulty: number;
  timestamp: Date;
}

export interface TimeLockPool {
  id: string;
  name: string;
  description: string;
  algorithm: TimeLockAlgorithm;
  participants: string[];
  currentRound: number;
  totalRounds: number;
  status: 'active' | 'completed' | 'failed';
  createdAt: Date;
  endTime?: Date;
}

export interface PoolRound {
  roundNumber: number;
  poolId: string;
  encryptedData: string[];
  decryptionProgress: { [participantId: string]: number };
  startTime: Date;
  endTime?: Date;
  winner?: string;
  prize?: string;
}
