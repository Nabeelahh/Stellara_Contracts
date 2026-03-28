export interface JurisdictionProfile {
  id: string;
  name: string;
  isoCode: string;
  region: string;
  regulatoryFramework: string;
  taxJurisdiction: boolean;
  financialRegulations: FinancialRegulations;
  privacyLaws: PrivacyLaws;
  reportingRequirements: ReportingRequirements;
  enforcementActions: EnforcementActions;
  riskLevel: RiskLevel;
  lastUpdated: Date;
}

export interface FinancialRegulations {
  kycRequirements: KYCRequirements;
  amlThresholds: AMLThresholds;
  reportingThresholds: ReportingThresholds;
  licensingRequirements: LicensingRequirements;
  dataRetention: DataRetention;
  crossBorderRestrictions: CrossBorderRestrictions;
}

export interface KYCRequirements {
  identityVerification: boolean;
  addressVerification: boolean;
  sourceOfFunds: boolean;
  enhancedDueDiligence: boolean;
  documentTypes: string[];
  verificationMethods: string[];
}

export interface AMLThresholds {
  reportingThreshold: number;
  recordKeepingThreshold: number;
  suspiciousTransactionThreshold: number;
  currency: string;
  timeFrame: string;
}

export interface ReportingThresholds {
  transactionReporting: number;
  annualReporting: boolean;
  quarterlyReporting: boolean;
  realTimeReporting: boolean;
  reportTypes: string[];
}

export interface LicensingRequirements {
  financialLicenseRequired: boolean;
  licenseTypes: string[];
  minimumCapital: number;
  complianceOfficer: boolean;
  auditFrequency: string;
}

export interface DataRetention {
  transactionRecords: number; // years
  customerRecords: number; // years
  communicationRecords: number; // years
  encryptionRequired: boolean;
}

export interface CrossBorderRestrictions {
  outboundTransfers: boolean;
  inboundTransfers: boolean;
  reportingRequired: boolean;
  authorizationRequired: boolean;
  restrictedCountries: string[];
  monitoringRequired: boolean;
}

export interface PrivacyLaws {
  dataProtection: string;
  consentRequired: boolean;
  dataLocalization: boolean;
  encryptionStandards: string;
  breachNotification: boolean;
  crossBorderTransfer: boolean;
  userRights: string[];
}

export interface ReportingRequirements {
  suspiciousActivityReporting: boolean;
  transactionReporting: boolean;
  annualReports: boolean;
  auditTrail: boolean;
  realTimeMonitoring: boolean;
  reportFormats: string[];
  reportingFrequencies: string[];
}

export interface EnforcementActions {
  fines: number[];
  licenseSuspension: boolean;
  criminalCharges: boolean;
  assetFreeze: boolean;
  travelRestrictions: boolean;
  reportingObligations: string[];
}

export enum RiskLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface IPGeolocation {
  ipAddress: string;
  country: string;
  region: string;
  city: string;
  isp: string;
  organization: string;
  vpn: boolean;
  proxy: boolean;
  tor: boolean;
  confidence: number;
  lastSeen: Date;
}

export interface DeviceFingerprint {
  userAgent: string;
  language: string;
  timezone: string;
  screenResolution: string;
  platform: string;
  hardware: HardwareInfo;
  software: SoftwareInfo;
  privacyTools: PrivacyTool[];
  riskScore: number;
  anomalies: DeviceAnomaly[];
}

export interface HardwareInfo {
  cpu: string;
  gpu: string;
  ram: string;
  storage: string;
  networkInterfaces: NetworkInterface[];
  virtualization: boolean;
  container: boolean;
  mobile: boolean;
}

export interface SoftwareInfo {
  os: string;
  browser: string;
  extensions: BrowserExtension[];
  plugins: string[];
  privacyExtensions: PrivacyExtension[];
  securitySoftware: SecuritySoftware[];
}

export interface PrivacyTool {
  name: string;
  type: PrivacyToolType;
  enabled: boolean;
  configuration: any;
  detected: Date;
}

export enum PrivacyToolType {
  VPN = 'vpn',
  PROXY = 'proxy',
  TOR = 'tor',
  MIXER = 'mixer',
  PRIVACY_BROWSER = 'privacy_browser',
  ENCRYPTION_TOOL = 'encryption_tool',
  ANTI_TRACKING = 'anti_tracking'
}

export interface BrowserExtension {
  name: string;
  id: string;
  category: ExtensionCategory;
  permissions: string[];
  privacyFeatures: string[];
  riskLevel: RiskLevel;
  installed: Date;
}

export enum ExtensionCategory {
  PRIVACY = 'privacy',
  SECURITY = 'security',
  CRYPTO_WALLET = 'crypto_wallet',
  TRADING = 'trading',
  VPN_PROXY = 'vpn_proxy',
  AD_BLOCKER = 'ad_blocker'
}

export interface PrivacyExtension {
  name: string;
  features: string[];
  riskLevel: RiskLevel;
  detected: Date;
}

export interface SecuritySoftware {
  name: string;
  type: SecuritySoftwareType;
  enabled: boolean;
  configuration: any;
  lastScan: Date;
}

export enum SecuritySoftwareType {
  ANTIVIRUS = 'antivirus',
  FIREWALL = 'firewall',
  ANTISPYWARE = 'antispyware',
  VPN = 'vpn',
  PROXY = 'proxy'
}

export interface DeviceAnomaly {
  type: AnomalyType;
  description: string;
  severity: RiskLevel;
  detected: Date;
  evidence: any;
}

export enum AnomalyType {
  PRIVACY_TOOLS = 'privacy_tools',
  LOCATION_MISMATCH = 'location_mismatch',
  TIME_ZONE_ANOMALY = 'timezone_anomaly',
  USER_AGENT_SPOOFING = 'user_agent_spoofing',
  CONCURRENT_SESSIONS = 'concurrent_sessions',
  SUSPECT_EXTENSIONS = 'suspect_extensions',
  VIRTUALIZATION = 'virtualization',
  ROOT_ACCESS = 'root_access'
}

export interface UserBehavior {
  userId: string;
  sessionId: string;
  loginPattern: LoginPattern;
  transactionPattern: TransactionPattern;
  navigationPattern: NavigationPattern;
  timePattern: TimePattern;
  riskIndicators: RiskIndicator[];
  behaviorScore: number;
  anomalies: BehaviorAnomaly[];
}

export interface LoginPattern {
  frequency: number;
  timeDistribution: number[];
  locations: IPGeolocation[];
  devices: DeviceFingerprint[];
  methods: string[];
  riskScore: number;
}

export interface TransactionPattern {
  volume: number;
  frequency: number;
  averageAmount: number;
  amounts: number[];
  currencies: string[];
  destinations: string[];
  timeDistribution: number[];
  roundTripping: boolean;
  structuring: boolean;
  riskScore: number;
}

export interface NavigationPattern {
  pages: string[];
  flowSequences: string[];
  timeOnPage: number[];
  scrollPatterns: ScrollPattern[];
  clickPatterns: ClickPattern[];
  riskScore: number;
}

export interface ScrollPattern {
  velocity: number;
  acceleration: number;
  direction: string;
  duration: number;
  timestamp: Date;
}

export interface ClickPattern {
  coordinates: { x: number; y: number }[];
  timing: number[];
  pressure: number[];
  pattern: string;
  riskScore: number;
}

export interface TimePattern {
  activeHours: { start: string; end: string }[];
  timezone: string;
  sessionDuration: number;
  activityBursts: ActivityBurst[];
  riskScore: number;
}

export interface ActivityBurst {
  startTime: Date;
  endTime: Date;
  actions: number;
  riskScore: number;
}

export interface RiskIndicator {
  type: RiskIndicatorType;
  severity: RiskLevel;
  confidence: number;
  description: string;
  evidence: any;
  detected: Date;
}

export enum RiskIndicatorType {
  UNUSUAL_LOGIN_PATTERN = 'unusual_login_pattern',
  SUSPICIOUS_TRANSACTION_PATTERN = 'suspicious_transaction_pattern',
  PRIVACY_TOOL_USAGE = 'privacy_tool_usage',
  JURISDICTION_JUMPING = 'jurisdiction_jumping',
  ROUND_TRIPPING = 'round_tripping',
  STRUCTURING = 'structuring',
  SHELL_COMPANY_USAGE = 'shell_company_usage',
  TREATY_SHOPPING = 'treaty_shopping',
  AUTOMATED_BEHAVIOR = 'automated_behavior',
  CROSS_BORDER_ANOMALY = 'cross_border_anomaly'
}

export interface BehaviorAnomaly {
  type: BehaviorAnomalyType;
  description: string;
  severity: RiskLevel;
  detected: Date;
  impact: string;
}

export enum BehaviorAnomalyType {
  BEHAVIOR_CHANGE = 'behavior_change',
  AUTOMATION_DETECTED = 'automation_detected',
  SIMULTANEOUS_SESSIONS = 'simultaneous_sessions',
  GEOGRAPHIC_ANOMALY = 'geographic_anomaly',
  TEMPORAL_ANOMALY = 'temporal_anomaly',
  VOLUME_ANOMALY = 'volume_anomaly',
  PATTERN_ANOMALY = 'pattern_anomaly'
}

export interface CrossBorderFlow {
  id: string;
  userId: string;
  sourceJurisdiction: string;
  targetJurisdiction: string;
  transactionType: TransactionType;
  amount: number;
  currency: string;
  route: FlowRoute;
  timing: FlowTiming;
  purpose: FlowPurpose;
  intermediaries: Intermediary[];
  riskScore: number;
  suspiciousIndicators: SuspiciousIndicator[];
  detected: Date;
}

export enum TransactionType {
  TRANSFER = 'transfer',
  EXCHANGE = 'exchange',
  PURCHASE = 'purchase',
  SALE = 'sale',
  INVESTMENT = 'investment',
  LOAN = 'loan',
  REPAYMENT = 'repayment',
  DEPOSIT = 'deposit',
  WITHDRAWAL = 'withdrawal'
}

export interface FlowRoute {
  path: string[];
  intermediaries: string[];
  methods: string[];
  currencies: string[];
  estimatedTime: number;
  cost: number;
  riskLevel: RiskLevel;
}

export interface FlowTiming {
  startTime: Date;
  endTime: Date;
  duration: number;
  frequency: number;
  regularity: string;
  unusualPatterns: TimingAnomaly[];
}

export interface TimingAnomaly {
  type: TimingAnomalyType;
  description: string;
  severity: RiskLevel;
  detected: Date;
}

export enum TimingAnomalyType {
  UNUSUAL_HOURS = 'unusual_hours',
  RAPID_SUCCESSIVE = 'rapid_successive',
  COORDINATED_TIMING = 'coordinated_timing',
  SCHEDULED_PATTERN = 'scheduled_pattern',
  BURST_ACTIVITY = 'burst_activity'
}

export enum FlowPurpose {
  PERSONAL_USE = 'personal_use',
  BUSINESS_TRANSACTION = 'business_transaction',
  INVESTMENT = 'investment',
  SPECULATION = 'speculation',
  ARBITRAGE = 'arbitrage',
  TAX_EVASION = 'tax_evasion',
  MONEY_LAUNDERING = 'money_laundering',
  REGULATORY_ARBITRAGE = 'regulatory_arbitrage'
}

export interface Intermediary {
  id: string;
  name: string;
  type: IntermediaryType;
  jurisdiction: string;
  riskLevel: RiskLevel;
  suspicious: boolean;
  details: any;
}

export enum IntermediaryType {
  EXCHANGE = 'exchange',
  WALLET = 'wallet',
  MIXER = 'mixer',
  TUMBLER = 'tumbler',
  PAYMENT_PROCESSOR = 'payment_processor',
  BANK = 'bank',
  CRYPTO_ATM = 'crypto_atm',
  P2P_PLATFORM = 'p2p_platform'
}

export interface SuspiciousIndicator {
  type: SuspiciousIndicatorType;
  description: string;
  severity: RiskLevel;
  confidence: number;
  evidence: any;
  detected: Date;
}

export enum SuspiciousIndicatorType {
  ROUND_TRIPPING = 'round_tripping',
  STRUCTURING = 'structuring',
  SHELL_COMPANY_USAGE = 'shell_company_usage',
  TREATY_SHOPPING = 'treaty_shopping',
  MIXER_USAGE = 'mixer_usage',
  PRIVACY_TOOL_USAGE = 'privacy_tool_usage',
  JURISDICTION_JUMPING = 'jurisdiction_jumping',
  AUTOMATED_BEHAVIOR = 'automated_behavior',
  UNUSUAL_TRANSACTION_SIZE = 'unusual_transaction_size',
  RAPID_SUCCESSIVE = 'rapid_successive',
  COORDINATED_TIMING = 'coordinated_timing',
  GEOGRAPHIC_ANOMALY = 'geographic_anomaly',
  TEMPORAL_ANOMALY = 'temporal_anomaly',
  CROSS_BORDER_ANOMALY = 'cross_border_anomaly'
}

export interface EvasionTechnique {
  id: string;
  name: string;
  category: EvasionCategory;
  description: string;
  indicators: string[];
  detectionRules: DetectionRule[];
  riskScore: number;
  severity: RiskLevel;
  countermeasures: Countermeasure[];
}

export enum EvasionCategory {
  PRIVACY_OBFUSCATION = 'privacy_obfuscation',
  JURISDICTION_MANIPULATION = 'jurisdiction_manipulation',
  TRANSACTION_DISGUISEMENT = 'transaction_disguisement',
  AUTOMATION_EVASION = 'automation_evasion',
  IDENTITY_MANIPULATION = 'identity_manipulation',
  STRUCTURING_TECHNIQUES = 'structuring_techniques',
  CROSS_BORDER_EVASION = 'cross_border_evasion',
  REGULATORY_LOOPHOLES = 'regulatory_loopholes'
}

export interface DetectionRule {
  id: string;
  name: string;
  condition: string;
  threshold: number;
  timeWindow: number;
  weight: number;
  enabled: boolean;
  lastUpdated: Date;
}

export interface Countermeasure {
  type: CountermeasureType;
  description: string;
  action: string;
  effectiveness: number;
  implementation: string;
  resources: string[];
}

export enum CountermeasureType {
  ENHANCED_MONITORING = 'enhanced_monitoring',
  ADDITIONAL_VERIFICATION = 'additional_verification',
  TRANSACTION_LIMITS = 'transaction_limits',
  GEOGRAPHIC_RESTRICTIONS = 'geographic_restrictions',
  DEVICE_FINGERPRINTING = 'device_fingerprinting',
  BEHAVIORAL_ANALYSIS = 'behavioral_analysis',
  AUTOMATION_DETECTION = 'automation_detection',
  PRIVACY_TOOL_DETECTION = 'privacy_tool_detection',
  REPORTING_REQUIREMENTS = 'reporting_requirements'
}

export interface ArbitrageDetection {
  id: string;
  userId: string;
  type: ArbitrageType;
  jurisdictions: string[];
  transactions: string[];
  amount: number;
  currency: string;
  profit: number;
  riskScore: number;
  evidence: any;
  detected: Date;
}

export enum ArbitrageType {
  REGULATORY = 'regulatory',
  TAX = 'tax',
  REPORTING = 'reporting',
  COMPLIANCE = 'compliance',
  JURISDICTIONAL = 'jurisdictional'
}

export interface ComplianceAlert {
  id: string;
  userId: string;
  type: AlertType;
  severity: RiskLevel;
  title: string;
  description: string;
  evidence: EvidencePackage;
  jurisdiction: string;
  regulations: string[];
  recommendations: Recommendation[];
  detected: Date;
  status: AlertStatus;
  assignedTo?: string;
  resolvedAt?: Date;
}

export enum AlertType {
  REGULATORY_ARBITRAGE = 'regulatory_arbitrage',
  TAX_EVASION = 'tax_evasion',
  JURISDICTION_JUMPING = 'jurisdiction_jumping',
  SUSPICIOUS_PATTERN = 'suspicious_pattern',
  PRIVACY_TOOL_USAGE = 'privacy_tool_usage',
  CROSS_BORDER_ANOMALY = 'cross_border_anomaly',
  AUTOMATED_BEHAVIOR = 'automated_behavior',
  COMPLIANCE_VIOLATION = 'compliance_violation',
  STRUCTURED_TRANSACTIONS = 'structured_transactions'
}

export interface EvidencePackage {
  transactionIds: string[];
  ipAddresses: string[];
  deviceFingerprints: string[];
  behavioralData: any;
  crossBorderFlows: CrossBorderFlow[];
  evasionTechniques: EvasionTechnique[];
  riskScores: RiskScore[];
  timestamps: Date[];
  screenshots: string[];
  logs: string[];
}

export interface RiskScore {
  component: string;
  score: number;
  weight: number;
  calculatedAt: Date;
  threshold: number;
  level: RiskLevel;
}

export interface Recommendation {
  type: RecommendationType;
  priority: Priority;
  description: string;
  actions: string[];
  resources: string[];
  deadline: Date;
  automated: boolean;
}

export enum RecommendationType {
  INVESTIGATION = 'investigation',
  ADDITIONAL_MONITORING = 'additional_monitoring',
  TRANSACTION_LIMITS = 'transaction_limits',
  GEOGRAPHIC_RESTRICTIONS = 'geographic_restrictions',
  DOCUMENT_VERIFICATION = 'document_verification',
  SUSPENSION = 'suspension',
  REPORTING = 'reporting',
  LEGAL_ACTION = 'legal_action'
}

export enum Priority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export enum AlertStatus {
  OPEN = 'open',
  INVESTIGATING = 'investigating',
  RESOLVED = 'resolved',
  CLOSED = 'closed',
  ESCALATED = 'escalated',
  FALSE_POSITIVE = 'false_positive'
}

export interface TaxAuthorityIntegration {
  enabled: boolean;
  authority: string;
  reportingFormat: string;
  apiEndpoint: string;
  authentication: Authentication;
  dataMapping: DataMapping;
  reportingSchedule: ReportingSchedule;
  lastSync: Date;
  syncStatus: SyncStatus;
}

export interface Authentication {
  type: AuthType;
  credentials: any;
  encryption: EncryptionConfig;
  rateLimit: RateLimit;
}

export enum AuthType {
  API_KEY = 'api_key',
  OAUTH = 'oauth',
  CERTIFICATE = 'certificate',
  BASIC_AUTH = 'basic_auth'
}

export interface EncryptionConfig {
  algorithm: string;
  keyExchange: string;
  certificate: string;
  enabled: boolean;
}

export interface RateLimit {
  requests: number;
  window: number;
  blockDuration: number;
}

export interface DataMapping {
  alertTypes: { [key: string]: string };
  riskLevels: { [key: string]: string };
  jurisdictions: { [key: string]: string };
  transactionTypes: { [key: string]: string };
  customMappings: any;
}

export interface ReportingSchedule {
  daily: boolean;
  weekly: boolean;
  monthly: boolean;
  quarterly: boolean;
  annual: boolean;
  realTime: boolean;
  immediate: boolean;
}

export enum SyncStatus {
  ACTIVE = 'active',
  SYNCING = 'syncing',
  ERROR = 'error',
  DISABLED = 'disabled'
}

export interface DetectionRules {
  id: string;
  name: string;
  version: string;
  rules: DetectionRule[];
  versionHistory: Version[];
  lastUpdated: Date;
  updateFrequency: string;
  autoUpdate: boolean;
}

export interface Version {
  version: string;
  releaseDate: Date;
  changes: string[];
  breakingChanges: boolean;
  migrationRequired: boolean;
}

export interface RegulatoryDatabase {
  jurisdictions: JurisdictionProfile[];
  evasionTechniques: EvasionTechnique[];
  detectionRules: DetectionRules;
  complianceFrameworks: ComplianceFramework[];
  lastUpdated: Date;
  updateSource: string;
}

export interface ComplianceFramework {
  name: string;
  version: string;
  jurisdiction: string;
  requirements: ComplianceRequirement[];
  penalties: Penalty[];
  guidelines: Guideline[];
  lastUpdated: Date;
}

export interface ComplianceRequirement {
  category: string;
  requirement: string;
  threshold: any;
  monitoring: boolean;
  reporting: boolean;
  enforcement: boolean;
}

export interface Penalty {
  type: PenaltyType;
  description: string;
  amount: number;
  currency: string;
  conditions: string[];
  jurisdiction: string;
}

export enum PenaltyType {
  FINE = 'fine',
  LICENSE_SUSPENSION = 'license_suspension',
  CRIMINAL_CHARGES = 'criminal_charges',
  ASSET_FREEZE = 'asset_freeze',
  IMPRISONMENT = 'imprisonment'
}

export interface Guideline {
  category: string;
  title: string;
  description: string;
  examples: string[];
  bestPractices: string[];
  references: string[];
}

export interface NetworkInterface {
  name: string;
  type: NetworkType;
  mac: string;
  ip: string;
  gateway: string;
  vpn: boolean;
  proxy: boolean;
  tor: boolean;
}

export enum NetworkType {
  ETHERNET = 'ethernet',
  WIFI = 'wifi',
  MOBILE = 'mobile',
  VPN = 'vpn',
  PROXY = 'proxy',
  TOR = 'tor'
}

export interface JurisdictionInference {
  userId: string;
  primaryJurisdiction: JurisdictionProfile;
  alternativeJurisdictions: JurisdictionProfile[];
  confidenceScores: InferenceConfidence;
  evidence: {
    geolocation: {
      source: GeolocationSource;
      data: IPGeolocation;
      confidence: number;
      timestamp: Date;
    };
    device: {
      source: DeviceSource;
      data: DeviceFingerprint;
      confidence: number;
      timestamp: Date;
    };
    behavior?: {
      source: BehaviorSource;
      data: any;
      confidence: number;
      timestamp: Date;
    };
  };
  inconsistencies: any[];
  riskScore: number;
  lastUpdated: Date;
}

export enum GeolocationSource {
  IP_GEOLOCATION = 'ip_geolocation',
  GPS = 'gps',
  WIFI_GEOLOCATION = 'wifi_geolocation',
  CELL_TOWER = 'cell_tower',
  USER_PROVIDED = 'user_provided'
}

export enum DeviceSource {
  USER_AGENT_ANALYSIS = 'user_agent_analysis',
  BROWSER_FINGERPRINT = 'browser_fingerprint',
  HARDWARE_ANALYSIS = 'hardware_analysis',
  BEHAVIORAL_ANALYSIS = 'behavioral_analysis'
}

export enum BehaviorSource {
  PATTERN_ANALYSIS = 'pattern_analysis',
  MACHINE_LEARNING = 'machine_learning',
  RULE_BASED = 'rule_based',
  HISTORICAL_COMPARISON = 'historical_comparison'
}

export interface InferenceConfidence {
  geolocation: number;
  device: number;
  behavior: number;
  overall: number;
}

export interface PatternMatch {
  patternType: PatternType;
  patternName: string;
  confidence: number;
  evidence: any;
  detected: Date;
}

export enum PatternType {
  ROUND_TRIPPING = 'round_tripping',
  STRUCTURING = 'structuring',
  JURISDICTION_SHOPPING = 'jurisdiction_shopping',
  TREATY_SHOPPING = 'treaty_shopping',
  AUTOMATION_DETECTION = 'automation_detection',
  PRIVACY_TOOL_USAGE = 'privacy_tool_usage',
  COORDINATED_BEHAVIOR = 'coordinated_behavior',
  TEMPORAL_ANOMALY = 'temporal_anomaly',
  GEOGRAPHIC_ANOMALY = 'geographic_anomaly',
  VOLUME_ANOMALY = 'volume_anomaly',
  PATTERN_ANOMALY = 'pattern_anomaly'
}

export interface SuspiciousActivity {
  type: string;
  description: string;
  severity: RiskLevel;
  confidence: number;
  evidence: any;
  detected: Date;
}

export interface ActivitySignature {
  name: string;
  description: string;
  indicators: string[];
  riskScore: number;
  severity: RiskLevel;
}

export interface FlowAnalysis {
  totalFlows: number;
  crossBorderTransactions: number;
  uniqueJurisdictions: string[];
  averageRiskScore: number;
  arbitrageOpportunities: number;
  suspiciousIndicators: SuspiciousIndicator[];
  riskDistribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  jurisdictionPatterns: {
    frequentPairs: any;
    regulatoryArbitrageRoutes: string[];
    highRiskCorridors: string[];
  };
  timingPatterns: {
    peakHours: any;
    unusualTiming: any;
    coordinatedPatterns: any;
  };
  intermediaries: any[];
}
