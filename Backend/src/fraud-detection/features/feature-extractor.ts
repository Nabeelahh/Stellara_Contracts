import { Injectable, Logger } from '@nestjs/common';
import { Redis } from 'ioredis';

/**
 * Transaction Data
 */
export interface Transaction {
  id: string;
  userId: string;
  amount: number;
  currency: string;
  timestamp: Date;
  deviceId?: string;
  ipAddress?: string;
  location?: {
    latitude: number;
    longitude: number;
    country: string;
    city: string;
  };
  merchantId?: string;
  paymentMethod: string;
  metadata?: Record<string, unknown>;
}

/**
 * User Profile
 */
export interface UserProfile {
  userId: string;
  accountAge: number; // days
  kycLevel: string;
  totalTransactions: number;
  totalVolume: number;
  averageTransactionAmount: number;
  lastTransactionDate?: Date;
  typicalLocations: string[];
  typicalDevices: string[];
  riskScore: number;
}

/**
 * Extracted Features
 */
export interface FraudFeatures {
  // Transaction features
  amount: number;
  amountDeviationFromAverage: number;
  timeSinceLastTransaction: number; // hours
  
  // Velocity features
  transactionsLastHour: number;
  transactionsLastDay: number;
  transactionsLastWeek: number;
  amountVelocityHourly: number;
  amountVelocityDaily: number;
  
  // Device features
  deviceFingerprint: string;
  isNewDevice: boolean;
  deviceRiskScore: number;
  deviceTransactionCount: number;
  
  // Location features
  locationRiskScore: number;
  isNewLocation: boolean;
  distanceFromTypicalLocation: number; // km
  isHighRiskCountry: boolean;
  
  // Network features
  ipRiskScore: number;
  isVpn: boolean;
  isTor: boolean;
  isProxy: boolean;
  
  // Behavioral features
  hourOfDay: number;
  dayOfWeek: number;
  isWeekend: boolean;
  isBusinessHours: boolean;
  
  // Historical features
  userAccountAge: number; // days
  userTotalTransactions: number;
  userAverageAmount: number;
  userChargebackRate: number;
  
  // Merchant features
  merchantRiskScore: number;
  merchantCategoryRisk: number;
}

/**
 * Feature Extractor Service
 * 
 * Extracts real-time features from transactions for fraud detection.
 * Uses Redis for fast access to historical data.
 */
@Injectable()
export class FeatureExtractor {
  private readonly logger = new Logger(FeatureExtractor.name);

  constructor(private readonly redis: Redis) {}

  /**
   * Extract features from a transaction in real-time
   */
  async extractFeatures(
    transaction: Transaction,
    userProfile: UserProfile
  ): Promise<FraudFeatures> {
    const startTime = Date.now();

    const [
      velocityFeatures,
      deviceFeatures,
      locationFeatures,
      networkFeatures,
      behavioralFeatures,
    ] = await Promise.all([
      this.extractVelocityFeatures(transaction),
      this.extractDeviceFeatures(transaction),
      this.extractLocationFeatures(transaction, userProfile),
      this.extractNetworkFeatures(transaction),
      this.extractBehavioralFeatures(transaction),
    ]);

    const features: FraudFeatures = {
      // Transaction features
      amount: transaction.amount,
      amountDeviationFromAverage: this.calculateAmountDeviation(
        transaction.amount,
        userProfile.averageTransactionAmount
      ),
      timeSinceLastTransaction: this.calculateTimeSinceLastTransaction(
        userProfile.lastTransactionDate
      ),
      
      // Velocity features
      ...velocityFeatures,
      
      // Device features
      ...deviceFeatures,
      
      // Location features
      ...locationFeatures,
      
      // Network features
      ...networkFeatures,
      
      // Behavioral features
      ...behavioralFeatures,
      
      // Historical features
      userAccountAge: userProfile.accountAge,
      userTotalTransactions: userProfile.totalTransactions,
      userAverageAmount: userProfile.averageTransactionAmount,
      userChargebackRate: await this.getUserChargebackRate(transaction.userId),
      
      // Merchant features
      merchantRiskScore: await this.getMerchantRiskScore(transaction.merchantId),
      merchantCategoryRisk: await this.getMerchantCategoryRisk(transaction.merchantId),
    };

    const duration = Date.now() - startTime;
    this.logger.debug(`Feature extraction completed in ${duration}ms`);

    return features;
  }

  /**
   * Extract velocity-based features
   */
  private async extractVelocityFeatures(
    transaction: Transaction
  ): Promise<Partial<FraudFeatures>> {
    const userId = transaction.userId;
    const now = new Date();
    
    // Get transaction counts from Redis
    const [
      hourlyCount,
      dailyCount,
      weeklyCount,
      hourlyAmount,
      dailyAmount,
    ] = await Promise.all([
      this.getTransactionCount(userId, '1h'),
      this.getTransactionCount(userId, '24h'),
      this.getTransactionCount(userId, '7d'),
      this.getTransactionAmount(userId, '1h'),
      this.getTransactionAmount(userId, '24h'),
    ]);

    return {
      transactionsLastHour: hourlyCount,
      transactionsLastDay: dailyCount,
      transactionsLastWeek: weeklyCount,
      amountVelocityHourly: hourlyAmount,
      amountVelocityDaily: dailyAmount,
    };
  }

  /**
   * Extract device-based features
   */
  private async extractDeviceFeatures(
    transaction: Transaction
  ): Promise<Partial<FraudFeatures>> {
    const deviceId = transaction.deviceId || 'unknown';
    const userId = transaction.userId;
    
    // Generate device fingerprint
    const fingerprint = await this.generateDeviceFingerprint(deviceId, transaction);
    
    // Check if device is new for this user
    const isNewDevice = await this.isNewDeviceForUser(userId, deviceId);
    
    // Get device risk score
    const deviceRiskScore = await this.getDeviceRiskScore(deviceId);
    
    // Get device transaction count
    const deviceTransactionCount = await this.getDeviceTransactionCount(deviceId);

    return {
      deviceFingerprint: fingerprint,
      isNewDevice,
      deviceRiskScore,
      deviceTransactionCount,
    };
  }

  /**
   * Extract location-based features
   */
  private async extractLocationFeatures(
    transaction: Transaction,
    userProfile: UserProfile
  ): Promise<Partial<FraudFeatures>> {
    const location = transaction.location;
    
    if (!location) {
      return {
        locationRiskScore: 0.5,
        isNewLocation: false,
        distanceFromTypicalLocation: 0,
        isHighRiskCountry: false,
      };
    }

    // Check if location is new
    const isNewLocation = !userProfile.typicalLocations.includes(location.country);
    
    // Calculate distance from typical location
    const distance = await this.calculateDistanceFromTypicalLocation(
      location,
      userProfile.typicalLocations
    );
    
    // Check if high-risk country
    const isHighRiskCountry = await this.isHighRiskCountry(location.country);
    
    // Get location risk score
    const locationRiskScore = await this.getLocationRiskScore(location);

    return {
      locationRiskScore,
      isNewLocation,
      distanceFromTypicalLocation: distance,
      isHighRiskCountry,
    };
  }

  /**
   * Extract network-based features
   */
  private async extractNetworkFeatures(
    transaction: Transaction
  ): Promise<Partial<FraudFeatures>> {
    const ipAddress = transaction.ipAddress;
    
    if (!ipAddress) {
      return {
        ipRiskScore: 0.5,
        isVpn: false,
        isTor: false,
        isProxy: false,
      };
    }

    // Check IP reputation
    const [ipRiskScore, isVpn, isTor, isProxy] = await Promise.all([
      this.getIpRiskScore(ipAddress),
      this.checkIsVpn(ipAddress),
      this.checkIsTor(ipAddress),
      this.checkIsProxy(ipAddress),
    ]);

    return {
      ipRiskScore,
      isVpn,
      isTor,
      isProxy,
    };
  }

  /**
   * Extract behavioral features
   */
  private extractBehavioralFeatures(
    transaction: Transaction
  ): Partial<FraudFeatures> {
    const timestamp = new Date(transaction.timestamp);
    const hour = timestamp.getHours();
    const dayOfWeek = timestamp.getDay();
    
    return {
      hourOfDay: hour,
      dayOfWeek: dayOfWeek,
      isWeekend: dayOfWeek === 0 || dayOfWeek === 6,
      isBusinessHours: hour >= 9 && hour <= 17,
    };
  }

  // Helper methods

  private calculateAmountDeviation(amount: number, average: number): number {
    if (average === 0) return 0;
    return (amount - average) / average;
  }

  private calculateTimeSinceLastTransaction(lastDate?: Date): number {
    if (!lastDate) return Infinity;
    const hours = (Date.now() - lastDate.getTime()) / (1000 * 60 * 60);
    return hours;
  }

  private async getTransactionCount(userId: string, window: string): Promise<number> {
    const key = `tx:count:${userId}:${window}`;
    const count = await this.redis.get(key);
    return parseInt(count || '0', 10);
  }

  private async getTransactionAmount(userId: string, window: string): Promise<number> {
    const key = `tx:amount:${userId}:${window}`;
    const amount = await this.redis.get(key);
    return parseFloat(amount || '0');
  }

  private async generateDeviceFingerprint(
    deviceId: string,
    transaction: Transaction
  ): Promise<string> {
    // Simplified fingerprint generation
    const data = `${deviceId}:${transaction.ipAddress}:${transaction.metadata?.userAgent || ''}`;
    return Buffer.from(data).toString('base64').substring(0, 32);
  }

  private async isNewDeviceForUser(userId: string, deviceId: string): Promise<boolean> {
    const key = `user:devices:${userId}`;
    const isMember = await this.redis.sismember(key, deviceId);
    return isMember === 0;
  }

  private async getDeviceRiskScore(deviceId: string): Promise<number> {
    const key = `device:risk:${deviceId}`;
    const score = await this.redis.get(key);
    return parseFloat(score || '0.5');
  }

  private async getDeviceTransactionCount(deviceId: string): Promise<number> {
    const key = `device:txcount:${deviceId}`;
    const count = await this.redis.get(key);
    return parseInt(count || '0', 10);
  }

  private async calculateDistanceFromTypicalLocation(
    location: { latitude: number; longitude: number },
    typicalLocations: string[]
  ): Promise<number> {
    // Simplified distance calculation
    // In production, use proper geolocation database
    if (typicalLocations.length === 0) return 0;
    return Math.random() * 1000; // Placeholder
  }

  private async isHighRiskCountry(country: string): Promise<boolean> {
    const highRiskCountries = ['XX', 'YY', 'ZZ']; // Placeholder
    return highRiskCountries.includes(country);
  }

  private async getLocationRiskScore(location: { country: string }): Promise<number> {
    const key = `location:risk:${location.country}`;
    const score = await this.redis.get(key);
    return parseFloat(score || '0.5');
  }

  private async getIpRiskScore(ipAddress: string): Promise<number> {
    const key = `ip:risk:${ipAddress}`;
    const score = await this.redis.get(key);
    return parseFloat(score || '0.5');
  }

  private async checkIsVpn(ipAddress: string): Promise<boolean> {
    const key = `ip:vpn:${ipAddress}`;
    const isVpn = await this.redis.get(key);
    return isVpn === '1';
  }

  private async checkIsTor(ipAddress: string): Promise<boolean> {
    const key = `ip:tor:${ipAddress}`;
    const isTor = await this.redis.get(key);
    return isTor === '1';
  }

  private async checkIsProxy(ipAddress: string): Promise<boolean> {
    const key = `ip:proxy:${ipAddress}`;
    const isProxy = await this.redis.get(key);
    return isProxy === '1';
  }

  private async getUserChargebackRate(userId: string): Promise<number> {
    const key = `user:chargeback:${userId}`;
    const rate = await this.redis.get(key);
    return parseFloat(rate || '0');
  }

  private async getMerchantRiskScore(merchantId?: string): Promise<number> {
    if (!merchantId) return 0.5;
    const key = `merchant:risk:${merchantId}`;
    const score = await this.redis.get(key);
    return parseFloat(score || '0.5');
  }

  private async getMerchantCategoryRisk(merchantId?: string): Promise<number> {
    if (!merchantId) return 0.5;
    const key = `merchant:category:risk:${merchantId}`;
    const score = await this.redis.get(key);
    return parseFloat(score || '0.5');
  }
}
