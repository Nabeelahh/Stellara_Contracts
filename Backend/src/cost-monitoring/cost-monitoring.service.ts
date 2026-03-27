// src/cost-monitoring/cost-monitoring.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { Cron, CronExpression } from '@nestjs/schedule';
import { firstValueFrom } from 'rxjs';

export interface CloudCostData {
  provider: 'aws' | 'azure' | 'gcp';
  region: string;
  service: string;
  cost: number;
  currency: string;
  timestamp: Date;
  resourceId?: string;
  tags?: Record<string, string>;
}

export interface CostAnalysis {
  totalCost: number;
  costByProvider: Record<string, number>;
  costByService: Record<string, number>;
  costTrend: Array<{ date: string; cost: number }>;
  recommendations: CostRecommendation[];
}

export interface CostRecommendation {
  type: 'optimization' | 'migration' | 'reservation';
  description: string;
  potentialSavings: number;
  priority: 'high' | 'medium' | 'low';
  actionItems: string[];
}

@Injectable()
export class CostMonitoringService {
  private readonly logger = new Logger(CostMonitoringService.name);
  private costData: CloudCostData[] = [];

  constructor(
    private configService: ConfigService,
    private httpService: HttpService,
  ) {}

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async collectCostData() {
    await Promise.all([
      this.collectAWSCosts(),
      this.collectAzureCosts(),
      this.collectGCPCosts(),
    ]);

    await this.analyzeCosts();
  }

  private async collectAWSCosts(): Promise<void> {
    try {
      // AWS Cost Explorer API call
      const response = await firstValueFrom(
        this.httpService.post(
          'https://ce.us-east-1.amazonaws.com/',
          {
            Service: 'AWSInsightsIndexService',
            Action: 'GetCostAndUsage',
            TimePeriod: {
              Start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
              End: new Date().toISOString().split('T')[0],
            },
            Granularity: 'DAILY',
            Metrics: ['BlendedCost'],
            GroupBy: [
              { Type: 'DIMENSION', Key: 'SERVICE' },
              { Type: 'DIMENSION', Key: 'AZ' },
            ],
          },
          {
            headers: {
              'X-Amz-Target': 'AWSInsightsIndexService.GetCostAndUsage',
              'Content-Type': 'application/x-amz-json-1.1',
            },
          }
        )
      );

      // Process AWS cost data
      const results = response.data.ResultsByTime || [];
      for (const result of results) {
        for (const group of result.Groups || []) {
          this.costData.push({
            provider: 'aws',
            region: group.Keys[1] || 'us-east-1',
            service: group.Keys[0],
            cost: parseFloat(group.Metrics.BlendedCost.Amount),
            currency: group.Metrics.BlendedCost.Unit,
            timestamp: new Date(result.TimePeriod.Start),
          });
        }
      }

      this.logger.log('Collected AWS cost data successfully');
    } catch (error) {
      this.logger.error(`Failed to collect AWS cost data: ${error.message}`);
    }
  }

  private async collectAzureCosts(): Promise<void> {
    try {
      // Azure Cost Management API call
      const response = await firstValueFrom(
        this.httpService.post(
          'https://management.azure.com/providers/Microsoft.CostManagement/query',
          {
            type: 'ActualCost',
            timeframe: 'MonthToDate',
            dataset: {
              granularity: 'Daily',
              aggregation: {
                totalCost: {
                  name: 'Cost',
                  function: 'Sum',
                },
              },
              grouping: [
                { type: 'Dimension', name: 'ResourceGroup' },
                { type: 'Dimension', name: 'ResourceType' },
              ],
            },
          },
          {
            headers: {
              'Authorization': `Bearer ${this.configService.get<string>('AZURE_ACCESS_TOKEN')}`,
              'Content-Type': 'application/json',
            },
          }
        )
      );

      // Process Azure cost data
      const rows = response.data.properties.rows || [];
      for (const row of rows) {
        this.costData.push({
          provider: 'azure',
          region: row[2] || 'uksouth', // Resource location
          service: row[1], // Resource type
          cost: parseFloat(row[0]), // Cost
          currency: 'USD',
          timestamp: new Date(),
          resourceId: row[3], // Resource ID
        });
      }

      this.logger.log('Collected Azure cost data successfully');
    } catch (error) {
      this.logger.error(`Failed to collect Azure cost data: ${error.message}`);
    }
  }

  private async collectGCPCosts(): Promise<void> {
    try {
      // Google Cloud Billing API call
      const response = await firstValueFrom(
        this.httpService.post(
          `https://cloudbilling.googleapis.com/v1/projects/${this.configService.get<string>('GCP_PROJECT_ID')}/billingInfo`,
          {
            // GCP Billing Catalog API request
          },
          {
            headers: {
              'Authorization': `Bearer ${this.configService.get<string>('GCP_ACCESS_TOKEN')}`,
              'Content-Type': 'application/json',
            },
          }
        )
      );

      // Process GCP cost data
      // Note: GCP cost collection is more complex and would require
      // BigQuery integration for detailed cost analysis

      this.logger.log('Collected GCP cost data successfully');
    } catch (error) {
      this.logger.error(`Failed to collect GCP cost data: ${error.message}`);
    }
  }

  private async analyzeCosts(): Promise<void> {
    const analysis = this.generateCostAnalysis();

    // Store analysis results
    await this.storeCostAnalysis(analysis);

    // Send alerts for cost anomalies
    await this.checkCostAlerts(analysis);

    // Generate recommendations
    const recommendations = await this.generateRecommendations(analysis);
    await this.storeRecommendations(recommendations);
  }

  private generateCostAnalysis(): CostAnalysis {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    const recentData = this.costData.filter(d => d.timestamp >= thirtyDaysAgo);

    const totalCost = recentData.reduce((sum, d) => sum + d.cost, 0);

    const costByProvider = recentData.reduce((acc, d) => {
      acc[d.provider] = (acc[d.provider] || 0) + d.cost;
      return acc;
    }, {} as Record<string, number>);

    const costByService = recentData.reduce((acc, d) => {
      acc[d.service] = (acc[d.service] || 0) + d.cost;
      return acc;
    }, {} as Record<string, number>);

    // Calculate cost trend
    const costTrend = [];
    for (let i = 29; i >= 0; i--) {
      const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      const dayData = recentData.filter(d =>
        d.timestamp.toDateString() === date.toDateString()
      );
      const dayCost = dayData.reduce((sum, d) => sum + d.cost, 0);
      costTrend.push({
        date: date.toISOString().split('T')[0],
        cost: dayCost,
      });
    }

    return {
      totalCost,
      costByProvider,
      costByService,
      costTrend,
      recommendations: [], // Will be filled by generateRecommendations
    };
  }

  private async generateRecommendations(analysis: CostAnalysis): Promise<CostRecommendation[]> {
    const recommendations: CostRecommendation[] = [];

    // Check for high-cost services
    const highCostServices = Object.entries(analysis.costByService)
      .filter(([, cost]) => cost > 1000) // Threshold for "high cost"
      .sort(([, a], [, b]) => b - a);

    for (const [service, cost] of highCostServices.slice(0, 3)) {
      recommendations.push({
        type: 'optimization',
        description: `High cost detected for ${service}: $${cost.toFixed(2)}`,
        potentialSavings: cost * 0.2, // Assume 20% optimization potential
        priority: 'high',
        actionItems: [
          `Review ${service} usage patterns`,
          `Consider reserved instances for ${service}`,
          `Evaluate alternative providers for ${service}`,
        ],
      });
    }

    // Check for provider cost imbalances
    const providers = Object.keys(analysis.costByProvider);
    if (providers.length > 1) {
      const avgCost = analysis.totalCost / providers.length;
      for (const [provider, cost] of Object.entries(analysis.costByProvider)) {
        if (cost > avgCost * 1.5) { // 50% above average
          recommendations.push({
            type: 'migration',
            description: `${provider} costs are 50% above average`,
            potentialSavings: cost - avgCost,
            priority: 'medium',
            actionItems: [
              `Evaluate migrating workloads from ${provider}`,
              `Compare pricing for similar services across providers`,
              `Consider workload redistribution`,
            ],
          });
        }
      }
    }

    return recommendations;
  }

  private async storeCostAnalysis(analysis: CostAnalysis): Promise<void> {
    // TODO: Store in database
    this.logger.log(`Stored cost analysis: Total cost $${analysis.totalCost.toFixed(2)}`);
  }

  private async storeRecommendations(recommendations: CostRecommendation[]): Promise<void> {
    // TODO: Store recommendations in database
    this.logger.log(`Generated ${recommendations.length} cost recommendations`);
  }

  private async checkCostAlerts(analysis: CostAnalysis): Promise<void> {
    const costThreshold = this.configService.get<number>('COST_ALERT_THRESHOLD', 5000);

    if (analysis.totalCost > costThreshold) {
      this.logger.warn(`Cost alert: Total cost $${analysis.totalCost.toFixed(2)} exceeds threshold $${costThreshold}`);

      // TODO: Send alert notifications
    }
  }

  // Public API methods
  async getCostAnalysis(): Promise<CostAnalysis> {
    return this.generateCostAnalysis();
  }

  async getCostData(
    provider?: string,
    startDate?: Date,
    endDate?: Date
  ): Promise<CloudCostData[]> {
    return this.costData.filter(d => {
      if (provider && d.provider !== provider) return false;
      if (startDate && d.timestamp < startDate) return false;
      if (endDate && d.timestamp > endDate) return false;
      return true;
    });
  }
}