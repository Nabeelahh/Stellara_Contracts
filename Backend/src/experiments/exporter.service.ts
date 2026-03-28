import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { ExperimentsService } from './experiments.service';
import { PrismaService } from '../prisma.service';

@Injectable()
export class ExperimentExporterService {
  private readonly logger = new Logger(ExperimentExporterService.name);

  constructor(
    private readonly experimentsService: ExperimentsService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * Daily export of experiment results to the "data warehouse" (mocked as a log/file export).
   */
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async exportResults() {
    this.logger.log('Starting scheduled experiment result export...');
    
    const experiments = await (this.prisma as any).experiment.findMany({
      where: { status: { in: ['ACTIVE', 'COMPLETED'] } },
    });

    for (const exp of experiments) {
      const analysis = await this.experimentsService.getDetailedAnalysis(exp.key);
      if (analysis) {
        // Mock export to data warehouse
        await this.syncToWarehouse(exp.key, analysis);
      }
    }

    this.logger.log(`Exported results for ${experiments.length} experiments.`);
  }

  private async syncToWarehouse(key: string, data: any) {
    // In a real scenario, this would push to Snowflake, BigQuery, or a S3 bucket
    this.logger.debug(`[WAREHOUSE] Exporting ${key}: ${JSON.stringify(data.global)}`);
    // Example: append to a JSONL file or hit an external API
  }
}
