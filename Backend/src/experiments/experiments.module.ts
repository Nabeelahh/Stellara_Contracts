import { Module, Global } from '@nestjs/common';
import { ExperimentsService } from './experiments.service';
import { ExperimentsController } from './experiments.controller';
import { BucketerService } from './bucketer.service';
import { StatisticsEngineService } from './engine.service';
import { ExperimentExporterService } from './exporter.service';
import { PrismaService } from '../prisma.service';

/**
 * Global Experiments Module for management and assignment of A/B tests.
 */
@Global()
@Module({
  controllers: [ExperimentsController],
  providers: [
    ExperimentsService,
    BucketerService,
    StatisticsEngineService,
    ExperimentExporterService,
    PrismaService,
  ],
  exports: [ExperimentsService],
})
export class ExperimentsModule {}
