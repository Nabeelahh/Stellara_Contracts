import { Module } from '@nestjs/common';
import { CollateralService } from './collateral.service';
import { CollateralController } from './collateral.controller';
import { OracleService } from './oracle.service';
import { LiquidationService } from './liquidation.service';
import { PrismaModule } from '../prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [CollateralController],
  providers: [
    CollateralService,
    OracleService,
    LiquidationService,
  ],
  exports: [CollateralService, LiquidationService, OracleService],
})
export class CollateralModule {}
