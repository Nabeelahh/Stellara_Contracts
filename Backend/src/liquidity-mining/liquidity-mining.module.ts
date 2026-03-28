import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma.module';
import { LiquidityMiningService } from './liquidity-mining.service';
import { LiquidityMiningController } from './liquidity-mining.controller';

@Module({
  imports: [PrismaModule],
  controllers: [LiquidityMiningController],
  providers: [LiquidityMiningService],
  exports: [LiquidityMiningService],
})
export class LiquidityMiningModule {}
