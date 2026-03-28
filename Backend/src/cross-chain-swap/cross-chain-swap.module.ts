import { Module } from '@nestjs/common';
import { CrossChainSwapService } from './cross-chain-swap.service';
import { CrossChainSwapController } from './cross-chain-swap.controller';
import { HtlcService } from './htlc.service';
import { PrismaModule } from '../prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [CrossChainSwapController],
  providers: [CrossChainSwapService, HtlcService],
  exports: [CrossChainSwapService, HtlcService],
})
export class CrossChainSwapModule {}
