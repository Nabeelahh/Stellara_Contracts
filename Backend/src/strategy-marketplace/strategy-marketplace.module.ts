import { Module } from '@nestjs/common';
import { StrategyMarketplaceController } from './strategy-marketplace.controller';
import { StrategyMarketplaceService } from './services/strategy-marketplace.service';

@Module({
  controllers: [StrategyMarketplaceController],
  providers: [StrategyMarketplaceService],
  exports: [StrategyMarketplaceService],
})
export class StrategyMarketplaceModule {}
