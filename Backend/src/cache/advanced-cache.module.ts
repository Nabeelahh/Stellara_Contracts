import { Module } from '@nestjs/common';
import { AdvancedCacheService } from './advanced-cache.service';
import { CacheWarmingService } from './cache-warming.service';

@Module({
  providers: [AdvancedCacheService, CacheWarmingService],
  exports: [AdvancedCacheService, CacheWarmingService],
})
export class AdvancedCacheModule {}
