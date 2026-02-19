import { Module, Global } from '@nestjs/common';
import { ThrottleService } from './throttle.service';
import { ThrottleGuard } from './throttle.guard';
import { DistributedThrottleGuard } from './distributed-throttle.guard';
import { DistributedRateLimitService } from './distributed-rate-limit.service';
import { RoleBasedRateLimitService } from './role-based-rate-limit.service';
import { RateLimitMetricsCollector } from './rate-limit-metrics.collector';
import { RedisModule } from '../redis/redis.module';

@Global()
@Module({
  imports: [RedisModule],
  providers: [
    // Legacy services
    ThrottleService,
    ThrottleGuard,
    // New distributed rate limiting services
    DistributedRateLimitService,
    RoleBasedRateLimitService,
    DistributedThrottleGuard,
    RateLimitMetricsCollector,
  ],
  exports: [
    // Legacy exports
    ThrottleGuard,
    // New exports
    DistributedRateLimitService,
    RoleBasedRateLimitService,
    DistributedThrottleGuard,
    RateLimitMetricsCollector,
  ],
})
export class ThrottleModule {}
