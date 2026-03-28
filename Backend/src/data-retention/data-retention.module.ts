import { Module } from '@nestjs/common';

import { DataRetentionController } from './data-retention.controller';
import { DataRetentionService } from './data-retention.service';
import { ObjectStorageModule } from '../object-storage/object-storage.module';
import { RedisModule } from '../redis/redis.module';

@Module({
  imports: [ObjectStorageModule, RedisModule],
  controllers: [DataRetentionController],
  providers: [DataRetentionService],
  exports: [DataRetentionService],
})
export class DataRetentionModule {}

