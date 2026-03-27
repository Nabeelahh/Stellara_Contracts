// src/failover/failover.module.ts
import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ScheduleModule } from '@nestjs/schedule';
import { FailoverService } from './failover.service';

@Module({
  imports: [HttpModule, ScheduleModule.forRoot()],
  providers: [FailoverService],
  exports: [FailoverService],
})
export class FailoverModule {}