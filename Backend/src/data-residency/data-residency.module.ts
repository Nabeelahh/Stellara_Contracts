// src/data-residency/data-residency.module.ts
import { Module } from '@nestjs/common';
import { DataResidencyService } from './data-residency.service';

@Module({
  providers: [DataResidencyService],
  exports: [DataResidencyService],
})
export class DataResidencyModule {}