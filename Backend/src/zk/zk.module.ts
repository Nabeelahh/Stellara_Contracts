import { Module } from '@nestjs/common';
import { ZkService } from './zk.service';
import { ZkController } from './zk.controller';

@Module({
  imports: [],
  providers: [ZkService],
  controllers: [ZkController],
  exports: [ZkService],
})
export class ZkModule {}
