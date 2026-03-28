import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { CircuitBreakerModule } from '../circuit-breaker/circuit-breaker.module';
import { TransactionQueueController } from './transaction-queue.controller';
import { TransactionQueueService } from './transaction-queue.service';
import { TransactionGatewayService } from './transaction-gateway.service';

@Module({
  imports: [ConfigModule, CircuitBreakerModule],
  controllers: [TransactionQueueController],
  providers: [TransactionQueueService, TransactionGatewayService],
  exports: [TransactionQueueService],
})
export class TransactionQueueModule {}

