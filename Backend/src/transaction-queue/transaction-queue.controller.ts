import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { EnqueueTransactionDto } from './dto/transaction-queue.dto';
import { TransactionQueueService } from './transaction-queue.service';

@Controller('transaction-queue')
export class TransactionQueueController {
  constructor(private readonly queueService: TransactionQueueService) {}

  @Post('enqueue')
  enqueue(@Body() dto: EnqueueTransactionDto) {
    return this.queueService.enqueue(dto);
  }

  @Get('summary')
  summary() {
    return this.queueService.getSummary();
  }

  @Get('idempotency/:idempotencyKey')
  getByIdempotencyKey(@Param('idempotencyKey') idempotencyKey: string) {
    return this.queueService.getByIdempotencyKey(idempotencyKey);
  }

  @Get('nonce/:signerAddress')
  getSignerNonce(@Param('signerAddress') signerAddress: string) {
    return this.queueService.getSignerNonceState(signerAddress);
  }

  @Post(':id/retry')
  retry(@Param('id') id: string) {
    return this.queueService.retryNow(id);
  }

  @Post(':id/cancel')
  cancel(@Param('id') id: string) {
    return this.queueService.cancel(id);
  }

  @Get(':id')
  getById(@Param('id') id: string) {
    return this.queueService.getById(id);
  }
}

