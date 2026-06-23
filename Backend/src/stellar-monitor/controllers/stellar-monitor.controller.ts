import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Param,
  Body,
  Query,
  HttpStatus,
  HttpException,
  UseInterceptors,
  ClassSerializerInterceptor,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { ConsumerManagementService } from '../services/consumer-management.service';
import { EventStorageService } from '../services/event-storage.service';
import { StellarEventMonitorService } from '../services/stellar-event-monitor.service';
import { WebhookDeliveryService } from '../services/webhook-delivery.service';
import { CreateConsumerDto } from '../dto/create-consumer.dto';
import { UpdateConsumerDto } from '../dto/update-consumer.dto';
import { WebhookConsumer } from '../entities/webhook-consumer.entity';
import { StellarEvent } from '../entities/stellar-event.entity';
import { EventType, DeliveryStatus } from '../types/stellar.types';
import { IsString, Length } from 'class-validator';

class RotateSecretDto {
  @IsString()
  @Length(1, 100)
  secret: string;
}

@ApiTags('Stellar Monitor')
@Controller('api/stellar')
@UseInterceptors(ClassSerializerInterceptor)
export class StellarMonitorController {
  constructor(
    private readonly consumerService: ConsumerManagementService,
    private readonly eventService: EventStorageService,
    private readonly monitorService: StellarEventMonitorService,
    private readonly webhookService: WebhookDeliveryService,
  ) {}

  // Consumer Management Endpoints

  @Post('consumers')
  @ApiOperation({ summary: 'Register a new webhook consumer' })
  @ApiResponse({ status: 201, description: 'Consumer created successfully' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  async createConsumer(
    @Body() createDto: CreateConsumerDto,
  ): Promise<WebhookConsumer> {
    try {
      return await this.consumerService.createConsumer(createDto);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.BAD_REQUEST);
    }
  }

  @Get('consumers')
  @ApiOperation({ summary: 'List all webhook consumers' })
  @ApiQuery({ name: 'activeOnly', required: false, type: Boolean })
  @ApiResponse({ status: 200, description: 'List of consumers' })
  async getConsumers(
    @Query('activeOnly') activeOnly?: string,
  ): Promise<WebhookConsumer[]> {
    const isActiveOnly = activeOnly === 'true';
    return this.consumerService.getAllConsumers(isActiveOnly);
  }

  @Get('consumers/:id')
  @ApiOperation({ summary: 'Get a specific webhook consumer' })
  @ApiParam({ name: 'id', description: 'Consumer ID' })
  @ApiResponse({ status: 200, description: 'Consumer details' })
  @ApiResponse({ status: 404, description: 'Consumer not found' })
  async getConsumer(@Param('id') id: string): Promise<WebhookConsumer> {
    try {
      return await this.consumerService.getConsumerById(id);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }

  @Put('consumers/:id')
  @ApiOperation({ summary: 'Update a webhook consumer' })
  @ApiParam({ name: 'id', description: 'Consumer ID' })
  @ApiResponse({ status: 200, description: 'Consumer updated successfully' })
  @ApiResponse({ status: 404, description: 'Consumer not found' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  async updateConsumer(
    @Param('id') id: string,
    @Body() updateDto: UpdateConsumerDto,
  ): Promise<WebhookConsumer> {
    try {
      return await this.consumerService.updateConsumer(id, updateDto);
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(error.message, HttpStatus.BAD_REQUEST);
    }
  }

  @Delete('consumers/:id')
  @ApiOperation({ summary: 'Delete a webhook consumer' })
  @ApiParam({ name: 'id', description: 'Consumer ID' })
  @ApiResponse({ status: 204, description: 'Consumer deleted successfully' })
  @ApiResponse({ status: 404, description: 'Consumer not found' })
  async deleteConsumer(@Param('id') id: string): Promise<void> {
    try {
      await this.consumerService.deleteConsumer(id);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }

  @Post('consumers/:id/activate')
  @ApiOperation({ summary: 'Activate a webhook consumer' })
  @ApiParam({ name: 'id', description: 'Consumer ID' })
  @ApiResponse({ status: 200, description: 'Consumer activated' })
  @ApiResponse({ status: 404, description: 'Consumer not found' })
  async activateConsumer(@Param('id') id: string): Promise<WebhookConsumer> {
    try {
      return await this.consumerService.activateConsumer(id);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }

  @Post('consumers/:id/deactivate')
  @ApiOperation({ summary: 'Deactivate a webhook consumer' })
  @ApiParam({ name: 'id', description: 'Consumer ID' })
  @ApiResponse({ status: 200, description: 'Consumer deactivated' })
  @ApiResponse({ status: 404, description: 'Consumer not found' })
  async deactivateConsumer(@Param('id') id: string): Promise<WebhookConsumer> {
    try {
      return await this.consumerService.deactivateConsumer(id);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }

  @Post('consumers/:id/test')
  @ApiOperation({ summary: 'Test webhook delivery to a consumer' })
  @ApiParam({ name: 'id', description: 'Consumer ID' })
  @ApiResponse({ status: 200, description: 'Test delivery result' })
  @ApiResponse({ status: 404, description: 'Consumer not found' })
  async testConsumer(@Param('id') id: string): Promise<any> {
    try {
      const result = await this.webhookService.deliverTestEvent(id);
      return {
        consumerId: id,
        success: result.success,
        statusCode: result.statusCode,
        errorMessage: result.errorMessage,
      };
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }

  @Post('consumers/:id/rotate-secret')
  @ApiOperation({ summary: 'Rotate the signing secret for a webhook consumer' })
  @ApiParam({ name: 'id', description: 'Consumer ID' })
  @ApiResponse({ status: 204, description: 'Secret rotated successfully' })
  @ApiResponse({ status: 404, description: 'Consumer not found' })
  async rotateSecret(
    @Param('id') id: string,
    @Body() body: RotateSecretDto,
  ): Promise<void> {
    try {
      await this.consumerService.rotateSecret(id, body.secret);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }

  // Event Monitoring Endpoints

  @Get('events')
  @ApiOperation({ summary: 'List stellar events' })
  @ApiQuery({ name: 'page', required: false, type: Number })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'eventType', required: false, enum: EventType })
  @ApiQuery({ name: 'deliveryStatus', required: false, enum: DeliveryStatus })
  @ApiResponse({ status: 200, description: 'List of events' })
  async getEvents(
    @Query('page') page?: string,
    @Query('limit') limit?: string,
    @Query('eventType') eventType?: EventType,
    @Query('deliveryStatus') deliveryStatus?: DeliveryStatus,
  ): Promise<{
    events: StellarEvent[];
    total: number;
    page: number;
    limit: number;
  }> {
    const pageNum = parseInt(page || '1', 10);
    const limitNum = parseInt(limit || '50', 10);

    const [events, total] = await this.eventService.getEvents(
      pageNum,
      limitNum,
      eventType,
      undefined,
      undefined,
      deliveryStatus,
    );

    return {
      events,
      total,
      page: pageNum,
      limit: limitNum,
    };
  }

  @Get('events/:id')
  @ApiOperation({ summary: 'Get a specific stellar event' })
  @ApiParam({ name: 'id', description: 'Event ID' })
  @ApiResponse({ status: 200, description: 'Event details' })
  @ApiResponse({ status: 404, description: 'Event not found' })
  async getEvent(@Param('id') id: string): Promise<StellarEvent> {
    const event = await this.eventService.getEventById(id);
    if (!event) {
      throw new HttpException('Event not found', HttpStatus.NOT_FOUND);
    }
    return event;
  }

  @Get('stats')
  @ApiOperation({ summary: 'Get monitoring statistics' })
  @ApiResponse({ status: 200, description: 'Statistics data' })
  async getStats(): Promise<any> {
    const [eventStats, consumerStats, deliveryStats] = await Promise.all([
      this.eventService.getStats(),
      this.consumerService.getStats(),
      this.webhookService.getDeliveryStats(),
    ]);

    return {
      events: eventStats,
      consumers: consumerStats,
      delivery: deliveryStats,
      monitor: this.monitorService.getStatus(),
    };
  }

  // Monitoring Control Endpoints

  @Post('monitor/start')
  @ApiOperation({ summary: 'Start stellar event monitoring' })
  @ApiResponse({ status: 200, description: 'Monitoring started' })
  async startMonitoring(): Promise<{ message: string; status: any }> {
    await this.monitorService.startMonitoring();
    return {
      message: 'Monitoring started successfully',
      status: this.monitorService.getStatus(),
    };
  }

  @Post('monitor/stop')
  @ApiOperation({ summary: 'Stop stellar event monitoring' })
  @ApiResponse({ status: 200, description: 'Monitoring stopped' })
  async stopMonitoring(): Promise<{ message: string }> {
    await this.monitorService.stopMonitoring();
    return { message: 'Monitoring stopped successfully' };
  }

  @Get('monitor/status')
  @ApiOperation({ summary: 'Get monitoring status' })
  @ApiResponse({ status: 200, description: 'Monitoring status' })
  async getMonitoringStatus(): Promise<any> {
    return this.monitorService.getStatus();
  }

  // Simulation Endpoints (for testing)

  @Post('simulate/payment')
  @ApiOperation({ summary: 'Simulate a payment event' })
  @ApiResponse({ status: 201, description: 'Simulated event created' })
  async simulatePayment(
    @Body()
    body?: {
      from?: string;
      to?: string;
      amount?: string;
      assetType?: string;
    },
  ): Promise<StellarEvent> {
    return this.monitorService.simulatePaymentEvent(
      body?.from,
      body?.to,
      body?.amount || '100',
      body?.assetType || 'native',
    );
  }

  @Post('simulate/offer')
  @ApiOperation({ summary: 'Simulate an offer event' })
  @ApiResponse({ status: 201, description: 'Simulated event created' })
  async simulateOffer(
    @Body()
    body?: {
      seller?: string;
      sellingAmount?: string;
      buyingAmount?: string;
    },
  ): Promise<StellarEvent> {
    return this.monitorService.simulateOfferEvent(
      body?.seller,
      body?.sellingAmount || '1000',
      body?.buyingAmount || '50',
    );
  }
}
