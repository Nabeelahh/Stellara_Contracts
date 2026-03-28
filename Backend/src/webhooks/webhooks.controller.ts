import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { RolesGuard } from '../auth/guards/roles.guard';
import {
  CreateWebhookSubscriptionDto,
  DeliveryQueryDto,
  PublishWebhookEventDto,
  UpdateWebhookSubscriptionDto,
} from './dto/webhook.dto';
import { WebhooksService } from './webhooks.service';

@ApiTags('webhooks')
@ApiBearerAuth('JWT-auth')
@Controller('webhooks')
@UseGuards(JwtAuthGuard, RolesGuard)
export class WebhooksController {
  constructor(private readonly webhooksService: WebhooksService) {}

  @Get('subscriptions')
  @Roles(Role.SUPER_ADMIN, Role.TENANT_ADMIN)
  @ApiOperation({ summary: 'List webhook subscriptions' })
  @ApiQuery({ name: 'tenantId', required: false })
  listSubscriptions(@Query('tenantId') tenantId?: string) {
    return this.webhooksService.listSubscriptions(tenantId);
  }

  @Post('subscriptions')
  @Roles(Role.SUPER_ADMIN, Role.TENANT_ADMIN)
  @ApiOperation({ summary: 'Create a webhook subscription' })
  createSubscription(@Body() dto: CreateWebhookSubscriptionDto, @Request() req: any) {
    return this.webhooksService.createSubscription(dto, req.user?.id);
  }

  @Get('subscriptions/:id')
  @Roles(Role.SUPER_ADMIN, Role.TENANT_ADMIN)
  @ApiOperation({ summary: 'Get a webhook subscription' })
  @ApiParam({ name: 'id' })
  getSubscription(@Param('id') id: string) {
    return this.webhooksService.getSubscription(id);
  }

  @Patch('subscriptions/:id')
  @Roles(Role.SUPER_ADMIN, Role.TENANT_ADMIN)
  @ApiOperation({ summary: 'Update a webhook subscription' })
  updateSubscription(@Param('id') id: string, @Body() dto: UpdateWebhookSubscriptionDto) {
    return this.webhooksService.updateSubscription(id, dto);
  }

  @Delete('subscriptions/:id')
  @Roles(Role.SUPER_ADMIN, Role.TENANT_ADMIN)
  @ApiOperation({ summary: 'Delete a webhook subscription' })
  deleteSubscription(@Param('id') id: string) {
    return this.webhooksService.deleteSubscription(id);
  }

  @Post('subscriptions/:id/test')
  @Roles(Role.SUPER_ADMIN, Role.TENANT_ADMIN)
  @ApiOperation({ summary: 'Send a test webhook delivery' })
  sendTestWebhook(@Param('id') id: string) {
    return this.webhooksService.sendTestWebhook(id);
  }

  @Get('deliveries')
  @Roles(Role.SUPER_ADMIN, Role.TENANT_ADMIN)
  @ApiOperation({ summary: 'List webhook deliveries' })
  listDeliveries(@Query() filters: DeliveryQueryDto) {
    return this.webhooksService.listDeliveries(filters);
  }

  @Post('deliveries/:id/retry')
  @Roles(Role.SUPER_ADMIN, Role.TENANT_ADMIN)
  @ApiOperation({ summary: 'Retry a failed webhook delivery' })
  retryDelivery(@Param('id') id: string) {
    return this.webhooksService.retryDelivery(id);
  }

  @Get('dashboard')
  @Roles(Role.SUPER_ADMIN, Role.TENANT_ADMIN)
  @ApiOperation({ summary: 'Get webhook delivery dashboard metrics' })
  @ApiOkResponse({ description: 'Webhook delivery summary and recent failures' })
  getDashboard(@Query('tenantId') tenantId?: string) {
    return this.webhooksService.getDashboard(tenantId);
  }

  @Post('events')
  @Roles(Role.SUPER_ADMIN, Role.TENANT_ADMIN)
  @ApiOperation({ summary: 'Publish a platform event to matching webhook subscribers' })
  publishEvent(@Body() dto: PublishWebhookEventDto) {
    return this.webhooksService.publishEvent(dto);
  }
}
