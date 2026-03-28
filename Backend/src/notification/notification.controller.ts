import { Body, Controller, Get, Param, Post, Put, Query } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBearerAuth } from '@nestjs/swagger';
import { Prisma, NotificationChannel, NotificationType } from '@prisma/client';
import { PrismaService } from '../prisma.service';
import { NotificationService } from './services/notification.service';
import {
  NotificationSettingsDto,
  UpdateNotificationSettingsDto,
  PushSubscriptionDto,
  SubscribeResponseDto,
  UnsubscribeDto,
  TrackEventDto,
} from './dto/notification.dto';

@ApiTags('notifications')
@ApiBearerAuth('JWT-auth')
@Controller('notifications')
export class NotificationController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly notificationService: NotificationService,
  ) {}

  @Get('settings/:userId')
  @ApiOperation({
    summary: 'Get notification settings',
    description: 'Retrieves notification preferences for a specific user',
  })
  @ApiParam({
    name: 'userId',
    description: 'User unique identifier',
    example: 'cm3x1234567890',
  })
  @ApiResponse({
    status: 200,
    description: 'Notification settings retrieved',
    type: NotificationSettingsDto,
  })
  async getSettings(@Param('userId') userId: string): Promise<NotificationSettingsDto> {
    return this.prisma.notificationSetting.upsert({
      where: { userId },
      update: {},
      create: { userId },
    });
  }

  @Put('settings/:userId')
  @ApiOperation({
    summary: 'Update notification settings',
    description: 'Updates notification preferences for a specific user',
  })
  @ApiParam({
    name: 'userId',
    description: 'User unique identifier',
    example: 'cm3x1234567890',
  })
  @ApiResponse({
    status: 200,
    description: 'Notification settings updated',
    type: NotificationSettingsDto,
  })
  async updateSettings(
    @Param('userId') userId: string,
    @Body() settings: UpdateNotificationSettingsDto,
  ): Promise<NotificationSettingsDto> {
    return this.prisma.notificationSetting.upsert({
      where: { userId },
      update: settings,
      create: {
        userId,
        ...settings,
      },
    });
  }

  @Post('subscribe/:userId')
  @ApiOperation({
    summary: 'Subscribe to push notifications',
    description: 'Registers a push notification subscription for a user',
  })
  @ApiParam({
    name: 'userId',
    description: 'User unique identifier',
    example: 'cm3x1234567890',
  })
  @ApiResponse({
    status: 201,
    description: 'Push subscription registered',
    type: SubscribeResponseDto,
  })
  async subscribeToPush(
    @Param('userId') userId: string,
    @Body() subscription: PushSubscriptionDto,
  ): Promise<SubscribeResponseDto> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { pushSubscription: subscription.subscription as Prisma.InputJsonValue },
    });
    return { success: true };
  }

  @Post('unsubscribe/:userId')
  @ApiOperation({
    summary: 'Unsubscribe from notifications',
    description: 'Updates unsubscribe preferences for email, SMS, push, and channels',
  })
  @ApiParam({
    name: 'userId',
    description: 'User unique identifier',
    example: 'cm3x1234567890',
  })
  async unsubscribe(
    @Param('userId') userId: string,
    @Body() payload: UnsubscribeDto,
  ): Promise<SubscribeResponseDto> {
    await this.notificationService.unsubscribe(userId, payload.channel, payload.type);
    return { success: true };
  }

  @Get('unsubscribe/:identifier')
  @ApiOperation({
    summary: 'Unsubscribe from notifications via email link',
    description: 'Processes unsubscribe requests using an email address or user identifier',
  })
  async unsubscribeViaLink(
    @Param('identifier') identifier: string,
    @Query('channel') channel?: NotificationChannel,
    @Query('type') type?: NotificationType,
  ): Promise<SubscribeResponseDto> {
    await this.notificationService.unsubscribe(identifier, channel, type);
    return { success: true };
  }

  @Get('predict/send-time/:userId/:type')
  @ApiOperation({
    summary: 'Predict user optimal send time',
    description: 'Returns the best time to send the next notification based on engagement history',
  })
  @ApiParam({
    name: 'userId',
    description: 'User unique identifier',
    example: 'cm3x1234567890',
  })
  @ApiParam({
    name: 'type',
    description: 'Notification type',
    example: 'CONTRIBUTION',
  })
  async predictSendTime(
    @Param('userId') userId: string,
    @Param('type') type: NotificationType,
  ): Promise<{ sendAt: string }> {
    const sendAt = await this.notificationService.predictOptimalSendTime(userId, type);
    return { sendAt: sendAt.toISOString() };
  }

  @Post('track/open/:deliveryId')
  @ApiOperation({
    summary: 'Track notification open',
    description: 'Registers that a notification delivery was opened',
  })
  async trackOpen(
    @Param('deliveryId') deliveryId: string,
    @Body() payload: TrackEventDto,
  ): Promise<{ success: boolean }> {
    return this.notificationService.trackOpen(deliveryId);
  }

  @Post('track/click/:deliveryId')
  @ApiOperation({
    summary: 'Track notification click',
    description: 'Registers that a notification click-through occurred',
  })
  async trackClick(
    @Param('deliveryId') deliveryId: string,
    @Body() payload: TrackEventDto,
  ): Promise<{ success: boolean }> {
    return this.notificationService.trackClick(deliveryId);
  }
}
