import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsInt, IsOptional, IsObject, IsString } from 'class-validator';
import { NotificationChannel, NotificationType } from '@prisma/client';

export class NotificationSettingsDto {
  @ApiProperty({
    description: 'User ID',
    example: 'cm3x1234567890',
  })
  userId: string;

  @ApiPropertyOptional({
    description: 'Email notifications enabled',
    example: true,
    default: true,
  })
  emailEnabled?: boolean;

  @ApiPropertyOptional({
    description: 'Push notifications enabled',
    example: true,
    default: true,
  })
  pushEnabled?: boolean;

  @ApiPropertyOptional({
    description: 'SMS notifications enabled',
    example: false,
    default: false,
  })
  smsEnabled?: boolean;

  @ApiPropertyOptional({
    description: 'WebSocket notifications enabled',
    example: true,
    default: true,
  })
  websocketEnabled?: boolean;

  @ApiPropertyOptional({
    description: 'Notify on contributions',
    example: true,
    default: true,
  })
  notifyContributions?: boolean;

  @ApiPropertyOptional({
    description: 'Notify on milestones',
    example: true,
    default: true,
  })
  notifyMilestones?: boolean;

  @ApiPropertyOptional({
    description: 'Notify on deadlines',
    example: true,
    default: true,
  })
  notifyDeadlines?: boolean;

  @ApiPropertyOptional({
    description: 'Per-notification-type channel preferences',
    example: { CONTRIBUTION: ['EMAIL', 'PUSH'], DEADLINE: ['SMS'] },
  })
  channelPreferences?: Record<string, string[]>;

  @ApiPropertyOptional({
    description: 'Daily notification cap before frequency capping applies',
    example: 5,
    default: 5,
  })
  dailyLimit?: number;
}

export class UpdateNotificationSettingsDto {
  @ApiPropertyOptional({
    description: 'Email notifications enabled',
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  emailEnabled?: boolean;

  @ApiPropertyOptional({
    description: 'Push notifications enabled',
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  pushEnabled?: boolean;

  @ApiPropertyOptional({
    description: 'SMS notifications enabled',
    example: false,
  })
  @IsBoolean()
  @IsOptional()
  smsEnabled?: boolean;

  @ApiPropertyOptional({
    description: 'WebSocket notifications enabled',
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  websocketEnabled?: boolean;

  @ApiPropertyOptional({
    description: 'Notify on contributions',
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  notifyContributions?: boolean;

  @ApiPropertyOptional({
    description: 'Notify on milestones',
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  notifyMilestones?: boolean;

  @ApiPropertyOptional({
    description: 'Notify on deadlines',
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  notifyDeadlines?: boolean;

  @ApiPropertyOptional({
    description: 'Per-notification-type channel preferences',
    example: { CONTRIBUTION: ['EMAIL', 'PUSH'], DEADLINE: ['SMS'] },
  })
  @IsObject()
  @IsOptional()
  channelPreferences?: Record<string, string[]>;

  @ApiPropertyOptional({
    description: 'Daily notification cap before frequency capping applies',
    example: 5,
  })
  @IsInt()
  @IsOptional()
  dailyLimit?: number;
}

export class PushSubscriptionDto {
  @ApiProperty({
    description: 'Push notification subscription object',
    example: {
      endpoint: 'https://fcm.googleapis.com/fcm/send/abc123',
      keys: {
        p256dh: 'user_public_key',
        auth: 'auth_secret',
      },
    },
  })
  subscription: any;
}

export class SubscribeResponseDto {
  @ApiProperty({
    description: 'Subscription success status',
    example: true,
  })
  success: boolean;
}

export class UnsubscribeDto {
  @ApiPropertyOptional({
    description: 'Channel to unsubscribe from',
    enum: ['EMAIL', 'SMS', 'PUSH', 'WEBSOCKET'],
  })
  @IsOptional()
  @IsString()
  channel?: NotificationChannel;

  @ApiPropertyOptional({
    description: 'Notification type to modify channel preference for',
    enum: ['CONTRIBUTION', 'MILESTONE', 'DEADLINE', 'SYSTEM'],
  })
  @IsOptional()
  @IsString()
  type?: NotificationType;
}

export class TrackEventDto {
  @ApiPropertyOptional({
    description: 'Optional tracking source',
    example: 'email',
  })
  @IsOptional()
  @IsString()
  source?: string;
}
