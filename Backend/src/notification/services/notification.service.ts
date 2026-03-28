import { Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { PrismaService } from '../../prisma.service';
import { EmailService } from './email.service';
import { WebPushService } from './web-push.service';
import { SmsService } from './sms.service';
import { TemplateService } from './template.service';
import { NotificationGateway } from '../notification.gateway';
import {
  NotificationChannel,
  NotificationType,
  NotificationStatus,
} from '@prisma/client';

const DEFAULT_CHANNEL_PREFERENCES: Record<NotificationType, NotificationChannel[]> = {
  CONTRIBUTION: ['EMAIL', 'PUSH'],
  MILESTONE: ['EMAIL', 'PUSH'],
  DEADLINE: ['SMS', 'PUSH'],
  SYSTEM: ['EMAIL', 'PUSH'],
};

const DEFAULT_DAILY_LIMIT = 5;
const DEFAULT_SEND_HOUR = 10;

@Injectable()
export class NotificationService {
  private readonly logger = new Logger(NotificationService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly emailService: EmailService,
    private readonly webPushService: WebPushService,
    private readonly smsService: SmsService,
    private readonly templateService: TemplateService,
    private readonly notificationGateway: NotificationGateway,
  ) {}

  async notify(
    userId: string,
    type: NotificationType,
    title: string,
    message: string,
    data?: any,
  ): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { notificationSettings: true },
    });

    if (!user) {
      this.logger.warn(`User ${userId} not found for notification`);
      return;
    }

    const settings = this.normalizeSettings(user.notificationSettings);
    if (!this.shouldNotifyType(settings, type)) {
      return;
    }

    const urgent = this.isUrgent(type, data);
    const variant = this.chooseVariant(userId, type);
    const enrichedData = { ...data, variant };
    const renderedMessage = this.templateService.render(type, { ...enrichedData, message, title });
    const sendAt = urgent ? new Date() : await this.predictOptimalSendTime(userId, type);
    const now = new Date();

    const recentCount = await this.prisma.notification.count({
      where: {
        userId,
        createdAt: { gte: new Date(now.getTime() - 24 * 60 * 60 * 1000) },
        status: { not: NotificationStatus.SKIPPED },
      },
    });

    if (!urgent && recentCount >= settings.dailyLimit) {
      await this.prisma.notification.create({
        data: {
          userId,
          type,
          title,
          message: renderedMessage,
          data: enrichedData,
          status: NotificationStatus.SKIPPED,
          variant,
          critical: false,
        },
      });
      this.logger.warn(`Daily notification cap reached for ${userId}, skipping non-critical notification`);
      return;
    }

    const notification = await this.prisma.notification.create({
      data: {
        userId,
        type,
        title,
        message: renderedMessage,
        data: enrichedData,
        status: sendAt > now ? NotificationStatus.SCHEDULED : NotificationStatus.SENT,
        scheduledAt: sendAt > now ? sendAt : null,
        variant,
        critical: urgent,
      },
    });

    if (sendAt > now) {
      this.logger.log(`Scheduled notification ${notification.id} for ${sendAt.toISOString()}`);
      return;
    }

    await this.sendNotification(notification, user, settings, renderedMessage, enrichedData, urgent);
  }

  async processScheduledNotifications(): Promise<void> {
    const now = new Date();
    const scheduledNotifications = await this.prisma.notification.findMany({
      where: {
        status: NotificationStatus.SCHEDULED,
        scheduledAt: { lte: now },
      },
    });

    for (const notification of scheduledNotifications) {
      try {
        await this.deliverScheduledNotification(notification.id);
      } catch (error) {
        this.logger.error(`Failed scheduled notification ${notification.id}: ${error.message}`);
      }
    }
  }

  async deliverScheduledNotification(notificationId: string): Promise<void> {
    const notification = await this.prisma.notification.findUnique({
      where: { id: notificationId },
      include: { user: { include: { notificationSettings: true } } },
    });

    if (!notification) {
      this.logger.warn(`Scheduled notification ${notificationId} not found`);
      return;
    }

    if (notification.status !== NotificationStatus.SCHEDULED) {
      return;
    }

    const user = notification.user;
    const settings = this.normalizeSettings(user.notificationSettings);
    const urgent = notification.critical;

    const renderedMessage = notification.message;
    const enrichedData = notification.data;

    await this.sendNotification(notification, user, settings, renderedMessage, enrichedData, urgent);
    await this.prisma.notification.update({
      where: { id: notification.id },
      data: { status: NotificationStatus.SENT },
    });
  }

  async trackOpen(deliveryId: string): Promise<{ success: boolean }> {
    const delivery = await this.prisma.notificationDelivery.update({
      where: { id: deliveryId },
      data: { openedAt: new Date() },
      select: { id: true, notificationId: true },
    });

    if (delivery.notificationId) {
      await this.prisma.notification.update({
        where: { id: delivery.notificationId },
        data: { openCount: { increment: 1 } },
      });
    }

    return { success: true };
  }

  async trackClick(deliveryId: string): Promise<{ success: boolean }> {
    const delivery = await this.prisma.notificationDelivery.update({
      where: { id: deliveryId },
      data: { clickedAt: new Date() },
      select: { id: true, notificationId: true },
    });

    if (delivery.notificationId) {
      await this.prisma.notification.update({
        where: { id: delivery.notificationId },
        data: { clickCount: { increment: 1 } },
      });
    }

    return { success: true };
  }

  async unsubscribe(
    identifier: string,
    channel?: NotificationChannel,
    type?: NotificationType,
  ): Promise<{ success: boolean }> {
    const user = await this.resolveUserByIdentifier(identifier);
    if (!user) {
      this.logger.warn(`Unable to resolve user for unsubscribe identifier ${identifier}`);
      return { success: false };
    }

    const current = await this.prisma.notificationSetting.findUnique({ where: { userId: user.id } });
    const update: any = {};

    if (!channel && !type) {
      update.emailEnabled = false;
      update.smsEnabled = false;
      update.pushEnabled = false;
      update.websocketEnabled = false;
    } else if (channel && !type) {
      if (channel === 'EMAIL') update.emailEnabled = false;
      if (channel === 'SMS') update.smsEnabled = false;
      if (channel === 'PUSH') update.pushEnabled = false;
      if (channel === 'WEBSOCKET') update.websocketEnabled = false;
    }

    if (type) {
      const currentPreferences = (current?.channelPreferences as Record<string, NotificationChannel[]>) || {};
      if (channel) {
        const existing = currentPreferences[type] || DEFAULT_CHANNEL_PREFERENCES[type] || ['EMAIL'];
        currentPreferences[type] = existing.filter((channelValue) => channelValue !== channel);
      } else {
        currentPreferences[type] = [];
      }
      update.channelPreferences = currentPreferences;
    }

    update.unsubscribeToken = current?.unsubscribeToken ?? randomUUID();

    await this.prisma.notificationSetting.upsert({
      where: { userId: user.id },
      update,
      create: {
        userId: user.id,
        emailEnabled: update.emailEnabled ?? true,
        smsEnabled: update.smsEnabled ?? false,
        pushEnabled: update.pushEnabled ?? false,
        websocketEnabled: update.websocketEnabled ?? true,
        notifyContributions: true,
        notifyMilestones: true,
        notifyDeadlines: true,
        channelPreferences: update.channelPreferences,
        dailyLimit: DEFAULT_DAILY_LIMIT,
        unsubscribeToken: update.unsubscribeToken,
      },
    });

    return { success: true };
  }

  private async resolveUserByIdentifier(identifier: string) {
    let user = await this.prisma.user.findUnique({ where: { id: identifier } });
    if (!user && identifier.includes('@')) {
      user = await this.prisma.user.findUnique({ where: { email: identifier } });
    }
    return user;
  }

  async predictOptimalSendTime(userId: string, type: NotificationType): Promise<Date> {
    const history = await this.prisma.notification.findMany({
      where: {
        userId,
        status: NotificationStatus.SENT,
        openCount: { gt: 0 },
      },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });

    if (!history.length) {
      return this.getDefaultSendTime();
    }

    const hourCount = new Array<number>(24).fill(0);
    for (const item of history) {
      const hour = new Date(item.createdAt).getHours();
      hourCount[hour] += 1;
    }

    const bestHour = hourCount.reduce(
      (best, count, hour) => (count > hourCount[best] ? hour : best),
      0,
    );

    const nextSend = new Date();
    nextSend.setHours(bestHour, 0, 0, 0);
    if (nextSend <= new Date()) {
      nextSend.setDate(nextSend.getDate() + 1);
    }

    return nextSend;
  }

  private async sendNotification(
    notification: any,
    user: any,
    settings: any,
    renderedMessage: string,
    data: any,
    urgent: boolean,
  ) {
    const channels = this.resolveDeliveryChannels(user, settings, notification.type, urgent);
    const deliveryBatch = [];

    for (const channel of channels) {
      switch (channel) {
        case 'EMAIL':
          deliveryBatch.push(
            this.dispatch(notification.id, 'EMAIL', user.email, notification.title, renderedMessage),
          );
          break;
        case 'SMS':
          deliveryBatch.push(
            this.dispatch(notification.id, 'SMS', user.phoneNumber, notification.title, renderedMessage),
          );
          break;
        case 'PUSH':
          deliveryBatch.push(
            this.dispatch(notification.id, 'PUSH', user.pushSubscription, notification.title, renderedMessage, data),
          );
          break;
      }
    }

    if (settings.websocketEnabled) {
      const sent = this.notificationGateway.sendToUser(user.id, 'notification', {
        id: notification.id,
        title: notification.title,
        message: renderedMessage,
        type: notification.type,
        data,
      });
      await this.prisma.notificationDelivery.create({
        data: {
          notificationId: notification.id,
          channel: 'WEBSOCKET',
          status: sent ? 'SENT' : 'FAILED',
          errorMessage: sent ? null : 'User not connected',
        },
      });
    }

    await Promise.all(deliveryBatch);
  }

  private normalizeSettings(settings: any) {
    return {
      emailEnabled: settings?.emailEnabled ?? true,
      pushEnabled: settings?.pushEnabled ?? false,
      smsEnabled: settings?.smsEnabled ?? false,
      websocketEnabled: settings?.websocketEnabled ?? true,
      notifyContributions: settings?.notifyContributions ?? true,
      notifyMilestones: settings?.notifyMilestones ?? true,
      notifyDeadlines: settings?.notifyDeadlines ?? true,
      channelPreferences: settings?.channelPreferences ?? null,
      dailyLimit: settings?.dailyLimit ?? DEFAULT_DAILY_LIMIT,
    };
  }

  private shouldNotifyType(settings: any, type: NotificationType): boolean {
    if (type === 'CONTRIBUTION' && !settings.notifyContributions) {
      return false;
    }
    if (type === 'MILESTONE' && !settings.notifyMilestones) {
      return false;
    }
    if (type === 'DEADLINE' && !settings.notifyDeadlines) {
      return false;
    }
    return true;
  }

  private isUrgent(type: NotificationType, data?: any): boolean {
    if (data?.urgent || data?.critical) {
      return true;
    }

    if (type === 'SYSTEM') {
      return true;
    }

    return false;
  }

  private resolveDeliveryChannels(
    user: any,
    settings: any,
    type: NotificationType,
    urgent: boolean,
  ): NotificationChannel[] {
    if (urgent) {
      const urgentChannels: NotificationChannel[] = [];
      if (settings.smsEnabled && user.phoneNumber) urgentChannels.push('SMS');
      if (settings.pushEnabled && user.pushSubscription) urgentChannels.push('PUSH');
      if (settings.emailEnabled && user.email) urgentChannels.push('EMAIL');
      return urgentChannels.length ? urgentChannels : DEFAULT_CHANNEL_PREFERENCES[type];
    }

    const preferences = (settings.channelPreferences as Record<string, NotificationChannel[]>) || {};
    const channels = preferences[type] ?? DEFAULT_CHANNEL_PREFERENCES[type] ?? ['EMAIL'];
    return channels.filter((channel) => this.isChannelAvailable(channel, settings, user));
  }

  private isChannelAvailable(channel: NotificationChannel, settings: any, user: any): boolean {
    switch (channel) {
      case 'EMAIL':
        return settings.emailEnabled && !!user.email;
      case 'SMS':
        return settings.smsEnabled && !!user.phoneNumber;
      case 'PUSH':
        return settings.pushEnabled && !!user.pushSubscription;
      case 'WEBSOCKET':
        return settings.websocketEnabled;
      default:
        return false;
    }
  }

  private chooseVariant(userId: string, type: NotificationType): string {
    const hash = [...userId].reduce((acc, char) => acc + char.charCodeAt(0), 0);
    return hash % 2 === 0 ? 'A' : 'B';
  }

  private getDefaultSendTime(): Date {
    const next = new Date();
    next.setHours(DEFAULT_SEND_HOUR, 0, 0, 0);
    if (next <= new Date()) {
      next.setDate(next.getDate() + 1);
    }
    return next;
  }

  private async dispatch(
    notificationId: string,
    channel: NotificationChannel,
    target: any,
    title: string,
    message: string,
    data?: any,
  ): Promise<void> {
    const delivery = await this.prisma.notificationDelivery.create({
      data: {
        notificationId,
        channel,
        status: 'PENDING',
      },
    });

    try {
      switch (channel) {
        case 'EMAIL':
          await this.emailService.sendEmail(target, title, `<p>${message}</p>`);
          break;
        case 'SMS':
          await this.smsService.sendSms(target, message);
          break;
        case 'PUSH':
          await this.webPushService.sendNotification(target, { title, body: message, data });
          break;
      }

      await this.prisma.notificationDelivery.update({
        where: { id: delivery.id },
        data: { status: 'SENT' },
      });
    } catch (err) {
      this.logger.error(`Failed to dispatch ${channel}: ${err.message}`);
      await this.prisma.notificationDelivery.update({
        where: { id: delivery.id },
        data: {
          status: 'FAILED',
          errorMessage: err.message,
        },
      });
    }
  }
}
