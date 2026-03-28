import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { NotificationService } from '../services/notification.service';

@Injectable()
export class NotificationSchedulerTask {
  private readonly logger = new Logger(NotificationSchedulerTask.name);

  constructor(private readonly notificationService: NotificationService) {}

  @Cron(CronExpression.EVERY_MINUTE)
  async handleCron(): Promise<void> {
    this.logger.debug('Checking for scheduled notifications to dispatch');

    try {
      await this.notificationService.processScheduledNotifications();
    } catch (error) {
      this.logger.error(`Scheduled notification dispatch failed: ${error.message}`);
    }
  }
}
