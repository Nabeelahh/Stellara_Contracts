import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { NotificationController } from './notification.controller';
import { NotificationService } from './services/notification.service';
import { EmailService } from './services/email.service';
import { WebPushService } from './services/web-push.service';
import { SmsService } from './services/sms.service';
import { TemplateService } from './services/template.service';
import { NotificationGateway } from './notification.gateway';
import { DeadlineAlertTask } from './tasks/deadline-alert.task';
import { EmailRetryTask } from './tasks/email-retry.task';
import { NotificationSchedulerTask } from './tasks/notification-scheduler.task';
import { DatabaseModule } from '../database.module';

@Module({
  imports: [DatabaseModule, ScheduleModule],
  controllers: [NotificationController],
  providers: [
    NotificationService,
    EmailService,
    WebPushService,
    SmsService,
    TemplateService,
    NotificationGateway,
    DeadlineAlertTask,
    EmailRetryTask,
    NotificationSchedulerTask,
  ],
  exports: [NotificationService],
})
export class NotificationModule {}
