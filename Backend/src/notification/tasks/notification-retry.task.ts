import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../../prisma.service';
import { EmailService } from '../services/email.service';
import { SmsService } from '../services/sms.service';
import { WebPushService } from '../services/web-push.service';
import { NotificationGateway } from '../notification.gateway';

@Injectable()
export class NotificationRetryTask {
  private readonly logger = new Logger(NotificationRetryTask.name);
  private readonly MAX_ATTEMPTS = 3;

  constructor(
    private readonly prisma: PrismaService,
    private readonly emailService: EmailService,
    private readonly smsService: SmsService,
    private readonly webPushService: WebPushService,
    private readonly notificationGateway: NotificationGateway,
  ) {}

  @Cron(CronExpression.EVERY_5_MINUTES)
  async handleCron() {
    this.logger.debug('Checking notification deliveries for failed messages...');

    const failedDeliveries = await this.prisma.notificationDelivery.findMany({
      where: {
        status: 'FAILED',
        attempts: {
          lt: this.MAX_ATTEMPTS,
        },
      },
      include: {
        notification: {
          include: {
            user: true,
          },
        },
      },
      take: 50,
    });

    for (const delivery of failedDeliveries) {
      try {
        this.logger.log(
          `Retrying ${delivery.channel} for notification ${delivery.notificationId} (attempt ${delivery.attempts + 1}/${this.MAX_ATTEMPTS})`,
        );

        const { notification } = delivery;
        const { user } = notification;

        switch (delivery.channel) {
          case 'EMAIL':
            if (user.email) {
              await this.emailService.sendEmail(
                user.email,
                notification.title,
                `<p>${notification.message}</p>`,
              );
            }
            break;
          case 'SMS':
            if (user.phoneNumber) {
              await this.smsService.sendSms(user.phoneNumber, notification.message);
            }
            break;
          case 'PUSH':
            if (user.pushSubscription) {
              await this.webPushService.sendNotification(user.pushSubscription as any, {
                title: notification.title,
                body: notification.message,
                data: notification.data,
              });
            }
            break;
          case 'WEBSOCKET':
            const sent = this.notificationGateway.sendToUser(user.id, 'notification', {
              id: notification.id,
              title: notification.title,
              message: notification.message,
              type: notification.type,
              data: notification.data,
            });
            if (!sent) throw new Error('User still not connected via WebSocket');
            break;
        }

        await this.prisma.notificationDelivery.update({
          where: { id: delivery.id },
          data: {
            status: 'SENT',
            attempts: delivery.attempts + 1,
            lastAttemptAt: new Date(),
          },
        });

        this.logger.log(
          `Successfully retried ${delivery.channel} for notification ${delivery.notificationId}`,
        );
      } catch (error) {
        this.logger.error(`Retry failed for delivery ${delivery.id}: ${error.message}`);

        await this.prisma.notificationDelivery.update({
          where: { id: delivery.id },
          data: {
            attempts: delivery.attempts + 1,
            lastError: error.message,
            lastAttemptAt: new Date(),
          },
        });
      }
    }
  }
}
