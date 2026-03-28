import { Test, TestingModule } from '@nestjs/testing';
import { NotificationService } from './notification.service';
import { PrismaService } from '../../prisma.service';
import { EmailService } from './email.service';
import { WebPushService } from './web-push.service';
import { SmsService } from './sms.service';
import { TemplateService } from './template.service';
import { NotificationGateway } from '../notification.gateway';

jest.mock('web-push', () => ({
  setVapidDetails: jest.fn(),
  sendNotification: jest.fn().mockResolvedValue({}),
}));

describe('NotificationService', () => {
  let service: NotificationService;

  const mockPrismaService = {
    user: { findUnique: jest.fn() },
    notification: { create: jest.fn() },
    notificationDelivery: { create: jest.fn(), update: jest.fn() },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        NotificationService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: EmailService, useValue: { sendEmail: jest.fn() } },
        { provide: WebPushService, useValue: { sendNotification: jest.fn() } },
        { provide: SmsService, useValue: { sendSms: jest.fn() } },
        { provide: TemplateService, useValue: { render: jest.fn() } },
        { provide: NotificationGateway, useValue: { sendToUser: jest.fn() } },
      ],
    }).compile();

    service = module.get<NotificationService>(NotificationService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
