import { Test, TestingModule } from '@nestjs/testing';
import { NotificationController } from './notification.controller';
import { PrismaService } from '../prisma.service';

describe('NotificationController', () => {
  let controller: NotificationController;

  const mockPrismaService = {
    notificationSetting: {
      upsert: jest.fn(),
    },
    user: {
      update: jest.fn(),
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [NotificationController],
      providers: [{ provide: PrismaService, useValue: mockPrismaService }],
    }).compile();

    controller = module.get<NotificationController>(NotificationController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
