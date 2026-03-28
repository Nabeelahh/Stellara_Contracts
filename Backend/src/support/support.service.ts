import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { 
  CreateSupportNoteDto, 
  UpdateSupportNoteDto,
  CreateManualAdjustmentDto,
  ApproveAdjustmentDto,
  RejectAdjustmentDto,
  CreateSupportActionDto,
  UserLookupDto,
  ActivityTimelineDto,
  ImpersonateUserDto
} from './dto';
import { 
  SupportNote, 
  ManualAdjustment, 
  SupportAction, 
  AdjustmentStatus,
  ActionType,
  User,
  Contribution,
  Project,
  ReputationHistory,
  Notification,
  Claim,
  StakeLedger
} from '@prisma/client';

@Injectable()
export class SupportService {
  constructor(private prisma: PrismaService) {}

  // ─── User Lookup & Unified View ───────────────────────────────────────────────

  async findUser(query: UserLookupDto): Promise<User | null> {
    if (query.userId) {
      return this.prisma.user.findUnique({
        where: { id: query.userId },
        include: {
          tenant: true,
          notificationSettings: true,
          createdProjects: true,
          contributions: {
            include: { project: true }
          },
          reputationHistory: true,
          notifications: true,
          tenantMembers: true,
        }
      });
    }

    if (query.walletAddress) {
      return this.prisma.user.findUnique({
        where: { walletAddress: query.walletAddress },
        include: {
          tenant: true,
          notificationSettings: true,
          createdProjects: true,
          contributions: {
            include: { project: true }
          },
          reputationHistory: true,
          notifications: true,
          tenantMembers: true,
        }
      });
    }

    if (query.email) {
      return this.prisma.user.findFirst({
        where: { email: query.email },
        include: {
          tenant: true,
          notificationSettings: true,
          createdProjects: true,
          contributions: {
            include: { project: true }
          },
          reputationHistory: true,
          notifications: true,
          tenantMembers: true,
        }
      });
    }

    if (query.phoneNumber) {
      return this.prisma.user.findFirst({
        where: { phoneNumber: query.phoneNumber },
        include: {
          tenant: true,
          notificationSettings: true,
          createdProjects: true,
          contributions: {
            include: { project: true }
          },
          reputationHistory: true,
          notifications: true,
          tenantMembers: true,
        }
      });
    }

    throw new NotFoundException('User not found with provided criteria');
  }

  // ─── Activity Timeline ───────────────────────────────────────────────────────

  async getActivityTimeline(userId: string, query: ActivityTimelineDto) {
    const startDate = query.startDate ? new Date(query.startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const endDate = query.endDate ? new Date(query.endDate) : new Date();
    const limit = query.limit || 100;

    const [
      contributions,
      reputationHistory,
      notifications,
      supportActions,
      manualAdjustments,
      supportNotes,
      claims,
      stakeLedgers
    ] = await Promise.all([
      this.prisma.contribution.findMany({
        where: {
          investorId: userId,
          createdAt: { gte: startDate, lte: endDate }
        },
        include: { project: true },
        orderBy: { createdAt: 'desc' },
        take: limit
      }),
      this.prisma.reputationHistory.findMany({
        where: {
          userId,
          timestamp: { gte: startDate, lte: endDate }
        },
        orderBy: { timestamp: 'desc' },
        take: limit
      }),
      this.prisma.notification.findMany({
        where: {
          userId,
          createdAt: { gte: startDate, lte: endDate }
        },
        orderBy: { createdAt: 'desc' },
        take: limit
      }),
      this.prisma.supportAction.findMany({
        where: {
          userId,
          createdAt: { gte: startDate, lte: endDate }
        },
        orderBy: { createdAt: 'desc' },
        take: limit
      }),
      this.prisma.manualAdjustment.findMany({
        where: {
          userId,
          createdAt: { gte: startDate, lte: endDate }
        },
        orderBy: { createdAt: 'desc' },
        take: limit
      }),
      this.prisma.supportNote.findMany({
        where: {
          userId,
          createdAt: { gte: startDate, lte: endDate }
        },
        orderBy: { createdAt: 'desc' },
        take: limit
      }),
      this.prisma.claim.findMany({
        where: {
          userAddress: userId,
          createdAt: { gte: startDate, lte: endDate }
        },
        orderBy: { createdAt: 'desc' },
        take: limit
      }),
      this.prisma.stakeLedger.findMany({
        where: {
          userAddress: userId,
          createdAt: { gte: startDate, lte: endDate }
        },
        orderBy: { createdAt: 'desc' },
        take: limit
      })
    ]);

    const timeline = [
      ...contributions.map(item => ({ type: 'contribution', data: item, timestamp: item.createdAt })),
      ...reputationHistory.map(item => ({ type: 'reputation', data: item, timestamp: item.timestamp })),
      ...notifications.map(item => ({ type: 'notification', data: item, timestamp: item.createdAt })),
      ...supportActions.map(item => ({ type: 'support_action', data: item, timestamp: item.createdAt })),
      ...manualAdjustments.map(item => ({ type: 'manual_adjustment', data: item, timestamp: item.createdAt })),
      ...supportNotes.map(item => ({ type: 'support_note', data: item, timestamp: item.createdAt })),
      ...claims.map(item => ({ type: 'claim', data: item, timestamp: item.createdAt })),
      ...stakeLedgers.map(item => ({ type: 'stake', data: item, timestamp: item.createdAt }))
    ];

    return timeline
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  // ─── Support Notes ───────────────────────────────────────────────────────────

  async createSupportNote(dto: CreateSupportNoteDto, authorId: string): Promise<SupportNote> {
    return this.prisma.supportNote.create({
      data: {
        userId: dto.userId,
        authorId,
        content: dto.content,
        type: dto.type,
        isInternal: dto.isInternal || false,
      }
    });
  }

  async updateSupportNote(id: string, dto: UpdateSupportNoteDto, authorId: string): Promise<SupportNote> {
    return this.prisma.supportNote.update({
      where: { id },
      data: dto
    });
  }

  async deleteSupportNote(id: string, authorId: string): Promise<void> {
    await this.prisma.supportNote.delete({
      where: { id }
    });
  }

  async getSupportNotes(userId: string, includeInternal = false): Promise<SupportNote[]> {
    return this.prisma.supportNote.findMany({
      where: {
        userId,
        ...(includeInternal ? {} : { isInternal: false })
      },
      orderBy: { createdAt: 'desc' }
    });
  }

  // ─── Manual Adjustments ───────────────────────────────────────────────────────

  async createManualAdjustment(dto: CreateManualAdjustmentDto, agentId: string): Promise<ManualAdjustment> {
    return this.prisma.manualAdjustment.create({
      data: {
        userId: dto.userId,
        agentId,
        adjustmentType: dto.adjustmentType,
        amount: dto.amount,
        currency: dto.currency || 'USD',
        reason: dto.reason,
        referenceId: dto.referenceId,
        referenceType: dto.referenceType,
        status: AdjustmentStatus.PENDING,
      }
    });
  }

  async approveAdjustment(dto: ApproveAdjustmentDto, approvedById: string): Promise<ManualAdjustment> {
    const adjustment = await this.prisma.manualAdjustment.findUnique({
      where: { id: dto.adjustmentId }
    });

    if (!adjustment) {
      throw new NotFoundException('Adjustment not found');
    }

    if (adjustment.status !== AdjustmentStatus.PENDING) {
      throw new ForbiddenException('Adjustment is not in pending status');
    }

    const updatedAdjustment = await this.prisma.manualAdjustment.update({
      where: { id: dto.adjustmentId },
      data: {
        status: AdjustmentStatus.APPROVED,
        approvedById,
        approvedAt: new Date()
      }
    });

    // TODO: Process the actual adjustment (e.g., update user balance, create transaction)
    await this.processAdjustment(updatedAdjustment);

    return updatedAdjustment;
  }

  async rejectAdjustment(dto: RejectAdjustmentDto, rejectedById: string): Promise<ManualAdjustment> {
    return this.prisma.manualAdjustment.update({
      where: { id: dto.adjustmentId },
      data: {
        status: AdjustmentStatus.REJECTED,
        metadata: {
          rejectionReason: dto.reason,
          rejectedById,
          rejectedAt: new Date()
        }
      }
    });
  }

  async getPendingAdjustments(): Promise<ManualAdjustment[]> {
    return this.prisma.manualAdjustment.findMany({
      where: { status: AdjustmentStatus.PENDING },
      include: {
        user: true,
        agent: true
      },
      orderBy: { createdAt: 'asc' }
    });
  }

  private async processAdjustment(adjustment: ManualAdjustment): Promise<void> {
    // Implementation depends on your business logic
    // This could involve updating user balances, creating transactions, etc.
    console.log(`Processing adjustment: ${adjustment.id} for user: ${adjustment.userId}`);
  }

  // ─── Support Actions & Impersonation ───────────────────────────────────────────

  async createSupportAction(dto: CreateSupportActionDto, agentId: string, ipAddress?: string, userAgent?: string): Promise<SupportAction> {
    return this.prisma.supportAction.create({
      data: {
        userId: dto.userId,
        agentId,
        actionType: dto.actionType,
        description: dto.description,
        metadata: dto.metadata,
        ipAddress,
        userAgent
      }
    });
  }

  async startImpersonation(dto: ImpersonateUserDto, agentId: string, ipAddress?: string, userAgent?: string): Promise<SupportAction> {
    const user = await this.prisma.user.findUnique({
      where: { id: dto.userId }
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.createSupportAction({
      userId: dto.userId,
      actionType: ActionType.IMPERSONATION_START,
      description: `Started impersonation: ${dto.reason || 'No reason provided'}`,
      metadata: { reason: dto.reason }
    }, agentId, ipAddress, userAgent);
  }

  async endImpersonation(userId: string, agentId: string, ipAddress?: string, userAgent?: string): Promise<SupportAction> {
    return this.createSupportAction({
      userId,
      actionType: ActionType.IMPERSONATION_END,
      description: 'Ended impersonation session',
      metadata: {}
    }, agentId, ipAddress, userAgent);
  }

  async getUserSupportActions(userId: string): Promise<SupportAction[]> {
    return this.prisma.supportAction.findMany({
      where: { userId },
      include: {
        agent: true
      },
      orderBy: { createdAt: 'desc' }
    });
  }
}
