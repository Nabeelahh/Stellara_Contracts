import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import {
  CreateVestingScheduleDto,
  TriggerAccelerationDto,
  TerminateVestingDto,
} from './vesting.dto';
import { Decimal } from '@prisma/client/runtime/library';

// Stub token price per token (replace with oracle feed in production)
const STUB_TOKEN_PRICE_USD = 1.0;

@Injectable()
export class VestingService {
  private readonly logger = new Logger(VestingService.name);

  constructor(private readonly prisma: PrismaService) {}

  async createSchedule(dto: CreateVestingScheduleDto) {
    const schedule = await this.prisma.vestingSchedule.create({
      data: {
        recipientAddress: dto.recipientAddress,
        totalAmount: new Decimal(dto.totalAmount),
        scheduleType: dto.scheduleType,
        cliffMonths: dto.cliffMonths,
        startDate: new Date(dto.startDate),
        endDate: new Date(dto.endDate),
        status: 'active',
        milestones:
          dto.milestones && dto.milestones.length > 0
            ? {
                create: dto.milestones.map((m) => ({
                  milestoneDate: new Date(m.date),
                  percentage: new Decimal(m.percentage / 100),
                  description: m.description,
                })),
              }
            : undefined,
      },
      include: { milestones: true },
    });

    this.logger.log(`Created vesting schedule ${schedule.id} for ${dto.recipientAddress}`);
    return schedule;
  }

  async getSchedule(id: string) {
    const schedule = await this.prisma.vestingSchedule.findUnique({
      where: { id },
      include: { milestones: true, events: { orderBy: { createdAt: 'desc' } } },
    });

    if (!schedule) {
      throw new NotFoundException(`Vesting schedule ${id} not found`);
    }

    return schedule;
  }

  async listSchedules(filter: { recipientAddress?: string; status?: string }) {
    return this.prisma.vestingSchedule.findMany({
      where: {
        ...(filter.recipientAddress ? { recipientAddress: filter.recipientAddress } : {}),
        ...(filter.status ? { status: filter.status } : {}),
      },
      include: { milestones: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  async calculateVested(vestingId: string, asOfDate: Date): Promise<{ vestedAmount: number; percentage: number }> {
    const schedule = await this.getSchedule(vestingId);
    const total = Number(schedule.totalAmount);
    const start = new Date(schedule.startDate);
    const end = new Date(schedule.endDate);

    if (asOfDate < start) {
      return { vestedAmount: 0, percentage: 0 };
    }

    // Check cliff
    const cliffEnd = new Date(start);
    cliffEnd.setMonth(cliffEnd.getMonth() + schedule.cliffMonths);

    if (asOfDate < cliffEnd) {
      return { vestedAmount: 0, percentage: 0 };
    }

    let vestedAmount = 0;

    if (schedule.scheduleType === 'linear') {
      vestedAmount = this.calculateLinear(total, start, end, asOfDate);
    } else if (schedule.scheduleType === 'milestone') {
      vestedAmount = await this.calculateMilestone(schedule, total, asOfDate);
    } else if (schedule.scheduleType === 'hybrid') {
      // 50% linear, 50% milestone
      const linearPart = this.calculateLinear(total * 0.5, start, end, asOfDate);
      const milestonePart = await this.calculateMilestone(schedule, total * 0.5, asOfDate);
      vestedAmount = linearPart + milestonePart;
    }

    vestedAmount = Math.min(vestedAmount, total);
    const percentage = total > 0 ? (vestedAmount / total) * 100 : 0;

    return {
      vestedAmount: Math.round(vestedAmount * 10000) / 10000,
      percentage: Math.round(percentage * 100) / 100,
    };
  }

  private calculateLinear(total: number, start: Date, end: Date, asOf: Date): number {
    const clampedAsOf = asOf > end ? end : asOf;
    const totalDuration = end.getTime() - start.getTime();
    const elapsed = clampedAsOf.getTime() - start.getTime();
    if (totalDuration <= 0) return total;
    return total * (elapsed / totalDuration);
  }

  private async calculateMilestone(schedule: any, total: number, asOf: Date): Promise<number> {
    const milestones = await this.prisma.vestingMilestone.findMany({
      where: { scheduleId: schedule.id, milestoneDate: { lte: asOf } },
    });

    let vestedPercentage = 0;
    for (const m of milestones) {
      vestedPercentage += Number(m.percentage);
    }

    return total * Math.min(vestedPercentage, 1);
  }

  async processVestingEvent(vestingId: string) {
    const schedule = await this.getSchedule(vestingId);
    if (schedule.status !== 'active') {
      throw new BadRequestException(`Schedule ${vestingId} is not active`);
    }

    const now = new Date();
    const { vestedAmount } = await this.calculateVested(vestingId, now);
    const alreadyVested = Number(schedule.vestedAmount);
    const newVestAmount = vestedAmount - alreadyVested;

    if (newVestAmount <= 0) {
      this.logger.debug(`No new tokens to vest for schedule ${vestingId}`);
      return { vestingId, newVestAmount: 0, totalVested: alreadyVested };
    }

    const vestEvent = await this.prisma.vestingEvent.create({
      data: {
        scheduleId: vestingId,
        eventType: 'vest',
        amount: new Decimal(newVestAmount),
        tokenPrice: new Decimal(STUB_TOKEN_PRICE_USD),
      },
    });

    // Calculate taxable income
    const taxableIncome = await this.calculateTaxableIncome(vestingId, vestEvent);

    // Update event with taxable income
    await this.prisma.vestingEvent.update({
      where: { id: vestEvent.id },
      data: { taxableIncome: new Decimal(taxableIncome) },
    });

    // Update schedule vested amount
    await this.prisma.vestingSchedule.update({
      where: { id: vestingId },
      data: { vestedAmount: new Decimal(vestedAmount) },
    });

    this.logger.log(`Processed vest event: ${newVestAmount} tokens for schedule ${vestingId}`);
    return { vestingId, newVestAmount, totalVested: vestedAmount, taxableIncome };
  }

  async triggerAcceleration(dto: TriggerAccelerationDto) {
    const schedule = await this.getSchedule(dto.vestingId);

    if (schedule.status !== 'active') {
      throw new BadRequestException(`Schedule ${dto.vestingId} is not active`);
    }

    const remainingAmount = Number(schedule.totalAmount) - Number(schedule.vestedAmount);

    await this.prisma.vestingEvent.create({
      data: {
        scheduleId: dto.vestingId,
        eventType: 'acceleration',
        amount: new Decimal(remainingAmount),
        tokenPrice: new Decimal(STUB_TOKEN_PRICE_USD),
        taxableIncome: new Decimal(remainingAmount * STUB_TOKEN_PRICE_USD),
      },
    });

    const updated = await this.prisma.vestingSchedule.update({
      where: { id: dto.vestingId },
      data: {
        status: 'accelerated',
        accelerationReason: dto.reason,
        acceleratedAt: new Date(),
        vestedAmount: schedule.totalAmount,
      },
    });

    this.logger.log(
      `Accelerated vesting schedule ${dto.vestingId}: ${remainingAmount} tokens vested immediately. Reason: ${dto.reason}`,
    );
    return updated;
  }

  async terminateVesting(dto: TerminateVestingDto) {
    const schedule = await this.getSchedule(dto.vestingId);

    if (schedule.status !== 'active') {
      throw new BadRequestException(`Schedule ${dto.vestingId} is not active`);
    }

    const terminationDate = new Date(dto.terminationDate);
    const { vestedAmount } = await this.calculateVested(dto.vestingId, terminationDate);
    const unvestedAmount = Number(schedule.totalAmount) - vestedAmount;

    await this.prisma.vestingEvent.create({
      data: {
        scheduleId: dto.vestingId,
        eventType: 'termination',
        amount: new Decimal(vestedAmount),
        tokenPrice: new Decimal(STUB_TOKEN_PRICE_USD),
        taxableIncome: new Decimal(vestedAmount * STUB_TOKEN_PRICE_USD),
      },
    });

    const updated = await this.prisma.vestingSchedule.update({
      where: { id: dto.vestingId },
      data: {
        status: 'terminated',
        terminationDate,
        terminationReason: dto.reason,
        vestedAmount: new Decimal(vestedAmount),
      },
    });

    this.logger.log(
      `Terminated vesting schedule ${dto.vestingId}. Final payout: ${vestedAmount} tokens. Forfeited: ${unvestedAmount} tokens.`,
    );
    return { ...updated, finalPayout: vestedAmount, forfeited: unvestedAmount };
  }

  async calculateTaxableIncome(vestingId: string, vestEvent: any): Promise<number> {
    const amount = Number(vestEvent.amount);
    const tokenPrice = vestEvent.tokenPrice ? Number(vestEvent.tokenPrice) : STUB_TOKEN_PRICE_USD;
    const taxableIncome = amount * tokenPrice;

    this.logger.debug(
      `Taxable income for vest event ${vestEvent.id}: ${amount} tokens × $${tokenPrice} = $${taxableIncome}`,
    );

    return taxableIncome;
  }

  async generateTaxReport(recipientAddress: string, year: number) {
    const yearStart = new Date(`${year}-01-01T00:00:00.000Z`);
    const yearEnd = new Date(`${year + 1}-01-01T00:00:00.000Z`);

    const schedules = await this.prisma.vestingSchedule.findMany({
      where: { recipientAddress },
      include: {
        events: {
          where: {
            createdAt: { gte: yearStart, lt: yearEnd },
          },
        },
      },
    });

    let totalVestedTokens = 0;
    let totalTaxableIncome = 0;
    const eventSummaries: any[] = [];

    for (const schedule of schedules) {
      for (const event of schedule.events) {
        const amount = Number(event.amount);
        const taxable = Number(event.taxableIncome ?? 0);
        totalVestedTokens += amount;
        totalTaxableIncome += taxable;
        eventSummaries.push({
          scheduleId: schedule.id,
          eventId: event.id,
          eventType: event.eventType,
          date: event.createdAt,
          tokensVested: amount,
          tokenPrice: Number(event.tokenPrice ?? STUB_TOKEN_PRICE_USD),
          taxableIncome: taxable,
        });
      }
    }

    return {
      recipientAddress,
      year,
      totalVestedTokens,
      totalTaxableIncomeUsd: Math.round(totalTaxableIncome * 100) / 100,
      events: eventSummaries,
      generatedAt: new Date(),
    };
  }
}
