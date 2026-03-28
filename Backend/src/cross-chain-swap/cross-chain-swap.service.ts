import { Injectable, Logger, ConflictException, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { HtlcService } from './htlc.service';
import { InitiateSwapDto, ClaimSwapDto, RefundSwapDto, SwapChain } from './dto/swap.dto';
import { SwapStatus } from '@prisma/client';

@Injectable()
export class CrossChainSwapService {
  private readonly logger = new Logger(CrossChainSwapService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly htlc: HtlcService,
  ) {}

  /**
   * Initiates a new swap by generating a preimage and hash lock.
   */
  async initiateSwap(userId: string, dto: InitiateSwapDto) {
    const preimage = this.htlc.generatePreimage();
    const hashLock = this.htlc.computeHash(preimage);
    const timeoutAt = new Date(Date.now() + (dto.timeoutSeconds || 86400) * 1000);

    const swap = await this.prisma.crossChainSwap.create({
      data: {
        userId,
        amount: dto.amount,
        sourceChain: dto.sourceChain,
        destinationChain: dto.destinationChain,
        destinationAddress: dto.destinationAddress,
        hashLock,
        status: SwapStatus.PENDING,
        timeoutAt,
      },
    });

    this.logger.log(`Swap initiated: ${swap.id} for user ${userId}`);

    // In a real system, we'd trigger the on-chain lock here or wait for transaction verification.
    return {
      swapId: swap.id,
      hashLock,
      preimage, // The user must keep this secret until claiming on the destination chain.
      timeoutAt,
    };
  }

  /**
   * Claims a swap by providing the secret preimage.
   */
  async claimSwap(userId: string, dto: ClaimSwapDto) {
    const swap = await this.prisma.crossChainSwap.findUnique({
      where: { id: dto.swapId },
    });

    if (!swap) {
      throw new NotFoundException(`Swap ${dto.swapId} not found`);
    }

    if (swap.status !== SwapStatus.PENDING && swap.status !== SwapStatus.COMMITTED) {
      throw new ConflictException(`Swap ${dto.swapId} is already ${swap.status}`);
    }

    if (new Date() > swap.timeoutAt) {
      await this.prisma.crossChainSwap.update({
        where: { id: swap.id },
        data: { status: SwapStatus.EXPIRED },
      });
      throw new BadRequestException(`Swap ${dto.swapId} has expired`);
    }

    // Verify preload
    if (!this.htlc.verify(dto.preimage, swap.hashLock)) {
      throw new BadRequestException('Invalid preimage');
    }

    const updatedSwap = await this.prisma.crossChainSwap.update({
      where: { id: swap.id },
      data: {
        status: SwapStatus.CLAIMED,
        secret: dto.preimage,
      },
    });

    this.logger.log(`Swap claimed: ${swap.id}`);
    return updatedSwap;
  }

  /**
   * Refunds a swap after timeout.
   */
  async refundSwap(userId: string, dto: RefundSwapDto) {
    const swap = await this.prisma.crossChainSwap.findUnique({
      where: { id: dto.swapId },
    });

    if (!swap) {
      throw new NotFoundException(`Swap ${dto.swapId} not found`);
    }

    if (swap.userId !== userId) {
      throw new ConflictException('Unauthorized');
    }

    if (new Date() <= swap.timeoutAt) {
      throw new BadRequestException('Swap has not timed out yet');
    }

    if (swap.status === SwapStatus.CLAIMED) {
      throw new ConflictException('Swap already claimed');
    }

    const updatedSwap = await this.prisma.crossChainSwap.update({
      where: { id: swap.id },
      data: { status: SwapStatus.REFUNDED },
    });

    this.logger.log(`Swap refunded: ${swap.id}`);
    return updatedSwap;
  }

  /**
   * Tracks swap status.
   */
  async getSwapStatus(swapId: string) {
    const swap = await this.prisma.crossChainSwap.findUnique({
      where: { id: swapId },
    });

    if (!swap) {
      throw new NotFoundException(`Swap ${swapId} not found`);
    }

    return swap;
  }
}
