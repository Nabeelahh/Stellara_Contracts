import { Controller, Post, Body, Get, Param, UseGuards, Put } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { CrossChainSwapService } from './cross-chain-swap.service';
import { InitiateSwapDto, ClaimSwapDto, RefundSwapDto } from './dto/swap.dto';

@ApiTags('Cross-Chain Swap')
@Controller('cross-chain-swap')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class CrossChainSwapController {
  constructor(private readonly swapService: CrossChainSwapService) {}

  @Post('initiate')
  @ApiOperation({ summary: 'Initiate a new cross-chain swap' })
  @ApiResponse({ status: 201, description: 'Swap initiated successfully' })
  async initiate(@CurrentUser() user: any, @Body() dto: InitiateSwapDto) {
    return this.swapService.initiateSwap(user.id, dto);
  }

  @Post('claim')
  @ApiOperation({ summary: 'Claim a swap by providing the secret preimage' })
  @ApiResponse({ status: 200, description: 'Swap claimed successfully' })
  async claim(@CurrentUser() user: any, @Body() dto: ClaimSwapDto) {
    return this.swapService.claimSwap(user.id, dto);
  }

  @Post('refund')
  @ApiOperation({ summary: 'Refund a swap after timeout' })
  @ApiResponse({ status: 200, description: 'Swap refunded successfully' })
  async refund(@CurrentUser() user: any, @Body() dto: RefundSwapDto) {
    return this.swapService.refundSwap(user.id, dto);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get current status of a swap' })
  @ApiResponse({ status: 200, description: 'Swap status retrieved' })
  async getStatus(@Param('id') id: string) {
    return this.swapService.getSwapStatus(id);
  }
}
