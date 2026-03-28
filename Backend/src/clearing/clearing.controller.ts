import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { ClearingService } from './clearing.service';
import { CreateTradeDto } from './dto/create-trade.dto';

@Controller('clearing')
export class ClearingController {
  constructor(private readonly clearingService: ClearingService) {}

  @Post('trade')
  async postTrade(@Body() trade: CreateTradeDto) {
    return this.clearingService.acceptTrade(trade);
  }

  @Post('settle/:instrument')
  async settleInstrument(@Param('instrument') instrument: string, @Body() body: { marketPrice: number }) {
    return this.clearingService.settleMarkToMarket(instrument, body.marketPrice);
  }

  @Post('default-fund/contribute')
  async contribute(@Body() body: { memberId: string; amount: number }) {
    this.clearingService.contributeDefaultFund(body.memberId, body.amount);
    return { status: 'ok' };
  }

  @Post('default/:memberId/auction')
  async startAuction(@Param('memberId') memberId: string) {
    return this.clearingService.startAuctionForDefault(memberId);
  }

  @Get('member/:memberId/margin')
  async getMargin(@Param('memberId') memberId: string) {
    return this.clearingService.getMemberMargin(memberId);
  }

  @Get('default-fund')
  async getDefaultFund() {
    return this.clearingService.getDefaultFund();
  }
}
