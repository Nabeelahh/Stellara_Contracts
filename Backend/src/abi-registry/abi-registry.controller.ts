import { Body, Controller, Get, Param, Post, Query, Request, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { RolesGuard } from '../auth/guards/roles.guard';
import { AbiRegistryService } from './abi-registry.service';
import {
  DecodeContractResultDto,
  ParseContractEventDto,
  PrepareInvocationDto,
  UpsertAbiRegistryDto,
} from './dto/abi-registry.dto';

@ApiTags('ABI Registry')
@Controller('abi-registry')
export class AbiRegistryController {
  constructor(private readonly abiRegistryService: AbiRegistryService) {}

  @Get('contracts')
  @ApiOperation({ summary: 'List registered contract ABIs' })
  async listRegistries() {
    return this.abiRegistryService.listRegistries();
  }

  @Get('contracts/:address')
  @ApiOperation({ summary: 'Get the active or requested ABI version for a contract' })
  async getRegistry(@Param('address') address: string, @Query('version') version?: string) {
    return this.abiRegistryService.getRegistry(address, version);
  }

  @Post('contracts')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @ApiBearerAuth()
  @Roles(Role.SUPER_ADMIN, Role.TENANT_ADMIN)
  @ApiOperation({ summary: 'Create or update a contract ABI registry entry' })
  async upsertRegistry(@Request() req: any, @Body() dto: UpsertAbiRegistryDto) {
    return this.abiRegistryService.upsertRegistry(req.user?.userId, dto);
  }

  @Post('contracts/:address/invocations/prepare')
  @ApiOperation({ summary: 'Prepare a dynamic contract invocation from ABI metadata' })
  async prepareInvocation(@Param('address') address: string, @Body() dto: PrepareInvocationDto) {
    return this.abiRegistryService.prepareInvocation(address, dto);
  }

  @Post('contracts/:address/decode-result')
  @ApiOperation({ summary: 'Decode a contract function result using ABI metadata' })
  async decodeResult(@Param('address') address: string, @Body() dto: DecodeContractResultDto) {
    return this.abiRegistryService.decodeContractResult(address, dto);
  }

  @Post('contracts/:address/parse-event')
  @ApiOperation({ summary: 'Parse a Soroban event using the ABI registry' })
  async parseEvent(@Param('address') address: string, @Body() dto: ParseContractEventDto) {
    return this.abiRegistryService.parseContractEvent(address, dto);
  }
}
