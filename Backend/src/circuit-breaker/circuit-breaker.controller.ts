import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { IsIn, IsOptional, IsString } from 'class-validator';

import { CircuitBreakerService, CircuitOverrideMode } from './circuit-breaker.service';

class CircuitOverrideDto {
  @IsIn(['AUTO', 'FORCE_OPEN', 'FORCE_CLOSED'])
  mode: CircuitOverrideMode;

  @IsOptional()
  @IsString()
  reason?: string;
}

@Controller('circuit-breakers')
export class CircuitBreakerController {
  constructor(private readonly circuitBreakerService: CircuitBreakerService) {}

  @Get()
  listCircuits() {
    return this.circuitBreakerService.getAllCircuits();
  }

  @Get(':name')
  getCircuit(@Param('name') name: string) {
    return this.circuitBreakerService.getCircuit(name);
  }

  @Post(':name/override')
  setOverride(@Param('name') name: string, @Body() dto: CircuitOverrideDto) {
    const circuit = this.circuitBreakerService.setOverride(name, dto.mode, dto.reason);
    return {
      ...circuit,
      updatedAt: new Date().toISOString(),
    };
  }

  @Post(':name/reset')
  resetCircuit(@Param('name') name: string) {
    return this.circuitBreakerService.reset(name);
  }
}
