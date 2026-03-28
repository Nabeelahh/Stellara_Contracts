import { Body, Controller, Post } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ZkService } from './zk.service';
import { ProofRequestDto, ProofResponseDto, SolvencyProofRequestDto } from './zk.dto';

@ApiTags('zk')
@Controller('zk')
export class ZkController {
  constructor(private readonly zkService: ZkService) {}

  @Post('solvency')
  @ApiOperation({
    summary: 'Generate a solvency proof',
    description: 'Produces a zero-knowledge solvency proof using a Circom circuit',
  })
  @ApiResponse({ status: 200, type: ProofResponseDto })
  async generateSolvencyProof(@Body() request: SolvencyProofRequestDto): Promise<ProofResponseDto> {
    return this.zkService.generateSolvencyProof(request.balances, request.threshold);
  }

  @Post('verify')
  @ApiOperation({
    summary: 'Verify a zero-knowledge proof',
    description: 'Verifies a proof against public signals for an existing circuit',
  })
  @ApiResponse({ status: 200, type: Boolean })
  async verifyProof(@Body() request: ProofRequestDto): Promise<boolean> {
    return this.zkService.verifyProof('solvency', request.proof, request.publicSignals);
  }
}
