import { Controller, Post } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { NonceService } from './nonce.service';
import { NonceResponseDto } from './dto/nonce.dto';

@ApiTags('nonce')
@Controller('nonce')
export class NonceController {
  constructor(private readonly nonceService: NonceService) {}

  @Post()
  @ApiOperation({
    summary: 'Generate nonce',
    description:
      'Generates a unique nonce for transaction signing. Used to prevent replay attacks.',
  })
  @ApiResponse({
    status: 201,
    description: 'Nonce generated successfully',
    type: NonceResponseDto,
  })
  async getNonce(): Promise<NonceResponseDto> {
    return { nonce: await this.nonceService.generateNonce() };
  }
}
