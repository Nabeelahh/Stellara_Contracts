import { Controller, Get, Param } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from '@nestjs/swagger';
import { PrismaService } from './prisma.service';
import { UserResponseDto, UserNotFoundDto } from './common/dto/common.dto';

@ApiTags('users')
@Controller('api/user')
export class UserController {
  constructor(private readonly prisma: PrismaService) {}

  @Get(':id')
  @ApiOperation({
    summary: 'Get user by ID',
    description: "Retrieves a user's public profile information by their unique identifier",
  })
  @ApiParam({
    name: 'id',
    description: 'User unique identifier',
    example: 'cm3x1234567890',
  })
  @ApiResponse({
    status: 200,
    description: 'User found',
    type: UserResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
    type: UserNotFoundDto,
  })
  async getUser(@Param('id') id: string): Promise<UserResponseDto | UserNotFoundDto> {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) return { error: 'User not found' };
    // Only return relevant fields
    return {
      id: user.id,
      walletAddress: user.walletAddress,
      reputationScore: user.reputationScore,
      trustScore: user.trustScore,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
