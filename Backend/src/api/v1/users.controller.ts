import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Param,
  Body,
  Headers,
  Deprecated,
  Version,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBody } from '@nestjs/swagger';
import { UserService } from '../../user/user.service';
import { CreateUserDto, UpdateUserDto, UserResponseDto } from './dto/user.dto';

@ApiTags('users')
@Controller('api/v1/users')
@Version('1')
export class UsersV1Controller {
  constructor(private readonly userService: UserService) {}

  @Get()
  @ApiOperation({ summary: 'Get all users (v1)', deprecated: true })
  @ApiResponse({ status: 200, description: 'List of users', type: [UserResponseDto] })
  @ApiResponse({ status: 410, description: 'API version deprecated' })
  @Deprecated({ since: '2024-01-01', reason: 'Use API v2 instead' })
  async findAll(@Headers() headers): Promise<UserResponseDto[]> {
    // Add deprecation warning header
    return this.userService.findAll();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get user by ID (v1)', deprecated: true })
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiResponse({ status: 200, description: 'User found', type: UserResponseDto })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 410, description: 'API version deprecated' })
  @Deprecated({ since: '2024-01-01', reason: 'Use API v2 instead' })
  async findOne(
    @Param('id') id: string,
    @Headers() headers: Record<string, string>,
  ): Promise<UserResponseDto> {
    return this.userService.findOne(id);
  }

  @Post()
  @ApiOperation({ summary: 'Create user (v1)', deprecated: true })
  @ApiBody({ type: CreateUserDto })
  @ApiResponse({ status: 201, description: 'User created', type: UserResponseDto })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 410, description: 'API version deprecated' })
  @Deprecated({ since: '2024-01-01', reason: 'Use API v2 instead' })
  async create(
    @Body() createUserDto: CreateUserDto,
    @Headers() headers: Record<string, string>,
  ): Promise<UserResponseDto> {
    return this.userService.create(createUserDto);
  }

  @Put(':id')
  @ApiOperation({ summary: 'Update user (v1)', deprecated: true })
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiBody({ type: UpdateUserDto })
  @ApiResponse({ status: 200, description: 'User updated', type: UserResponseDto })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 410, description: 'API version deprecated' })
  @Deprecated({ since: '2024-01-01', reason: 'Use API v2 instead' })
  async update(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
    @Headers() headers: Record<string, string>,
  ): Promise<UserResponseDto> {
    return this.userService.update(id, updateUserDto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete user (v1)', deprecated: true })
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiResponse({ status: 200, description: 'User deleted' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiResponse({ status: 410, description: 'API version deprecated' })
  @Deprecated({ since: '2024-01-01', reason: 'Use API v2 instead' })
  async remove(@Param('id') id: string, @Headers() headers: Record<string, string>): Promise<void> {
    return this.userService.remove(id);
  }
}
