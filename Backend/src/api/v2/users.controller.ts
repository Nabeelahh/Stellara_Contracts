import { Controller, Get, Post, Put, Delete, Param, Body, Headers, Version } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBody } from '@nestjs/swagger';
import { UserService } from '../../user/user.service';
import { CreateUserDtoV2, UpdateUserDtoV2, UserResponseDtoV2 } from './dto/user-v2.dto';

@ApiTags('users')
@Controller('api/v2/users')
@Version('2')
export class UsersV2Controller {
  constructor(private readonly userService: UserService) {}

  @Get()
  @ApiOperation({ summary: 'Get all users (v2)' })
  @ApiResponse({ status: 200, description: 'List of users', type: [UserResponseDtoV2] })
  async findAll(@Headers() headers): Promise<UserResponseDtoV2[]> {
    return this.userService.findAllV2();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get user by ID (v2)' })
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiResponse({ status: 200, description: 'User found', type: UserResponseDtoV2 })
  @ApiResponse({ status: 404, description: 'User not found' })
  async findOne(
    @Param('id') id: string,
    @Headers() headers: Record<string, string>,
  ): Promise<UserResponseDtoV2> {
    return this.userService.findOneV2(id);
  }

  @Post()
  @ApiOperation({ summary: 'Create user (v2)' })
  @ApiBody({ type: CreateUserDtoV2 })
  @ApiResponse({ status: 201, description: 'User created', type: UserResponseDtoV2 })
  @ApiResponse({ status: 400, description: 'Bad request' })
  async create(
    @Body() createUserDto: CreateUserDtoV2,
    @Headers() headers: Record<string, string>,
  ): Promise<UserResponseDtoV2> {
    return this.userService.createV2(createUserDto);
  }

  @Put(':id')
  @ApiOperation({ summary: 'Update user (v2)' })
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiBody({ type: UpdateUserDtoV2 })
  @ApiResponse({ status: 200, description: 'User updated', type: UserResponseDtoV2 })
  @ApiResponse({ status: 404, description: 'User not found' })
  async update(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDtoV2,
    @Headers() headers: Record<string, string>,
  ): Promise<UserResponseDtoV2> {
    return this.userService.updateV2(id, updateUserDto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete user (v2)' })
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiResponse({ status: 200, description: 'User deleted' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async remove(@Param('id') id: string, @Headers() headers: Record<string, string>): Promise<void> {
    return this.userService.remove(id);
  }
}
