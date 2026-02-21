import {
  Controller,
  Post,
  Get,
  Body,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiBadRequestResponse,
  ApiConflictResponse,
} from '@nestjs/swagger';
import { IsEmail, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { ApiDocumented, ApiPublic } from '../common/decorators/api-documented.decorator';
import { ErrorResponseDto }         from '../common/dtos/api-response.dto';


export class RegisterDto {
  @ApiProperty({ example: 'alice@stellara.network' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'Hunter2!', minLength: 8 })
  @IsString()
  @MinLength(8)
  password: string;

  @ApiProperty({ example: 'alice' })
  @IsString()
  @MinLength(2)
  username: string;
}

export class LoginDto {
  @ApiProperty({ example: 'alice@stellara.network' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'Hunter2!' })
  @IsString()
  password: string;
}

export class AuthTokenDto {
  @ApiProperty({ example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…' })
  accessToken: string;

  @ApiProperty({ example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…' })
  refreshToken: string;

  @ApiProperty({ example: 3600, description: 'Seconds until accessToken expires' })
  expiresIn: number;
}

export class UserProfileDto {
  @ApiProperty({ example: 'user_abc123' })
  id: string;

  @ApiProperty({ example: 'alice@stellara.network' })
  email: string;

  @ApiProperty({ example: 'alice' })
  username: string;

  @ApiProperty({ example: '2026-01-01T00:00:00.000Z' })
  createdAt: string;
}

// ─── Controller ───────────────────────────────────────────────────────────────

@ApiTags('Auth')                        
@Controller({ path: 'auth', version: '1' })
export class ExampleAuthController {

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiPublic({                            
    summary: 'Register a new user',
    description: 'Creates an account and returns JWT tokens.',
  })
  @ApiCreatedResponse({ type: AuthTokenDto, description: 'Account created' })
  @ApiBadRequestResponse({ type: ErrorResponseDto, description: 'Validation failed' })
  @ApiConflictResponse({ type: ErrorResponseDto, description: 'Email already registered' })
  async register(@Body() dto: RegisterDto): Promise<AuthTokenDto> {
    // your existing logic stays exactly the same
    return {} as AuthTokenDto;
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiPublic({ summary: 'Log in and receive JWT tokens' })
  @ApiOkResponse({ type: AuthTokenDto, description: 'Login successful' })
  @ApiBadRequestResponse({ type: ErrorResponseDto })
  async login(@Body() dto: LoginDto): Promise<AuthTokenDto> {
    return {} as AuthTokenDto;
  }

  @Get('profile')
  @ApiDocumented({                       
    summary: 'Get the authenticated user's profile',
    requiresAuth: true,
  })
  @ApiOkResponse({ type: UserProfileDto })
  async getProfile(): Promise<UserProfileDto> {
    return {} as UserProfileDto;
  }
}