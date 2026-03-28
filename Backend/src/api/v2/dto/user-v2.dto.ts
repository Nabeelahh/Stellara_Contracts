import { IsEmail, IsString, IsOptional, IsNumber, IsDateString, IsArray } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateUserDtoV2 {
  @ApiProperty({ description: 'User email address', example: 'user@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ description: 'User display name', example: 'John Doe' })
  @IsString()
  name: string;

  @ApiProperty({ description: 'User wallet address', example: 'GD5...' })
  @IsString()
  walletAddress: string;

  @ApiProperty({
    description: 'User profile data',
    example: { bio: 'Software developer', skills: ['JavaScript', 'TypeScript'] },
  })
  profileData: UserProfileV2;

  @ApiProperty({ description: 'User roles', example: ['USER'], isArray: true })
  @IsArray()
  @IsString({ each: true })
  roles: string[];

  @ApiPropertyOptional({
    description: 'User preferences',
    example: { theme: 'dark', language: 'en' },
  })
  preferences?: UserPreferencesV2;
}

export class UpdateUserDtoV2 {
  @ApiPropertyOptional({ description: 'User email address', example: 'user@example.com' })
  @IsEmail()
  @IsOptional()
  email?: string;

  @ApiPropertyOptional({ description: 'User display name', example: 'John Doe' })
  @IsString()
  @IsOptional()
  name?: string;

  @ApiPropertyOptional({ description: 'User wallet address', example: 'GD5...' })
  @IsString()
  @IsOptional()
  walletAddress?: string;

  @ApiPropertyOptional({
    description: 'User profile data',
    example: { bio: 'Software developer', skills: ['JavaScript', 'TypeScript'] },
  })
  @IsOptional()
  profileData?: UserProfileV2;

  @ApiPropertyOptional({ description: 'User roles', example: ['USER'], isArray: true })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  roles?: string[];

  @ApiPropertyOptional({
    description: 'User preferences',
    example: { theme: 'dark', language: 'en' },
  })
  @IsOptional()
  preferences?: UserPreferencesV2;
}

export class UserResponseDtoV2 {
  @ApiProperty({ description: 'User unique identifier', example: 'cuid...' })
  id: string;

  @ApiProperty({ description: 'User email address', example: 'user@example.com' })
  email: string;

  @ApiProperty({ description: 'User display name', example: 'John Doe' })
  name: string;

  @ApiProperty({ description: 'User wallet address', example: 'GD5...' })
  walletAddress: string;

  @ApiProperty({
    description: 'User profile data',
    example: { bio: 'Software developer', skills: ['JavaScript', 'TypeScript'] },
  })
  profileData: UserProfileV2;

  @ApiProperty({ description: 'User reputation score', example: 750 })
  reputationScore: number;

  @ApiProperty({ description: 'User trust score', example: 500 })
  trustScore: number;

  @ApiProperty({ description: 'User roles', example: ['USER'], isArray: true })
  roles: string[];

  @ApiPropertyOptional({
    description: 'User preferences',
    example: { theme: 'dark', language: 'en' },
  })
  preferences?: UserPreferencesV2;

  @ApiProperty({ description: 'Account creation date', example: '2024-01-01T00:00:00.000Z' })
  @Type(() => Date)
  createdAt: Date;

  @ApiProperty({ description: 'Last update date', example: '2024-01-01T00:00:00.000Z' })
  @Type(() => Date)
  updatedAt: Date;
}

export class UserProfileV2 {
  @ApiPropertyOptional({
    description: 'User biography',
    example: 'Software developer with 5 years experience',
  })
  @IsString()
  @IsOptional()
  bio?: string;

  @ApiProperty({
    description: 'User skills',
    example: ['JavaScript', 'TypeScript', 'Node.js'],
    isArray: true,
  })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  skills?: string[];

  @ApiProperty({ description: 'User experience level', example: 'senior' })
  @IsString()
  @IsOptional()
  experienceLevel?: string;

  @ApiProperty({ description: 'User location', example: 'San Francisco, CA' })
  @IsString()
  @IsOptional()
  location?: string;
}

export class UserPreferencesV2 {
  @ApiPropertyOptional({ description: 'UI theme preference', example: 'dark' })
  @IsString()
  @IsOptional()
  theme?: string;

  @ApiPropertyOptional({ description: 'Language preference', example: 'en' })
  @IsString()
  @IsOptional()
  language?: string;

  @ApiPropertyOptional({ description: 'Email notifications enabled', example: true })
  @IsOptional()
  emailNotifications?: boolean;

  @ApiPropertyOptional({ description: 'Push notifications enabled', example: false })
  @IsOptional()
  pushNotifications?: boolean;
}
