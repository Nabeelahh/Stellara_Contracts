import { IsString, IsOptional, IsEnum, IsBoolean } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { NoteType } from '@prisma/client';

export class CreateSupportNoteDto {
  @ApiProperty({ description: 'User ID to attach note to' })
  @IsString()
  userId: string;

  @ApiProperty({ description: 'Note content' })
  @IsString()
  content: string;

  @ApiPropertyOptional({ enum: NoteType, description: 'Type of note' })
  @IsOptional()
  @IsEnum(NoteType)
  type?: NoteType;

  @ApiPropertyOptional({ description: 'Whether note is internal only' })
  @IsOptional()
  @IsBoolean()
  isInternal?: boolean;
}

export class UpdateSupportNoteDto {
  @ApiPropertyOptional({ description: 'Note content' })
  @IsOptional()
  @IsString()
  content?: string;

  @ApiPropertyOptional({ enum: NoteType, description: 'Type of note' })
  @IsOptional()
  @IsEnum(NoteType)
  type?: NoteType;

  @ApiPropertyOptional({ description: 'Whether note is internal only' })
  @IsOptional()
  @IsBoolean()
  isInternal?: boolean;
}
