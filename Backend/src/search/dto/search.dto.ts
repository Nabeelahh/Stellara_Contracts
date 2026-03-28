import {
  IsString,
  IsOptional,
  IsArray,
  IsEnum,
  IsNumber,
  IsBoolean,
  IsObject,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum SearchEntityType {
  USER = 'user',
  TRANSACTION = 'transaction',
  CONTRACT = 'contract',
  WORKFLOW = 'workflow',
  AUDIT_LOG = 'audit_log',
}

export enum SortOrder {
  ASC = 'asc',
  DESC = 'desc',
}

export class DateRangeFilterDto {
  @ApiPropertyOptional()
  @IsString()
  startDate?: string;

  @ApiPropertyOptional()
  @IsString()
  endDate?: string;
}

export class SearchFilterDto {
  @ApiPropertyOptional()
  @IsString()
  status?: string;

  @ApiPropertyOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @ApiPropertyOptional()
  @IsObject()
  @Type(() => DateRangeFilterDto)
  dateRange?: DateRangeFilterDto;

  @ApiPropertyOptional()
  @IsString()
  userId?: string;

  @ApiPropertyOptional()
  @IsString()
  contractAddress?: string;

  @ApiPropertyOptional()
  @IsNumber()
  minAmount?: number;

  @ApiPropertyOptional()
  @IsNumber()
  maxAmount?: number;
}

export class SearchQueryDto {
  @ApiProperty({ description: 'Search query string' })
  @IsString()
  query: string;

  @ApiPropertyOptional({
    description: 'Entity types to search',
    enum: SearchEntityType,
    isArray: true,
  })
  @IsArray()
  @IsEnum(SearchEntityType, { each: true })
  @Type(() => String)
  entityTypes?: SearchEntityType[];

  @ApiPropertyOptional({ description: 'Search filters' })
  @IsObject()
  @Type(() => SearchFilterDto)
  filters?: SearchFilterDto;

  @ApiPropertyOptional({ description: 'Page number', default: 1 })
  @IsNumber()
  @Type(() => Number)
  page?: number = 1;

  @ApiPropertyOptional({ description: 'Results per page', default: 20 })
  @IsNumber()
  @Type(() => Number)
  limit?: number = 20;

  @ApiPropertyOptional({ description: 'Sort field', default: 'createdAt' })
  @IsString()
  sortBy?: string = 'createdAt';

  @ApiPropertyOptional({
    description: 'Sort order',
    enum: SortOrder,
    default: SortOrder.DESC,
  })
  @IsEnum(SortOrder)
  sortOrder?: SortOrder = SortOrder.DESC;

  @ApiPropertyOptional({ description: 'Enable highlighting', default: true })
  @IsBoolean()
  @Type(() => Boolean)
  highlight?: boolean = true;

  @ApiPropertyOptional({ description: 'Enable faceted search', default: true })
  @IsBoolean()
  @Type(() => Boolean)
  facets?: boolean = true;
}

export class FacetResultDto {
  @ApiProperty()
  field: string;

  @ApiProperty()
  values: Array<{
    value: string;
    count: number;
  }>;
}

export class SearchResultDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  entityType: SearchEntityType;

  @ApiProperty()
  title: string;

  @ApiPropertyOptional()
  description?: string;

  @ApiProperty()
  score: number;

  @ApiPropertyOptional()
  highlights?: string[];

  @ApiProperty()
  data: Record<string, any>;

  @ApiProperty()
  createdAt: Date;
}

export class SearchResponseDto {
  @ApiProperty()
  results: SearchResultDto[];

  @ApiProperty()
  total: number;

  @ApiProperty()
  page: number;

  @ApiProperty()
  limit: number;

  @ApiProperty()
  totalPages: number;

  @ApiPropertyOptional()
  facets?: FacetResultDto[];

  @ApiPropertyOptional()
  suggestions?: string[];

  @ApiProperty()
  searchTime: number;
}
