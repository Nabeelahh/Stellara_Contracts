import { IsDateString, IsEnum, IsInt, IsOptional, IsString, Max, Min } from 'class-validator';

export enum RollupBucketDto {
  M1 = 'M1',
  M5 = 'M5',
  M15 = 'M15',
  H1 = 'H1',
  D1 = 'D1',
}

export enum AnalyticsExportFormatDto {
  CSV = 'csv',
  EXCEL = 'excel',
}

export class QueryRealtimeRollupsDto {
  @IsOptional()
  @IsString()
  metricName?: string;

  @IsOptional()
  @IsEnum(RollupBucketDto)
  bucket?: RollupBucketDto;

  @IsOptional()
  @IsDateString()
  from?: string;

  @IsOptional()
  @IsDateString()
  to?: string;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(5000)
  limit?: number = 1000;
}

export class ExportRealtimeRollupsDto extends QueryRealtimeRollupsDto {
  @IsOptional()
  @IsEnum(AnalyticsExportFormatDto)
  format?: AnalyticsExportFormatDto = AnalyticsExportFormatDto.CSV;
}

