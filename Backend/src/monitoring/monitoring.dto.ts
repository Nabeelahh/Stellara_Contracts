import { IsString, IsNumber, IsBoolean, IsOptional, IsInt, Min } from 'class-validator';

export class SyntheticTestResultDto {
  @IsString()
  testName: string;

  @IsString()
  location: string;

  @IsInt()
  @Min(0)
  durationMs: number;

  @IsBoolean()
  success: boolean;

  @IsOptional()
  @IsString()
  errorMessage?: string;

  @IsOptional()
  @IsInt()
  statusCode?: number;
}
