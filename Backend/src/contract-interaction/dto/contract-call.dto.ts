import {
  IsString,
  IsObject,
  IsOptional,
  IsNumber,
  IsArray,
  IsBoolean,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class FunctionParameterDto {
  @ApiProperty()
  @IsString()
  name: string;

  @ApiProperty()
  @IsString()
  type: string;

  @ApiProperty()
  value: any;
}

export class MultisigDataDto {
  @ApiProperty()
  @IsArray()
  @IsString({ each: true })
  signers: string[];

  @ApiProperty()
  @IsNumber()
  requiredSignatures: number;

  @ApiPropertyOptional()
  @IsArray()
  @IsString({ each: true })
  signedBy?: string[];
}

export class ContractCallDto {
  @ApiProperty()
  @IsString()
  contractAddress: string;

  @ApiProperty()
  @IsString()
  functionName: string;

  @ApiProperty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => FunctionParameterDto)
  parameters: FunctionParameterDto[];

  @ApiPropertyOptional()
  @IsNumber()
  maxFee?: number;

  @ApiPropertyOptional()
  @IsNumber()
  gasLimit?: number;

  @ApiPropertyOptional()
  @IsNumber()
  nonce?: number;

  @ApiPropertyOptional()
  @IsBoolean()
  simulateOnly?: boolean;

  @ApiPropertyOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => MultisigDataDto)
  multisigData?: MultisigDataDto;

  @ApiPropertyOptional()
  @IsNumber()
  timeoutSeconds?: number;
}

export class ContractDeployDto {
  @ApiProperty()
  @IsString()
  wasmCode: string;

  @ApiProperty()
  @IsString()
  contractName: string;

  @ApiPropertyOptional()
  @IsObject()
  constructorArgs?: Record<string, any>;

  @ApiPropertyOptional()
  @IsNumber()
  maxFee?: number;

  @ApiPropertyOptional()
  @IsNumber()
  gasLimit?: number;

  @ApiPropertyOptional()
  @IsBoolean()
  simulateOnly?: boolean;
}

export class TransactionStatusDto {
  @ApiProperty()
  @IsString()
  transactionHash: string;

  @ApiPropertyOptional()
  @IsNumber()
  pollingInterval?: number;

  @ApiPropertyOptional()
  @IsNumber()
  maxPollingAttempts?: number;
}
