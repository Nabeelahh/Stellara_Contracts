import { Controller, Post, Body } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
import { StorageService } from './storage.service';
import {
  ProjectMetadataDto,
  PinMetadataResponseDto,
  BannerUploadDto,
  VerifyHashResponseDto,
} from './dto/storage.dto';

@ApiTags('storage')
@ApiBearerAuth('JWT-auth')
@Controller('projects')
export class StorageController {
  constructor(private readonly storageService: StorageService) {}

  @Post('metadata')
  @ApiOperation({
    summary: 'Pin project metadata to IPFS',
    description:
      'Uploads and pins project metadata to IPFS, returning the content identifier (CID)',
  })
  @ApiBody({ type: ProjectMetadataDto })
  @ApiResponse({
    status: 201,
    description: 'Metadata pinned successfully',
    type: PinMetadataResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid metadata format',
  })
  async pinProjectMetadata(@Body() metadata: ProjectMetadataDto): Promise<string> {
    return this.storageService.pinProjectMetadata(metadata);
  }

  @Post('banner')
  @ApiOperation({
    summary: 'Upload and optimize banner image',
    description: 'Optimizes a banner image and uploads it to IPFS storage',
  })
  @ApiBody({ type: BannerUploadDto })
  @ApiResponse({
    status: 201,
    description: 'Banner uploaded successfully',
    type: PinMetadataResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid image format or dimensions',
  })
  async optimizeAndUploadBanner(@Body() banner: BannerUploadDto): Promise<string> {
    const optimizedImage = await this.storageService.optimizeImage(
      banner.imagePath,
      banner.width,
      banner.height,
    );
    const cid = await this.storageService.pinProjectMetadata({ image: optimizedImage });
    return cid;
  }

  @Post('verify-hash')
  @ApiOperation({
    summary: 'Verify IPFS hash',
    description: 'Verifies if an IPFS hash is valid and retrievable from the network',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        hash: {
          type: 'string',
          description: 'IPFS hash to verify',
          example: 'QmXxxYyyZzz...',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Hash verification result',
    type: VerifyHashResponseDto,
  })
  async verifyIPFSHash(@Body('hash') hash: string): Promise<boolean> {
    return this.storageService.verifyIPFSHash(hash);
  }
}
