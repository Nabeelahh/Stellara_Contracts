import {
  Controller,
  Get,
  Post,
  Query,
  Body,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { SearchService } from './search.service';
import { SearchQueryDto, SearchResponseDto, SearchEntityType } from './dto/search.dto';

@ApiTags('Search')
@Controller('search')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class SearchController {
  constructor(private readonly searchService: SearchService) {}

  @Post()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Search across all entities' })
  @ApiResponse({ status: 200, description: 'Search results retrieved', type: SearchResponseDto })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async search(
    @Request() req: any,
    @Body() searchQuery: SearchQueryDto,
  ): Promise<SearchResponseDto> {
    return await this.searchService.search(searchQuery);
  }

  @Get('suggestions')
  @ApiOperation({ summary: 'Get search suggestions' })
  @ApiResponse({ status: 200, description: 'Suggestions retrieved' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getSuggestions(
    @Query('q') query: string,
    @Query('type') entityType?: SearchEntityType,
  ): Promise<string[]> {
    return await this.searchService.getSuggestions(query, entityType);
  }

  @Get('entities/:type')
  @ApiOperation({ summary: 'Search specific entity type' })
  @ApiResponse({ status: 200, description: 'Search results retrieved', type: SearchResponseDto })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async searchEntityType(
    @Request() req: any,
    @Query('q') query: string,
    @Query('type') entityType: SearchEntityType,
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 20,
  ): Promise<SearchResponseDto> {
    const searchQuery: SearchQueryDto = {
      query,
      entityTypes: [entityType],
      page,
      limit,
    };
    return await this.searchService.search(searchQuery);
  }
}
