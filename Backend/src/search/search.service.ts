import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource, SelectQueryBuilder } from 'typeorm';
import { Client } from '@elastic/elasticsearch';

import { User } from '../auth/entities/user.entity';
import {
  TransactionRecord,
  TransactionStatus,
} from '../contract-interaction/entities/transaction-record.entity';
import {
  ContractMetadata,
  ContractStatus,
} from '../contract-interaction/entities/contract-metadata.entity';
import { Workflow } from '../workflow/entities/workflow.entity';
import { AuditLog } from '../audit/audit.entity';

import {
  SearchQueryDto,
  SearchResponseDto,
  SearchResultDto,
  FacetResultDto,
  SearchEntityType,
  SortOrder,
} from './dto/search.dto';

@Injectable()
export class SearchService {
  private readonly logger = new Logger(SearchService.name);
  private elasticsearchClient: Client;
  private useElasticsearch: boolean;

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(TransactionRecord)
    private transactionRepository: Repository<TransactionRecord>,
    @InjectRepository(ContractMetadata)
    private contractRepository: Repository<ContractMetadata>,
    @InjectRepository(Workflow)
    private workflowRepository: Repository<Workflow>,
    @InjectRepository(AuditLog)
    private auditLogRepository: Repository<AuditLog>,
    private configService: ConfigService,
    private dataSource: DataSource,
  ) {
    this.useElasticsearch = this.configService.get < string('ELASTICSEARCH_URL') !== undefined;

    if (this.useElasticsearch) {
      this.elasticsearchClient = new Client({
        node: this.configService.get<string>('ELASTICSEARCH_URL'),
      });
      this.initializeElasticsearchIndex();
    }
  }

  async search(searchQuery: SearchQueryDto): Promise<SearchResponseDto> {
    const startTime = Date.now();

    if (this.useElasticsearch) {
      return await this.elasticsearchSearch(searchQuery, startTime);
    } else {
      return await this.postgresSearch(searchQuery, startTime);
    }
  }

  async indexEntity(entityType: SearchEntityType, data: any): Promise<void> {
    if (!this.useElasticsearch) return;

    try {
      const document = this.transformEntityForElasticsearch(entityType, data);
      await this.elasticsearchClient.index({
        index: `stellara_${entityType}`,
        id: data.id,
        body: document,
      });
    } catch (error) {
      this.logger.error(`Failed to index ${entityType} ${data.id}: ${error.message}`);
    }
  }

  async deleteEntity(entityType: SearchEntityType, id: string): Promise<void> {
    if (!this.useElasticsearch) return;

    try {
      await this.elasticsearchClient.delete({
        index: `stellara_${entityType}`,
        id,
      });
    } catch (error) {
      this.logger.error(`Failed to delete ${entityType} ${id}: ${error.message}`);
    }
  }

  async getSuggestions(query: string, entityType?: SearchEntityType): Promise<string[]> {
    if (!this.useElasticsearch) {
      return await this.getPostgresSuggestions(query, entityType);
    }

    try {
      const index = entityType ? `stellara_${entityType}` : 'stellara_*';
      const response = await this.elasticsearchClient.search({
        index,
        body: {
          suggest: {
            text: query,
            simple_phrase: {
              phrase: {
                field: 'suggest',
                size: 10,
              },
            },
          },
        },
      });

      return response.suggest.simple_phrase[0].options.map((option: any) => option.text);
    } catch (error) {
      this.logger.error(`Failed to get suggestions: ${error.message}`);
      return [];
    }
  }

  private async elasticsearchSearch(
    searchQuery: SearchQueryDto,
    startTime: number,
  ): Promise<SearchResponseDto> {
    const { query, entityTypes, filters, page, limit, sortBy, sortOrder, highlight, facets } =
      searchQuery;
    const offset = (page - 1) * limit;

    const indices =
      entityTypes && entityTypes.length > 0
        ? entityTypes.map((type) => `stellara_${type}`).join(',')
        : 'stellara_*';

    const searchBody: any = {
      query: this.buildElasticsearchQuery(query, filters),
      from: offset,
      size: limit,
      sort: [{ [sortBy]: { order: sortOrder } }],
    };

    if (highlight) {
      searchBody.highlight = {
        fields: {
          title: {},
          description: {},
          content: {},
        },
        fragment_size: 150,
        number_of_fragments: 3,
      };
    }

    if (facets) {
      searchBody.aggs = this.buildAggregations();
    }

    try {
      const response = await this.elasticsearchClient.search({
        index: indices,
        body: searchBody,
      });

      return this.formatElasticsearchResponse(response, searchQuery, startTime);
    } catch (error) {
      this.logger.error(`Elasticsearch search failed: ${error.message}`);
      throw error;
    }
  }

  private async postgresSearch(
    searchQuery: SearchQueryDto,
    startTime: number,
  ): Promise<SearchResponseDto> {
    const { query, entityTypes, filters, page, limit, sortBy, sortOrder } = searchQuery;
    const offset = (page - 1) * limit;

    const results: SearchResultDto[] = [];
    let total = 0;

    if (!entityTypes || entityTypes.includes(SearchEntityType.USER)) {
      const userResults = await this.searchUsers(query, filters, offset, limit, sortBy, sortOrder);
      results.push(...userResults.items);
      total += userResults.total;
    }

    if (!entityTypes || entityTypes.includes(SearchEntityType.TRANSACTION)) {
      const transactionResults = await this.searchTransactions(
        query,
        filters,
        offset,
        limit,
        sortBy,
        sortOrder,
      );
      results.push(...transactionResults.items);
      total += transactionResults.total;
    }

    if (!entityTypes || entityTypes.includes(SearchEntityType.CONTRACT)) {
      const contractResults = await this.searchContracts(
        query,
        filters,
        offset,
        limit,
        sortBy,
        sortOrder,
      );
      results.push(...contractResults.items);
      total += contractResults.total;
    }

    if (!entityTypes || entityTypes.includes(SearchEntityType.WORKFLOW)) {
      const workflowResults = await this.searchWorkflows(
        query,
        filters,
        offset,
        limit,
        sortBy,
        sortOrder,
      );
      results.push(...workflowResults.items);
      total += workflowResults.total;
    }

    if (!entityTypes || entityTypes.includes(SearchEntityType.AUDIT_LOG)) {
      const auditResults = await this.searchAuditLogs(
        query,
        filters,
        offset,
        limit,
        sortBy,
        sortOrder,
      );
      results.push(...auditResults.items);
      total += auditResults.total;
    }

    results.sort((a, b) => b.score - a.score);
    const paginatedResults = results.slice(offset, offset + limit);

    return {
      results: paginatedResults,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
      searchTime: Date.now() - startTime,
    };
  }

  private buildElasticsearchQuery(query: string, filters?: any): any {
    const must: any[] = [
      {
        multi_match: {
          query,
          fields: ['title^3', 'description^2', 'content', 'tags'],
          fuzziness: 'AUTO',
        },
      },
    ];

    if (filters) {
      if (filters.status) {
        must.push({ term: { status: filters.status } });
      }
      if (filters.userId) {
        must.push({ term: { userId: filters.userId } });
      }
      if (filters.contractAddress) {
        must.push({ term: { contractAddress: filters.contractAddress } });
      }
      if (filters.tags && filters.tags.length > 0) {
        must.push({ terms: { tags: filters.tags } });
      }
      if (filters.dateRange) {
        const dateFilter: any = {};
        if (filters.dateRange.startDate) {
          dateFilter.gte = filters.dateRange.startDate;
        }
        if (filters.dateRange.endDate) {
          dateFilter.lte = filters.dateRange.endDate;
        }
        if (Object.keys(dateFilter).length > 0) {
          must.push({ range: { createdAt: dateFilter } });
        }
      }
    }

    return {
      bool: { must },
    };
  }

  private buildAggregations(): any {
    return {
      status: {
        terms: { field: 'status' },
      },
      entityTypes: {
        terms: { field: 'entityType' },
      },
      tags: {
        terms: { field: 'tags' },
      },
      dateRange: {
        date_histogram: {
          field: 'createdAt',
          calendar_interval: 'month',
        },
      },
    };
  }

  private formatElasticsearchResponse(
    response: any,
    searchQuery: SearchQueryDto,
    startTime: number,
  ): SearchResponseDto {
    const results: SearchResultDto[] = response.body.hits.hits.map((hit: any) => ({
      id: hit._id,
      entityType: hit._index.replace('stellara_', ''),
      title: hit._source.title,
      description: hit._source.description,
      score: hit._score,
      highlights: hit.highlight ? Object.values(hit.highlight).flat() : undefined,
      data: hit._source,
      createdAt: new Date(hit._source.createdAt),
    }));

    const facets: FacetResultDto[] = [];
    if (searchQuery.facets && response.body.aggregations) {
      for (const [key, agg] of Object.entries(response.body.aggregations)) {
        facets.push({
          field: key,
          values: (agg as any).buckets.map((bucket: any) => ({
            value: bucket.key,
            count: bucket.doc_count,
          })),
        });
      }
    }

    return {
      results,
      total: response.body.hits.total.value,
      page: searchQuery.page,
      limit: searchQuery.limit,
      totalPages: Math.ceil(response.body.hits.total.value / searchQuery.limit),
      facets,
      searchTime: Date.now() - startTime,
    };
  }

  private async searchUsers(
    query: string,
    filters: any,
    offset: number,
    limit: number,
    sortBy: string,
    sortOrder: SortOrder,
  ): Promise<{ items: SearchResultDto[]; total: number }> {
    const queryBuilder = this.userRepository
      .createQueryBuilder('user')
      .where('user.email ILIKE :query OR user.username ILIKE :query', { query: `%${query}%` });

    if (filters?.status) {
      queryBuilder.andWhere('user.status = :status', { status: filters.status });
    }

    queryBuilder.orderBy(`user.${sortBy}`, sortOrder);
    queryBuilder.skip(offset).take(limit);

    const [users, total] = await queryBuilder.getManyAndCount();

    const items: SearchResultDto[] = users.map((user) => ({
      id: user.id,
      entityType: SearchEntityType.USER,
      title: user.username || user.email,
      description: user.email,
      score: 1.0,
      data: user,
      createdAt: user.createdAt,
    }));

    return { items, total };
  }

  private async searchTransactions(
    query: string,
    filters: any,
    offset: number,
    limit: number,
    sortBy: string,
    sortOrder: SortOrder,
  ): Promise<{ items: SearchResultDto[]; total: number }> {
    const queryBuilder = this.transactionRepository
      .createQueryBuilder('transaction')
      .leftJoinAndSelect('transaction.user', 'user')
      .where(
        'transaction.transactionHash ILIKE :query OR CAST(transaction.functionCall AS TEXT) ILIKE :query',
        { query: `%${query}%` },
      );

    if (filters?.status) {
      queryBuilder.andWhere('transaction.status = :status', { status: filters.status });
    }
    if (filters?.userId) {
      queryBuilder.andWhere('transaction.userId = :userId', { userId: filters.userId });
    }
    if (filters?.contractAddress) {
      queryBuilder.andWhere('transaction.contractId = :contractAddress', {
        contractAddress: filters.contractAddress,
      });
    }

    queryBuilder.orderBy(`transaction.${sortBy}`, sortOrder);
    queryBuilder.skip(offset).take(limit);

    const [transactions, total] = await queryBuilder.getManyAndCount();

    const items: SearchResultDto[] = transactions.map((transaction) => ({
      id: transaction.id,
      entityType: SearchEntityType.TRANSACTION,
      title: `Transaction ${transaction.transactionHash}`,
      description: `${transaction.transactionType} - ${transaction.status}`,
      score: 1.0,
      data: transaction,
      createdAt: transaction.createdAt,
    }));

    return { items, total };
  }

  private async searchContracts(
    query: string,
    filters: any,
    offset: number,
    limit: number,
    sortBy: string,
    sortOrder: SortOrder,
  ): Promise<{ items: SearchResultDto[]; total: number }> {
    const queryBuilder = this.contractRepository
      .createQueryBuilder('contract')
      .leftJoinAndSelect('contract.user', 'user')
      .where('contract.contractName ILIKE :query OR contract.contractAddress ILIKE :query', {
        query: `%${query}%`,
      });

    if (filters?.status) {
      queryBuilder.andWhere('contract.status = :status', { status: filters.status });
    }
    if (filters?.userId) {
      queryBuilder.andWhere('contract.userId = :userId', { userId: filters.userId });
    }

    queryBuilder.orderBy(`contract.${sortBy}`, sortOrder);
    queryBuilder.skip(offset).take(limit);

    const [contracts, total] = await queryBuilder.getManyAndCount();

    const items: SearchResultDto[] = contracts.map((contract) => ({
      id: contract.id,
      entityType: SearchEntityType.CONTRACT,
      title: contract.contractName,
      description: contract.contractAddress,
      score: 1.0,
      data: contract,
      createdAt: contract.createdAt,
    }));

    return { items, total };
  }

  private async searchWorkflows(
    query: string,
    filters: any,
    offset: number,
    limit: number,
    sortBy: string,
    sortOrder: SortOrder,
  ): Promise<{ items: SearchResultDto[]; total: number }> {
    const queryBuilder = this.workflowRepository
      .createQueryBuilder('workflow')
      .where('workflow.name ILIKE :query OR workflow.description ILIKE :query', {
        query: `%${query}%`,
      });

    if (filters?.status) {
      queryBuilder.andWhere('workflow.status = :status', { status: filters.status });
    }
    if (filters?.userId) {
      queryBuilder.andWhere('workflow.userId = :userId', { userId: filters.userId });
    }

    queryBuilder.orderBy(`workflow.${sortBy}`, sortOrder);
    queryBuilder.skip(offset).take(limit);

    const [workflows, total] = await queryBuilder.getManyAndCount();

    const items: SearchResultDto[] = workflows.map((workflow) => ({
      id: workflow.id,
      entityType: SearchEntityType.WORKFLOW,
      title: workflow.name,
      description: workflow.description,
      score: 1.0,
      data: workflow,
      createdAt: workflow.createdAt,
    }));

    return { items, total };
  }

  private async searchAuditLogs(
    query: string,
    filters: any,
    offset: number,
    limit: number,
    sortBy: string,
    sortOrder: SortOrder,
  ): Promise<{ items: SearchResultDto[]; total: number }> {
    const queryBuilder = this.auditLogRepository
      .createQueryBuilder('audit')
      .where(
        'audit.action ILIKE :query OR audit.resource ILIKE :query OR CAST(audit.details AS TEXT) ILIKE :query',
        { query: `%${query}%` },
      );

    if (filters?.userId) {
      queryBuilder.andWhere('audit.userId = :userId', { userId: filters.userId });
    }
    if (filters?.dateRange) {
      if (filters.dateRange.startDate) {
        queryBuilder.andWhere('audit.createdAt >= :startDate', {
          startDate: filters.dateRange.startDate,
        });
      }
      if (filters.dateRange.endDate) {
        queryBuilder.andWhere('audit.createdAt <= :endDate', {
          endDate: filters.dateRange.endDate,
        });
      }
    }

    queryBuilder.orderBy(`audit.${sortBy}`, sortOrder);
    queryBuilder.skip(offset).take(limit);

    const [auditLogs, total] = await queryBuilder.getManyAndCount();

    const items: SearchResultDto[] = auditLogs.map((audit) => ({
      id: audit.id,
      entityType: SearchEntityType.AUDIT_LOG,
      title: `${audit.action} - ${audit.resource}`,
      description: audit.userId,
      score: 1.0,
      data: audit,
      createdAt: audit.createdAt,
    }));

    return { items, total };
  }

  private async getPostgresSuggestions(
    query: string,
    entityType?: SearchEntityType,
  ): Promise<string[]> {
    const suggestions: string[] = [];
    const queryLower = query.toLowerCase();

    if (!entityType || entityType === SearchEntityType.USER) {
      const users = await this.userRepository
        .createQueryBuilder('user')
        .where('user.username ILIKE :query', { query: `${queryLower}%` })
        .select('user.username')
        .limit(5)
        .getMany();
      suggestions.push(...users.map((u) => u.username).filter(Boolean));
    }

    if (!entityType || entityType === SearchEntityType.CONTRACT) {
      const contracts = await this.contractRepository
        .createQueryBuilder('contract')
        .where('contract.contractName ILIKE :query', { query: `${queryLower}%` })
        .select('contract.contractName')
        .limit(5)
        .getMany();
      suggestions.push(...contracts.map((c) => c.contractName).filter(Boolean));
    }

    return suggestions.slice(0, 10);
  }

  private transformEntityForElasticsearch(entityType: SearchEntityType, data: any): any {
    const base = {
      id: data.id,
      entityType,
      createdAt: data.createdAt,
      updatedAt: data.updatedAt,
    };

    switch (entityType) {
      case SearchEntityType.USER:
        return {
          ...base,
          title: data.username || data.email,
          description: data.email,
          content: `${data.username} ${data.email}`,
          status: data.status,
          tags: [data.role],
        };
      case SearchEntityType.TRANSACTION:
        return {
          ...base,
          title: `Transaction ${data.transactionHash}`,
          description: `${data.transactionType} - ${data.status}`,
          content: `${data.transactionHash} ${JSON.stringify(data.functionCall)}`,
          status: data.status,
          userId: data.userId,
          contractAddress: data.contractId,
          tags: [data.transactionType],
        };
      case SearchEntityType.CONTRACT:
        return {
          ...base,
          title: data.contractName,
          description: data.contractAddress,
          content: `${data.contractName} ${data.contractAddress}`,
          status: data.status,
          userId: data.userId,
          tags: [data.contractVersion],
        };
      case SearchEntityType.WORKFLOW:
        return {
          ...base,
          title: data.name,
          description: data.description,
          content: `${data.name} ${data.description}`,
          status: data.status,
          userId: data.userId,
          tags: [data.type],
        };
      case SearchEntityType.AUDIT_LOG:
        return {
          ...base,
          title: `${data.action} - ${data.resource}`,
          description: data.userId,
          content: `${data.action} ${data.resource} ${JSON.stringify(data.details)}`,
          userId: data.userId,
          tags: [data.action],
        };
      default:
        return base;
    }
  }

  private async initializeElasticsearchIndex(): Promise<void> {
    try {
      const entityTypes = Object.values(SearchEntityType);

      for (const entityType of entityTypes) {
        const indexName = `stellara_${entityType}`;

        try {
          await this.elasticsearchClient.indices.get({ index: indexName });
        } catch (error) {
          if (error.statusCode === 404) {
            await this.elasticsearchClient.indices.create({
              index: indexName,
              body: {
                mappings: {
                  properties: {
                    title: {
                      type: 'text',
                      analyzer: 'standard',
                    },
                    description: {
                      type: 'text',
                      analyzer: 'standard',
                    },
                    content: {
                      type: 'text',
                      analyzer: 'standard',
                    },
                    status: {
                      type: 'keyword',
                    },
                    userId: {
                      type: 'keyword',
                    },
                    contractAddress: {
                      type: 'keyword',
                    },
                    tags: {
                      type: 'keyword',
                    },
                    entityType: {
                      type: 'keyword',
                    },
                    createdAt: {
                      type: 'date',
                    },
                    updatedAt: {
                      type: 'date',
                    },
                    suggest: {
                      type: 'completion',
                    },
                  },
                },
              },
            });
          }
        }
      }
    } catch (error) {
      this.logger.error(`Failed to initialize Elasticsearch indices: ${error.message}`);
    }
  }
}
