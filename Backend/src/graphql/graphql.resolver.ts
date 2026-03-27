import { Resolver, Query, Args, Int } from '@nestjs/graphql';
import { GraphqlService } from './graphql.service';
import { UserType, CallType, PaginatedUsersType } from './graphql.types';

@Resolver()
export class GraphqlResolver {
  constructor(private readonly graphqlService: GraphqlService) {}

  @Query(() => UserType, { nullable: true, description: 'Fetch a single user by ID' })
  async user(@Args('id', { type: () => String }) id: string): Promise<UserType | null> {
    return this.graphqlService.getUserById(id);
  }

  @Query(() => PaginatedUsersType, { description: 'Fetch paginated list of users' })
  async users(
    @Args('limit', { type: () => Int, nullable: true, defaultValue: 20 }) limit: number,
    @Args('offset', { type: () => Int, nullable: true, defaultValue: 0 }) offset: number,
  ): Promise<PaginatedUsersType> {
    return this.graphqlService.getUsers(limit, offset);
  }

  @Query(() => [CallType], { description: 'Fetch a list of calls' })
  async calls(
    @Args('limit', { type: () => Int, nullable: true, defaultValue: 20 }) limit: number,
  ): Promise<CallType[]> {
    return this.graphqlService.getCalls(limit);
  }
}
