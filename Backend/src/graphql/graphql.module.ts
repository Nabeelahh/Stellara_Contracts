import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { join } from 'path';
import { GraphqlResolver } from './graphql.resolver';
import { GraphqlService } from './graphql.service';
import { GraphqlComplexityGuard } from './graphql.complexity.guard';
import { PrismaService } from '../prisma.service';

@Module({
  imports: [
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      // Auto-generate schema file from decorators
      autoSchemaFile: join(process.cwd(), 'src/graphql/schema.gql'),
      sortSchema: true,
      playground: true,
      introspection: true,
      subscriptions: {
        'graphql-ws': true,
        'subscriptions-transport-ws': false,
      },
      context: ({ req, res }) => ({ req, res }),
    }),
  ],
  providers: [GraphqlResolver, GraphqlService, GraphqlComplexityGuard, PrismaService],
  exports: [GraphqlService],
})
export class GraphqlModule {}
