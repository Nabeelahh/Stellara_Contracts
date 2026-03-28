import { ObjectType, Field, ID, Int, Float } from '@nestjs/graphql';

@ObjectType()
export class UserType {
  @Field(() => ID)
  id: string;

  @Field()
  walletAddress: string;

  @Field(() => Int)
  reputationScore: number;

  @Field()
  createdAt: Date;
}

@ObjectType()
export class CallType {
  @Field(() => ID)
  id: string;

  @Field()
  title: string;

  @Field({ nullable: true })
  outcome: string;

  @Field()
  createdAt: Date;
}

@ObjectType()
export class StakeLedgerType {
  @Field(() => ID)
  id: string;

  @Field(() => Float)
  amount: number;

  @Field(() => Float, { nullable: true })
  profitLoss: number;

  @Field({ nullable: true })
  resolutionStatus: string;

  @Field()
  createdAt: Date;
}

@ObjectType()
export class PaginatedUsersType {
  @Field(() => [UserType])
  items: UserType[];

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  limit: number;

  @Field(() => Int)
  offset: number;
}
