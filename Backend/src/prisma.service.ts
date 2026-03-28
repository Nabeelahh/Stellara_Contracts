import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';

import { PrismaClient } from '@prisma/client';
import { getPrismaClientOptions } from '../prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  constructor() {
    super(getPrismaClientOptions());
  }

  async onModuleInit () {
    await this.$connect();
  }

  async onModuleDestroy () {
    await this.$disconnect();
  }
}
