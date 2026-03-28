import { INestApplication, Injectable, OnModuleInit } from '@nestjs/common'

import { PrismaClient } from '@prisma/client'
import { getPrismaClientOptions } from './client'

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  constructor() {
    super(getPrismaClientOptions())
  }

  async onModuleInit () {
    await this.$connect()
  }

  async enableShutdownHooks (app: INestApplication) {
    process.on('beforeExit', async () => {
      await app.close()
    })
  }
}