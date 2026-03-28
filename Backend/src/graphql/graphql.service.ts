import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import DataLoader from 'dataloader';

@Injectable()
export class GraphqlService {
  private userLoader: DataLoader<string, any>;

  constructor(private readonly prisma: PrismaService) {
    this.userLoader = new DataLoader<string, any>(async (ids: readonly string[]) => {
      const users = await this.prisma.user.findMany({
        where: { id: { in: ids as string[] } },
      });

      const userMap = new Map(users.map((u) => [u.id, u]));
      return ids.map((id) => userMap.get(id) ?? null);
    });
  }

  async getUserById(id: string) {
    return this.userLoader.load(id);
  }

  async getUsers(limit = 20, offset = 0) {
    const [items, total] = await Promise.all([
      this.prisma.user.findMany({
        take: limit,
        skip: offset,
        orderBy: { createdAt: 'desc' },
      }),
      this.prisma.user.count(),
    ]);

    return { items, total, limit, offset };
  }

  async getCalls(limit = 20) {
    return this.prisma.call.findMany({
      take: limit,
      orderBy: { createdAt: 'desc' },
    });
  }
}
