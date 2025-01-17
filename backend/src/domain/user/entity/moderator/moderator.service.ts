import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, Moderator } from '@prisma/client';

import { PrismaService } from '@/database/prisma';

import { ModeratorCreateDTO } from './dto';

@Injectable()
export class ModeratorService {
  constructor(private readonly prismaService: PrismaService) {}

  public async getMany(params: Prisma.ModeratorFindManyArgs): Promise<Moderator[]> {
    const moderators = await this.prismaService.moderator.findMany(params);
    return moderators;
  }

  public async getByUniqueParams(params: Prisma.ModeratorFindUniqueArgs): Promise<Moderator> {
    const moderator = await this.prismaService.moderator.findUnique(params);

    if (!moderator) {
      throw new NotFoundException('Moderator Not Found');
    }

    return moderator;
  }

  public async create(moderatorCreateData: ModeratorCreateDTO): Promise<Moderator> {
    const newModerator = await this.prismaService.moderator.create({
      data: moderatorCreateData,
    });

    return newModerator;
  }
}
