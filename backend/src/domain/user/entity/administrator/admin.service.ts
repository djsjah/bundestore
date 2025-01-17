import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, Administrator } from '@prisma/client';

import { PrismaService } from '@/database/prisma';

@Injectable()
export class AdminService {
  constructor(private readonly prismaService: PrismaService) {}

  public async getByUniqueParams(params: Prisma.AdministratorFindUniqueArgs): Promise<Administrator> {
    const admin = await this.prismaService.administrator.findUnique(params);

    if (!admin) {
      throw new NotFoundException('Administrator Not Found');
    }

    return admin;
  }
}
