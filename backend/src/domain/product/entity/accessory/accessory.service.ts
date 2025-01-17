import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, Accessory } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

import { PrismaService } from '@/database/prisma';

import { AccessoryCreateDTO } from './dto/accessory.create.dto';

@Injectable()
export class AccessoryService {
  constructor(private readonly prismaService: PrismaService) { }

  public async create(accessoryCreateData: AccessoryCreateDTO): Promise<Accessory> {
    const newAccessory = await this.prismaService.accessory.create({
      data: accessoryCreateData,
    });

    return newAccessory;
  }

  public async update(accessoryUpdateData: Prisma.AccessoryUpdateArgs): Promise<Accessory> {
    try {
      const updatedAccessory = await this.prismaService.accessory.update(accessoryUpdateData);
      return updatedAccessory;
    }
    catch(err) {
      if (err instanceof PrismaClientKnownRequestError && err.code === 'P2025') {
        throw new NotFoundException("Accessory to update not found");
      }

      throw err;
    }
  }
}
