import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, Clothing } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

import { PrismaService } from '@/database/prisma';

import { ClothingCreateDTO } from './dto/clothing.create.dto';

@Injectable()
export class ClothingService {
  constructor(private readonly prismaService: PrismaService) { }

  public async create(clothingCreateData: ClothingCreateDTO): Promise<Clothing> {
    const newClothing = await this.prismaService.clothing.create({
      data: clothingCreateData,
    });

    return newClothing;
  }

  public async update(clothingUpdateData: Prisma.ClothingUpdateArgs): Promise<Clothing> {
    try {
      const updatedClothing = await this.prismaService.clothing.update(clothingUpdateData);
      return updatedClothing;
    }
    catch (err) {
      if (err instanceof PrismaClientKnownRequestError && err.code === 'P2025') {
        throw new NotFoundException("Clothing to update not found");
      }

      throw err;
    }
  }
}
