import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, Cart } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

import { PrismaService } from '@/database/prisma';

@Injectable()
export class CartService {
  constructor(private readonly prismaService: PrismaService) { }

  public async findAll() {
    return;
  }

  public async getByUniqueParams(uniqueParams: Prisma.CartFindUniqueArgs): Promise<Cart> {
    const cart = await this.prismaService.cart.findUnique(uniqueParams);

    if (!cart) {
      throw new NotFoundException('Cart not found');
    }

    return cart;
  }

  public async update(cartUpdateData: Prisma.CartUpdateArgs): Promise<Cart> {
    try {
      const updatedCart = await this.prismaService.cart.update(cartUpdateData);
      return updatedCart;
    }
    catch (err) {
      if (err instanceof PrismaClientKnownRequestError && err.code === 'P2025') {
        throw new NotFoundException("Cart to update not found");
      }

      throw err;
    }
  }
}
