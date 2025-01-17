import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, OrderItem } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

import { PrismaService } from '@/database/prisma';

@Injectable()
export class OrderItemService {
  constructor(private readonly prismaService: PrismaService) { }

  public async getByUniqueParams(uniqueParams: Prisma.OrderItemFindUniqueArgs): Promise<OrderItem> {
    const orderItem = await this.prismaService.orderItem.findUnique(uniqueParams);

    if (!orderItem) {
      throw new NotFoundException('Order Item Not Found');
    }

    return orderItem;
  }

  public async update(orderItemUpdateData: Prisma.OrderItemUpdateArgs): Promise<OrderItem> {
    try {
      const updatedOrderItem = await this.prismaService.orderItem.update(orderItemUpdateData);
      return updatedOrderItem;
    }
    catch (err) {
      if (err instanceof PrismaClientKnownRequestError && err.code === 'P2025') {
        throw new NotFoundException("Order item to update not found");
      }

      throw err;
    }
  }
}
