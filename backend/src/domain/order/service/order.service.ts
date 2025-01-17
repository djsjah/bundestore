import { Injectable } from '@nestjs/common';
import { Prisma, Order } from '@prisma/client';

import { PrismaService } from '@/database/prisma';

import { OrderCreateDTO } from '../dto';

@Injectable()
export class OrderService {
  constructor(private readonly prismaService: PrismaService) {}

  public async getAll(params: Prisma.OrderFindManyArgs): Promise<Order[]> {
    const orders = await this.prismaService.order.findMany(params);
    return orders;
  }

  public async create(orderCreateData: OrderCreateDTO): Promise<Order> {
    const newOrder = await this.prismaService.order.create({
      data: orderCreateData,
    });

    return newOrder;
  }
}
