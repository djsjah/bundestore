import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '@/database/prisma';

import { ICartControlData, CartStrategy } from '../types';

import { CartControlStrategy } from './strategy/control/cart.control.strategy';

@Injectable()
export class CartControl {
  constructor(private readonly prismaService: PrismaService) {}

  public async querySQLControl(
    cartControlData: ICartControlData,
    cartStrategy: CartStrategy,
  ): Promise<Prisma.PrismaPromise<unknown>> {
    const strategy = CartControlStrategy.createStrategy(cartStrategy);
    const result = await this.prismaService.$queryRaw(strategy.generateSQLControl(cartControlData));
    return result;
  }
}
