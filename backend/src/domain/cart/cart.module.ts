import { Module } from '@nestjs/common';

import { PrismaModule } from '@/database/prisma';
import { JWTModule } from '@/utils';

import { UserModule, CustomerModule } from '../user';
import { OrderItemModule } from '../order-item';

import { CartService } from './service/cart.service';
import { CartFilter } from './service/cart.filter';
import { CartControl } from './service/cart.control';
import { CartAggregate } from './service/cart.aggregate';
import { CartController } from './cart.controller';

@Module({
  imports: [PrismaModule, JWTModule, UserModule, CustomerModule, OrderItemModule],
  controllers: [CartController],
  providers: [CartService, CartFilter, CartControl, CartAggregate],
  exports: [CartService, CartFilter],
})
export class CartModule {}
