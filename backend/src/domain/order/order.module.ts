import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { PrismaModule } from '@/database/prisma';
import { JWTModule, MailerModule } from '@/utils';

import { UserModule } from '../user/user.module';
import { CustomerModule } from '../user/entity/customer/customer.module';
import { CartModule } from '../cart/cart.module';

import { OrderService } from './service/order.service';
import { OrderFilter } from './service/order.filter';
import { OrderAggregate } from './service/order.aggregate';
import { OrderEmailTemplate } from './service/order.email.template';
import { OrderController } from './order.controller';

@Module({
  imports: [PrismaModule, ConfigModule, JWTModule, MailerModule, UserModule, CustomerModule, CartModule],
  controllers: [OrderController],
  providers: [OrderService, OrderFilter, OrderAggregate, OrderEmailTemplate],
  exports: [OrderService],
})
export class OrderModule {}
