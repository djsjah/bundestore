import { Module } from '@nestjs/common';

import { JWTModule } from '@/utils';
import { PrismaModule } from '@/database/prisma';
import { UserModule } from '@/domain/user';

import { OrderItemService } from './order-item.service';

@Module({
  imports: [PrismaModule, JWTModule, UserModule],
  providers: [OrderItemService],
  exports: [OrderItemService],
})
export class OrderItemModule {}
