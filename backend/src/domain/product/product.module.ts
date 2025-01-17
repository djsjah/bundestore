import { Module } from '@nestjs/common';

import { PrismaModule } from '@/database/prisma';
import { JWTModule } from '@/utils';

import { UserModule, ModeratorModule } from '../user';

import { ProductService } from './service/product.service';
import { ProductFilter } from './service/product.filter';
import { ProductController } from './product.controller';

@Module({
  imports: [PrismaModule, JWTModule, UserModule, ModeratorModule],
  controllers: [ProductController],
  providers: [ProductService, ProductFilter],
})
export class ProductModule {}
