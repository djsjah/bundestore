import { Module } from '@nestjs/common';

import { PrismaModule } from '@/database/prisma';
import { JWTModule } from '@/utils';
import { UserModule } from '@/domain/user';

import { ClothingService } from './clothing.service';
import { ClothingController } from './clothing.controller';

@Module({
  imports: [PrismaModule, JWTModule, UserModule],
  controllers: [ClothingController],
  providers: [ClothingService],
})
export class ClothingModule {}
