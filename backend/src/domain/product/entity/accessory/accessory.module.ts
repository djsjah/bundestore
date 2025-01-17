import { Module } from '@nestjs/common';

import { PrismaModule } from '@/database/prisma';
import { JWTModule } from '@/utils';
import { UserModule } from '@/domain/user';

import { AccessoryService } from './accessory.service';
import { AccessoryController } from './accessory.controller';

@Module({
  imports: [PrismaModule, JWTModule, UserModule],
  controllers: [AccessoryController],
  providers: [AccessoryService],
})
export class AccessoryModule {}
