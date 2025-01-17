import { Module } from '@nestjs/common';

import { PrismaModule } from '@/database/prisma';
import { JWTModule } from '@/utils';
import { UserModule } from '@/domain/user';

import { FootwearService } from './footwear.service';
import { FootwearController } from './footwear.controller';

@Module({
  imports: [PrismaModule, JWTModule, UserModule],
  controllers: [FootwearController],
  providers: [FootwearService],
})
export class FootwearModule {}
