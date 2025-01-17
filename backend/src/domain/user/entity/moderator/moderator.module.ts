import { Module } from '@nestjs/common';

import { PrismaModule } from '@/database/prisma';
import { JWTModule } from '@/utils';

import { AdminModule } from '../administrator';
import { UserModule } from '../../user.module';

import { ModeratorController } from './moderator.controller';
import { ModeratorService } from './moderator.service';

@Module({
  imports: [PrismaModule, JWTModule, AdminModule, UserModule],
  controllers: [ModeratorController],
  providers: [ModeratorService],
  exports: [ModeratorService],
})
export class ModeratorModule {}
