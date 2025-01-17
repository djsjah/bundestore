import { Module } from '@nestjs/common';

import { PrismaModule } from '@/database/prisma';
import { JWTModule } from '@/utils';

import { UserModule } from '../user';

import { EmailVerifService } from './email-verification.service';
import { EmailVerifController } from './email-verification.controller';

@Module({
  imports: [PrismaModule, JWTModule, UserModule],
  controllers: [EmailVerifController],
  providers: [EmailVerifService],
  exports: [EmailVerifService],
})
export class EmailVerifModule {}
