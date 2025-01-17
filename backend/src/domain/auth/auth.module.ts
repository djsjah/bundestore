import { Module } from '@nestjs/common';

import { PrismaModule } from '@/database/prisma';
import { CryptoModule, JWTModule, MailerModule } from '@/utils';

import { CustomerModule, UserModule } from '../user';
import { EmailVerifModule } from '../email-verification';

import { AuthEmailTemplate } from './service/auth.email.template';
import { AuthService } from './service/auth.service';
import { AuthController } from './auth.controller';

@Module({
  imports: [PrismaModule, CryptoModule, MailerModule, JWTModule, UserModule, CustomerModule, EmailVerifModule],
  controllers: [AuthController],
  providers: [AuthService, AuthEmailTemplate],
  exports: [AuthService],
})
export class AuthModule {}
