import { Module, forwardRef } from '@nestjs/common';

import { PrismaModule } from '@/database/prisma';
import { JWTModule } from '@/utils';
import { AuthModule } from '@/domain/auth';

import { UserModule } from '../../user.module';

import { CustomerController } from './customer.controller';
import { CustomerService } from './customer.service';

@Module({
  imports: [PrismaModule, forwardRef(() => AuthModule), JWTModule, UserModule],
  controllers: [CustomerController],
  providers: [CustomerService],
  exports: [CustomerService],
})
export class CustomerModule {}
