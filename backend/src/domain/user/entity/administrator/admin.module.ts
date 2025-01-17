import { Module } from '@nestjs/common';

import { PrismaModule } from '@/database/prisma';

import { AdminService } from './admin.service';

@Module({
  imports: [PrismaModule],
  providers: [AdminService],
  exports: [AdminService],
})
export class AdminModule {}
