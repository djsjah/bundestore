import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { NodeModule } from '@/utils/node';

import { JWTConfig } from './jwt.config';
import { JWTProvider } from './jwt.provider';

@Module({
  imports: [ConfigModule, NodeModule],
  providers: [JWTConfig, JWTProvider],
  exports: [JWTProvider],
})
export class JWTModule {}
