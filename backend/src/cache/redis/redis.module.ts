import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { RedisService } from './redis.service';
import { redisClientFactory } from './redis-client.factory';

@Module({
  imports: [ConfigModule],
  providers: [RedisService, redisClientFactory],
  exports: [RedisService],
})
export class RedisModule {}
