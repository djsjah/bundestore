import { Injectable, Inject, OnModuleDestroy } from '@nestjs/common';

import { REDIS_CLIENT, RedisClient } from './types';

@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly ttl: number = 86400;

  constructor(@Inject(REDIS_CLIENT) private readonly redis: RedisClient) {}

  public ping(): Promise<string> {
    return this.redis.ping();
  }

  public async get(key: string): Promise<any> {
    return await this.redis.get(key);
  }

  public async set(key: string, value: any, ttl?: number): Promise<void> {
    await this.redis.set(key, value, {
      EX: ttl || this.ttl,
    });
  }

  public async delete(key: string): Promise<void> {
    await this.redis.del(key);
  }

  public onModuleDestroy(): void {
    this.redis.quit();
  }
}
