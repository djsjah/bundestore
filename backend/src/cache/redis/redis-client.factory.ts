import { FactoryProvider } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient } from 'redis';

import { REDIS_CLIENT, RedisClient } from './types';

export const redisClientFactory: FactoryProvider<Promise<RedisClient>> = {
  provide: REDIS_CLIENT,
  inject: [ConfigService],
  useFactory: async (configService: ConfigService) => {
    const client = createClient({
      url: `redis://${configService.get<string>('REDIS_HOST')}:${configService.get<string>('REDIS_PORT')}`,
      password: configService.get<string>('REDIS_PASSWORD'),
    });

    try {
      await client.connect();
    }
    catch(err) {
      console.log(err);
    }

    return client;
  },
};
