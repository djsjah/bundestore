import { createClient } from 'redis';

export type RedisClient = ReturnType<typeof createClient>;
export const REDIS_CLIENT = process.env.REDIS_CLIENT as string;
