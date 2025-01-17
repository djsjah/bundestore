import { Prisma } from '@prisma/client';

export interface IProductFilterStrategy {
  generateSQLFilter(whereConditions?: string): Prisma.Sql;
}
