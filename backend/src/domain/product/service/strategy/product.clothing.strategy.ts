import { Prisma } from '@prisma/client';

import { IProductFilterStrategy } from '../../types';

export class ProductClothingStrategy implements IProductFilterStrategy {
  public generateSQLFilter(whereConditions?: string): Prisma.Sql {
    whereConditions = whereConditions ? 'WHERE ' + whereConditions : '';
    return Prisma.sql`
      SELECT
        p.id,
        p.name,
        p.description,
        CAST(p.price AS FLOAT) AS price,
        p."imageUrl",
        p.club,
        p.category,
        p.age,
        p.gender,
        JSON_AGG(JSON_BUILD_OBJECT(
          'clothingId', rel_mod.id,
          'size', rel_mod.size,
          'stockQuantity', rel_mod."stockQuantity"
        )) AS variants
      FROM
        public."Product" p
      INNER JOIN
        public."Clothing" rel_mod ON p.id = rel_mod."productId"
      ${Prisma.raw(whereConditions)}
      GROUP BY
        p.id, p.name, p.description, CAST(p.price AS FLOAT), p."imageUrl", p.club, p.category, p.age, p.gender
    `;
  }
}
