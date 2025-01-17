import { Prisma } from '@prisma/client';

import { IProductFilterStrategy } from '../../types';

export class ProductStandardStrategy implements IProductFilterStrategy {
  public generateSQLFilter(whereConditions?: string): Prisma.Sql {
    whereConditions = whereConditions ? 'AND ' + whereConditions : '';
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
        COALESCE(
          JSON_AGG(
            CASE
              WHEN c.id IS NOT NULL THEN JSON_BUILD_OBJECT(
                'clothingId', c.id,
                'size', c.size,
                'stockQuantity', c."stockQuantity"
              )
              WHEN f.id IS NOT NULL THEN JSON_BUILD_OBJECT(
                'footwearId', f.id,
                'size', f.size,
                'stockQuantity', f."stockQuantity"
              )
              WHEN a.id IS NOT NULL THEN JSON_BUILD_OBJECT(
                'accessoryId', a.id,
                'stockQuantity', a."stockQuantity"
              )
              ELSE NULL
            END
          ),
        '[]'::json) AS variants
      FROM
        public."Product" p
      LEFT JOIN
        public."Clothing" c ON p.id = c."productId"
      LEFT JOIN
        public."Footwear" f ON p.id = f."productId"
      LEFT JOIN
        public."Accessory" a ON p.id = a."productId"
      WHERE (c.id IS NOT NULL OR f.id IS NOT NULL OR a.id IS NOT NULL) ${Prisma.raw(whereConditions)}
      GROUP BY
        p.id, p.name, p.description, CAST(p.price AS FLOAT), p."imageUrl", p.club, p.category, p.age, p.gender
    `;
  }
}
