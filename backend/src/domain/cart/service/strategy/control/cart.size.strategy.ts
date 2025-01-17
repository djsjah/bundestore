import { Prisma } from '@prisma/client';

import { ICartControl, ICartControlData } from '@/domain/cart/types';

export class CartSizeStrategy implements ICartControl {
  public generateSQLControl(cartControlData: ICartControlData): Prisma.Sql {
    const size = cartControlData.size as string;
    return Prisma.sql`
      SELECT
        p.id AS "productId",
        p.price AS "productPrice",
        cl.id AS "clothingId",
        f.id AS "footwearId"
      FROM
        public."Product" p
      LEFT JOIN
        public."Clothing" cl ON p.id = cl."productId" AND cl.size::text = '${Prisma.raw(size)}'
      LEFT JOIN
        public."Footwear" f ON p.id = f."productId" AND f.size::text = '${Prisma.raw(size)}'
      WHERE p.id = '${Prisma.raw(cartControlData.productId as string)}'
      GROUP BY
        p.id, p.category, cl.id, f.id
    `;
  }
}
