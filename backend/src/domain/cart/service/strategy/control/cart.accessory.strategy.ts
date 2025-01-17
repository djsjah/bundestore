import { Prisma } from '@prisma/client';

import { ICartControl, ICartControlData } from '@/domain/cart/types';

export class CartAccessoryStrategy implements ICartControl {
  public generateSQLControl(cartControlData: ICartControlData): Prisma.Sql {
    return Prisma.sql`
      SELECT
        p.id,
        p.price,
        p.category,
        a.id AS "accessoryId"
      FROM
        public."Product" p
      INNER JOIN
        public."Accessory" a ON p.id = a."productId"
      WHERE p.id = '${Prisma.raw(cartControlData.productId as string)}'
      GROUP BY
        p.id, p.category, a.id
    `;
  }
}
