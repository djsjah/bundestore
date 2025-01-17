/* eslint-disable max-len */
import { Prisma } from '@prisma/client';

import { ICartControl, ICartControlData } from '@/domain/cart/types';

export class CartQuantityStrategy implements ICartControl {
  public generateSQLControl(cartControlData: ICartControlData): Prisma.Sql {
    return Prisma.sql`
      SELECT
        oi.id AS "orderItemId",
        oi.total AS "orderItemTotal",
        oi.quantity AS "orderItemQuantity",
        p.price AS "productPrice",
        c.id AS "cartId",
        c.quantity AS "cartQuantity",
        c.total AS "cartTotal",
        COALESCE(cl."stockQuantity", f."stockQuantity", a."stockQuantity") AS "stockQuantity"
      FROM
        public."Cart" c
      INNER JOIN
        public."OrderItem" oi ON c.id = oi."cartId" AND oi.id = '${Prisma.raw(cartControlData.orderItemId as string)}'
      LEFT JOIN
        public."Product" p ON oi."productId" = p.id
      LEFT JOIN
        public."Clothing" cl ON p.id = cl."productId" AND oi.size::text = cl.size::text
      LEFT JOIN
        public."Footwear" f ON p.id = f."productId" AND oi.size::text = f.size::text
      LEFT JOIN
        public."Accessory" a ON p.id = a."productId"
      WHERE c."customerId" = '${Prisma.raw(cartControlData.customerId as string)}'
      GROUP BY
        oi.id, oi.total, oi.quantity, p.price, c.id, c.quantity, c.total, cl."stockQuantity", f."stockQuantity", a."stockQuantity"
    `;
  }
}
