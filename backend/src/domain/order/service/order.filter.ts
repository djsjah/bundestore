import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '@/database/prisma';
import { IOrderItem } from '@/domain/order-item/types/order-item.interface';

@Injectable()
export class OrderFilter {
  constructor(private readonly prismaService: PrismaService) {}

  private readonly orderInclude: Prisma.OrderInclude = {
    orderItems: true,
  };

  public async querySQLFilter(customerId: string): Promise<IOrderItem[]> {
    const result = (await this.prismaService.$queryRaw`
        SELECT
          o.id,
          CAST(o.total AS FLOAT) AS total,
          o.quantity,
          o.status,
          o."createdAt",
          COALESCE(
            JSON_AGG(
              JSON_BUILD_OBJECT(
                'id', oi.id,
                'total', CAST(oi.total AS FLOAT),
                'quantity', oi.quantity,
                'size', oi.size,
                'productId', oi."productId"
              )
            ) FILTER (WHERE oi.id IS NOT NULL),
            '[]'::json) AS "orderItems"
        FROM
          public."Order" o
        LEFT JOIN
          public."OrderItem" oi ON o.id = oi."orderId"
        WHERE o."customerId" = '${Prisma.raw(customerId)}'
        GROUP BY
          o.id, CAST(o.total AS FLOAT), o.quantity, o.status, o."createdAt"
        ORDER BY
          o."createdAt" ASC
      `) as IOrderItem[];

    return result;
  }

  public getOrderInclude(): Prisma.OrderInclude {
    return this.orderInclude;
  }
}
