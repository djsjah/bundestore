import { Injectable } from '@nestjs/common';
import { PrismaClient, Order, Prisma } from '@prisma/client';
import { ITXClientDenyList } from '@prisma/client/runtime/library';

import { PrismaService } from '@/database/prisma';
import { CartRelations } from '@/domain/cart/types';

import { OrderCreateDTO } from '../dto';

@Injectable()
export class OrderAggregate {
  constructor(private readonly prismaService: PrismaService) {}

  public async applyCreateOrderTransaction(cart: CartRelations, orderCreateData: OrderCreateDTO): Promise<Order> {
    return await this.prismaService.$transaction(async (prisma: Omit<PrismaClient, ITXClientDenyList>) => {
      const order = await prisma.order.create({
        data: orderCreateData,
      });

      await prisma.cart.update({
        where: {
          id: cart.id,
        },
        data: {
          total: 0,
          quantity: 0,
        },
      });

      await prisma.$queryRaw`
        WITH order_items AS (
          SELECT
            oi.id AS "orderItemId",
            oi.quantity AS "orderItemQuantity",
            cl.id AS "clothingId",
            f.id AS "footwearId",
            a.id AS "accessoryId"
          FROM
            public."OrderItem" oi
          LEFT JOIN public."Clothing" cl ON oi."productId" = cl."productId" AND oi.size::text = cl.size::text
          LEFT JOIN public."Footwear" f ON oi."productId" = f."productId" AND oi.size::text = f.size::text
          LEFT JOIN public."Accessory" a ON oi."productId" = a."productId"
          WHERE oi."cartId" = '${Prisma.raw(cart.id)}'
        ),
        update_clothing AS (
          UPDATE public."Clothing"
          SET "stockQuantity" = "stockQuantity" - oi."orderItemQuantity"
          FROM order_items oi
          WHERE oi."clothingId" IS NOT NULL AND id = oi."clothingId"
        ),
        update_footwear AS (
          UPDATE public."Footwear"
          SET "stockQuantity" = "stockQuantity" - oi."orderItemQuantity"
          FROM order_items oi
          WHERE oi."footwearId" IS NOT NULL AND id = oi."footwearId"
        ),
        update_accessory AS (
          UPDATE public."Accessory"
          SET "stockQuantity" = "stockQuantity" - oi."orderItemQuantity"
          FROM order_items oi
          WHERE oi."accessoryId" IS NOT NULL AND id = oi."accessoryId"
        ),
        update_order_items AS (
          UPDATE public."OrderItem"
          SET
            "cartId" = NULL,
	          "orderId" = '${Prisma.raw(order.id)}'
          FROM order_items oi
          WHERE oi."orderItemId" IS NOT NULL AND id = oi."orderItemId"
        )
        SELECT 1;`;

      return order;
    });
  }
}
