import { Injectable } from '@nestjs/common';
import { PrismaClient, Cart, OrderItem, Prisma } from '@prisma/client';
import { ITXClientDenyList } from '@prisma/client/runtime/library';

import { PrismaService } from '@/database/prisma';
import { OrderItemUpdateDTO } from '@/domain/order-item';

import { ICartQuantity } from '../types';

@Injectable()
export class CartAggregate {
  constructor(private readonly prismaService: PrismaService) {}

  public async applyAddItemToCartTransaction(
    cart: Cart,
    orderItemCreateData: Prisma.OrderItemUncheckedCreateInput,
  ): Promise<void> {
    await this.prismaService.$transaction(async (prisma: Omit<PrismaClient, ITXClientDenyList>) => {
      const orderItem = await prisma.orderItem.create({
        data: {
          ...orderItemCreateData,
          cartId: cart.id,
        },
      });

      await prisma.cart.update({
        where: {
          id: cart.id,
        },
        data: {
          total: Number(cart.total) + Number(orderItem.total),
          quantity: cart.quantity + orderItem.quantity,
        },
      });
    });
  }

  public async applyUpdateItemInCartTransaction(
    transactionData: ICartQuantity,
    orderItemUpdateData: OrderItemUpdateDTO,
  ): Promise<void> {
    await this.prismaService.$transaction(async (prisma: Omit<PrismaClient, ITXClientDenyList>) => {
      const updatedOrderItem = await prisma.orderItem.update({
        where: {
          id: transactionData.orderItemId,
        },
        data: {
          ...orderItemUpdateData,
          total: orderItemUpdateData.quantity * Number(transactionData.productPrice),
        },
      });

      const newCartTotal: number =
        Number(transactionData.cartTotal) - Number(transactionData.orderItemTotal) + Number(updatedOrderItem.total);
      const newCartQuantity: number =
        transactionData.cartQuantity - transactionData.orderItemQuantity + updatedOrderItem.quantity;

      await prisma.cart.update({
        where: {
          id: transactionData.cartId,
        },
        data: {
          total: newCartTotal,
          quantity: newCartQuantity,
        },
      });
    });
  }

  public async applyRemoveItemFromCartTransaction(orderItem: OrderItem, cart: Cart): Promise<void> {
    await this.prismaService.$transaction(async (prisma: Omit<PrismaClient, ITXClientDenyList>) => {
      const deletedOrderItem = await prisma.orderItem.delete({
        where: {
          id: orderItem.id,
        },
        include: {
          product: true,
        },
      });

      await prisma.cart.update({
        where: {
          id: cart.id,
        },
        data: {
          total: Number(cart.total) - Number(deletedOrderItem.total),
          quantity: cart.quantity - orderItem.quantity,
        },
      });
    });
  }
}
