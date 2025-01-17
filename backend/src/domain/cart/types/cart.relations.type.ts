import { Cart, OrderItem } from '@prisma/client';

export type CartRelations = Cart & {
  orderItems?: Partial<OrderItem>[];
};
