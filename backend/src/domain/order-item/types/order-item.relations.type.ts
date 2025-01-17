import { OrderItem, Product } from '@prisma/client';

export type OrderItemRelations = OrderItem & {
  product?: Product;
};
