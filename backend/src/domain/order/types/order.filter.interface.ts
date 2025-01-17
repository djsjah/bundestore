import { OrderStatus } from '@prisma/client';

import { IOrderItem } from '@/domain/order-item/types/order-item.interface';

export interface IOrderFilter {
  id: string;
  total: number;
  quantity: number;
  status: OrderStatus;
  createdAt: Date;
  orderItems: IOrderItem[];
}
