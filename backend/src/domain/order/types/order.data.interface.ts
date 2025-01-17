import { Prisma, OrderItem, OrderStatus } from '@prisma/client';

export interface IOrderData {
  orderId: string;
  total: Prisma.Decimal;
  quantity: number;
  status: OrderStatus;
  createdAt: Date;
  userId: string;
  customerId: string;
  customerFullName: string;
  customerEmail: string;
  customerPhoneNumber: string;
  customerBirthDate: Date;
  orderItems?: Partial<OrderItem>[];
}
