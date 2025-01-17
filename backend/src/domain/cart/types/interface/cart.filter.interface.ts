import { IOrderItem } from '@/domain/order-item/types/order-item.interface';

export interface ICartFilter {
  id: string;
  total: number;
  quantity: number;
  orderItems: (IOrderItem & {
    stockQuantity: number;
  })[];
}
