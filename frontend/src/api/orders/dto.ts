import type { GetClothingSizeDTO, GetFootwearSizeDTO } from '../products';

export type GetOrderStatusDTO = 'CREATED' | 'REVIEW' | 'CONFIRMED' | 'REJECTED' | 'SHIPPED' | 'DELIVERED';

export type GetOrderItemDTO = {
  id: string;
  total: number;
  quantity: number;
  productId: string;
  size?: GetClothingSizeDTO | GetFootwearSizeDTO;
  stockQuantity: number;
};

type OrderDTO = {
  id: string;
  total: number;
  quantity: number;
  status: GetOrderStatusDTO;
  orderItems: Omit<GetOrderItemDTO, 'stockQuantity'>[];
  createdAt: string;
};

export type GetOrderDTO = OrderDTO;
