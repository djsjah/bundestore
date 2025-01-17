import type { GetOrderItemDTO } from '../orders';
import type { GetClothingSizeDTO, GetFootwearSizeDTO } from '../products';

type CartDTO = {
  id: string;
  total: number;
  quantity: number;
  orderItems: GetOrderItemDTO[];
};

export type GetCartDTO = CartDTO;

export type AddProductToCartDTO = {
  productId: string;
  size?: GetClothingSizeDTO | GetFootwearSizeDTO;
};
