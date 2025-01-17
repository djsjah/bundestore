import { ClothingSize, FootwearSize } from '@prisma/client';

export interface IOrderItem {
  id: string;
  total: number;
  quantity: number;
  size: ClothingSize | FootwearSize | null;
  productId: string;
}
