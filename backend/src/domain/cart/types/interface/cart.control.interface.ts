import { Prisma, ProductCategory, ClothingSize, FootwearSize } from '@prisma/client';

export interface ICartControlData {
  size?: ClothingSize | FootwearSize;
  customerId?: string;
  productId?: string;
  orderItemId?: string;
}

export interface ICartControl {
  generateSQLControl(cartControlData: ICartControlData): Prisma.Sql;
}

export interface ICartAccessory {
  id: string;
  price: Prisma.Decimal;
  category: ProductCategory;
  accessoryId: string;
}

export interface ICartQuantity {
  orderItemId: string;
  orderItemTotal: Prisma.Decimal;
  orderItemQuantity: number;
  productPrice: Prisma.Decimal;
  cartId: string;
  cartQuantity: number;
  cartTotal: number;
  stockQuantity: number;
}

export interface ICartSize {
  productId: string;
  productPrice: Prisma.Decimal;
  clothingId: string;
  footwearId: string;
}
