import { Club, ProductCategory, AgeCategory, Gender, ClothingSize, FootwearSize } from '@prisma/client';

export interface IProductFilter {
  id: string;
  imageUrl: string;
  name: string;
  description: string;
  price: number;
  club: Club;
  category: ProductCategory;
  age: AgeCategory;
  gender: Gender;
  variants: IProductVariant[];
}

interface IProductVariant {
  size?: ClothingSize | FootwearSize;
  stockQuantity: number;
}
