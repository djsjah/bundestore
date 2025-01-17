import { IsOptional, IsEnum } from 'class-validator';
import { ClothingSize } from '@prisma/client';

export class ProductClothingDTO {
  @IsOptional()
  @IsEnum(ClothingSize)
  public size: ClothingSize;
}
