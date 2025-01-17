import { IsOptional, IsEnum, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { ProductCategory, AgeCategory, Gender, Club } from '@prisma/client';

import { MutuallyExclusive } from '@/utils';

import { ProductPriceDTO } from './product.price.dto';
import { ProductClothingDTO } from './product.clothing.dto';
import { ProductFootwearDTO } from './product.footwear.dto';

export class ProductFilterDTO {
  @IsOptional()
  @IsEnum(ProductCategory)
  public category?: ProductCategory;

  @IsOptional()
  @IsEnum(AgeCategory)
  public age?: AgeCategory;

  @IsOptional()
  @IsEnum(Gender)
  public gender?: Gender;

  @IsOptional()
  @IsEnum(Club)
  public club?: Club;

  @IsOptional()
  @ValidateNested()
  @Type(() => ProductPriceDTO)
  public price?: ProductPriceDTO;

  @IsOptional()
  @ValidateNested()
  @Type(() => ProductClothingDTO)
  public clothing?: ProductClothingDTO;

  @IsOptional()
  @ValidateNested()
  @Type(() => ProductFootwearDTO)
  @MutuallyExclusive(['clothing'])
  public footwear?: ProductFootwearDTO;
}
