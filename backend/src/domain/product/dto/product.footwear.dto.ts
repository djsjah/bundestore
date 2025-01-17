import { IsOptional, IsEnum } from 'class-validator';
import { FootwearSize } from '@prisma/client';

export class ProductFootwearDTO {
  @IsOptional()
  @IsEnum(FootwearSize)
  public size: FootwearSize;
}
