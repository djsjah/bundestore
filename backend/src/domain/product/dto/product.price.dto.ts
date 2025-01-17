import { IsOptional, IsNumber } from 'class-validator';
import { Type } from 'class-transformer';

import { MutuallyExclusive } from '@/utils';

export class ProductPriceDTO {
  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  public gt?: number;

  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  public lt?: number;

  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  public gte?: number;

  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  public lte?: number;

  @IsOptional()
  @IsNumber()
  @MutuallyExclusive(['gt', 'lt', 'gte', 'lte'])
  @Type(() => Number)
  public equals?: number;
}
