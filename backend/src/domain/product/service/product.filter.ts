import { Injectable } from '@nestjs/common';

import { PrismaService, PrismaNumericOperator } from '@/database/prisma';

import { ProductPriceDTO, ProductClothingDTO, ProductFootwearDTO } from '../dto';
import { IProductFilter, ProductTypedef } from '../types';
import { ProductWhereCondition } from '../types/product.where.conditions.type';

import { ProductFilterStrategyFactory } from './strategy/product.filter.strategy';

@Injectable()
export class ProductFilter {
  constructor(private readonly prismaService: PrismaService) {}

  public async querySQLFilter(filterOptions: ProductWhereCondition): Promise<IProductFilter[]> {
    const whereConditions = this.createWhereConditions(filterOptions);
    const strategy = ProductFilterStrategyFactory.createStrategy(filterOptions);

    const result = (await this.prismaService.$queryRaw(
      strategy.generateSQLFilter(whereConditions),
    )) as IProductFilter[];

    return result;
  }

  public createWhereConditions(filterOptions: ProductWhereCondition): string {
    const whereConditions: string[] = [];

    Object.entries(filterOptions)
      .filter(([_, value]) => value !== undefined && value !== null)
      .forEach(([key, value]) => {
        switch (key) {
          case 'price':
            Object.entries(filterOptions.price as ProductPriceDTO)
              .filter(([_, value]) => value !== undefined && value !== null)
              .forEach(([key, value]) => {
                whereConditions.push(
                  `${ProductTypedef.p}.price ${
                    PrismaNumericOperator[key as unknown as keyof typeof PrismaNumericOperator]
                  } ${value}`,
                );
              });
            break;

          case 'clothing':
            Object.entries(filterOptions.clothing as ProductClothingDTO)
              .filter(([_, value]) => value !== undefined && value !== null)
              .forEach(([key, value]) => {
                whereConditions.push(`${ProductTypedef.c}."${key}" = ${value}`);
              });
            break;

          case 'footwear':
            Object.entries(filterOptions.footwear as ProductFootwearDTO)
              .filter(([_, value]) => value !== undefined && value !== null)
              .forEach(([key, value]) => {
                whereConditions.push(`${ProductTypedef.f}."${key}" = ${value}`);
              });
            break;

          default:
            whereConditions.push(`${ProductTypedef.p}."${key}" = '${value}'`);
        }
      });

    return whereConditions.join(' AND ');
  }
}
