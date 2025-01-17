import { ProductCategory } from '@prisma/client';

import { ProductWhereCondition } from '../../types/product.where.conditions.type';
import { IProductFilterStrategy } from '../../types';

import { ProductStandardStrategy } from './product.standard.strategy';
import { ProductClothingStrategy } from './product.clothing.strategy';
import { ProductFootwearStrategy } from './product.footwear.strategy';
import { ProductAccessoryStrategy } from './product.accessory.strategy';

export class ProductFilterStrategyFactory {
  static createStrategy(filterOptions: ProductWhereCondition): IProductFilterStrategy {
    switch (filterOptions.category) {
      case ProductCategory.UPPER_CLOTHING:
      case ProductCategory.LOWER_CLOTHING:
        return new ProductClothingStrategy();

      case ProductCategory.FOOTWEAR:
        return new ProductFootwearStrategy();

      case ProductCategory.ACCESSORIES:
        return new ProductAccessoryStrategy();

      default:
        if (filterOptions.clothing) {
          return new ProductClothingStrategy();
        }

        if (filterOptions.footwear) {
          return new ProductFootwearStrategy();
        }

        return new ProductStandardStrategy();
    }
  }
}
