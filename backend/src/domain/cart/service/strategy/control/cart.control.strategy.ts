import { ICartControl, CartStrategy } from '@/domain/cart/types';

import { CartAccessoryStrategy } from './cart.accessory.strategy';
import { CartSizeStrategy } from './cart.size.strategy';
import { CartQuantityStrategy } from './cart.quantity.strategy';

export class CartControlStrategy {
  static createStrategy(cartStrategy: CartStrategy): ICartControl {
    switch (cartStrategy) {
      case CartStrategy.accessory:
        return new CartAccessoryStrategy();

      case CartStrategy.size:
        return new CartSizeStrategy();

      case CartStrategy.quantity:
        return new CartQuantityStrategy();
    }
  }
}
