import { useQuery } from '@tanstack/react-query';

import { getProduct } from '@/api';
import type { ApiError, GetProductDTO } from '@/api';

export const useGetCartProductsQuery = (productIds: string[]) => {
  const getProducts = async () => {
    const products = await Promise.all(productIds.map(productId => getProduct(productId)));
    return products;
  };

  return useQuery<GetProductDTO[], ApiError>({
    queryKey: ['products', ...productIds],
    queryFn: getProducts,
    retry: 3,
    enabled: productIds.length > 0,
  });
};
