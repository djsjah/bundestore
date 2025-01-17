import { useQuery } from '@tanstack/react-query';

import { getProduct } from '@/api';
import type { ApiError, GetProductDTO } from '@/api';

export const useGetProductsByIdsQuery = (productIds: string[]) => {
  return useQuery<GetProductDTO[], ApiError>({
    queryKey: ['products', ...productIds],
    queryFn: async () => {
      const products = await Promise.all(productIds.map(id => getProduct(id)));
      return products;
    },
    retry: 1,
    enabled: productIds.length > 0,
  });
};
