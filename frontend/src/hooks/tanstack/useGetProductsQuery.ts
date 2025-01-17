import { useQuery } from '@tanstack/react-query';

import { getProducts } from '@/api';
import type { ApiError, GetProductDTO, GetProductsQueryParams } from '@/api';

export const useGetProductsQuery = (filters: GetProductsQueryParams) => {
  return useQuery<GetProductDTO[], ApiError>({
    queryKey: ['products', filters],
    queryFn: () => getProducts(filters),
    retry: 1,
  });
};
