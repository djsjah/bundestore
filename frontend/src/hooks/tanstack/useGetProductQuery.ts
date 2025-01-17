import { useQuery } from '@tanstack/react-query';

import { getProduct } from '@/api';
import type { ApiError, GetProductDTO } from '@/api';

export const useGetProductQuery = (productId: string | undefined) =>
  useQuery<GetProductDTO, ApiError>({
    queryKey: ['products', productId],
    queryFn: () => getProduct(productId || ''),
    retry: 1,
    enabled: !!productId,
  });
