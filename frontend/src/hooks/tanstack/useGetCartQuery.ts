import { useQuery } from '@tanstack/react-query';

import { getCart } from '@/api';
import type { ApiError, GetCartDTO } from '@/api';

export const useGetCartQuery = () => useQuery<GetCartDTO, ApiError>({ queryKey: ['cart'], queryFn: getCart, retry: 1 });
