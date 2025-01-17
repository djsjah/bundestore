import { useQuery } from '@tanstack/react-query';

import { getOrders } from '@/api';
import type { ApiError, GetOrderDTO } from '@/api';

export const useGetOrdersQuery = () =>
  useQuery<GetOrderDTO[], ApiError>({ queryKey: ['orders'], queryFn: getOrders, retry: 3 });
