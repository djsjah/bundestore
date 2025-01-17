import { useMutation, useQueryClient } from '@tanstack/react-query';

import { createOrder } from '@/api';
import type { ApiError } from '@/api';

export const useCreateOrderMutation = () => {
  const queryClient = useQueryClient();

  return useMutation<void, ApiError>({
    mutationKey: ['orders'],
    mutationFn: createOrder,
    retry: 3,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['orders'] });
      queryClient.refetchQueries({ queryKey: ['cart'] });
    },
  });
};
