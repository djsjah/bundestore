import { useMutation, useQueryClient } from '@tanstack/react-query';

import { updateCartItemQuantity } from '@/api';
import type { ApiError } from '@/api';

export const useUpdateCartItemQuantityMutation = () => {
  const queryClient = useQueryClient();

  return useMutation<void, ApiError, { orderItemId: string; quantity: number }>({
    mutationKey: ['cart'],
    mutationFn: updateCartItemQuantity,
    retry: 3,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cart'] });
    },
  });
};
