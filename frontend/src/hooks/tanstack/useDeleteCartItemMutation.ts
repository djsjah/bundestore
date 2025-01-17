import { useMutation, useQueryClient } from '@tanstack/react-query';

import { deleteCartItem } from '@/api';
import type { ApiError } from '@/api';

export const useDeleteCartItemMutation = () => {
  const queryClient = useQueryClient();

  return useMutation<void, ApiError, string>({
    mutationKey: ['cart'],
    mutationFn: deleteCartItem,
    retry: 3,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cart'] });
    },
  });
};
