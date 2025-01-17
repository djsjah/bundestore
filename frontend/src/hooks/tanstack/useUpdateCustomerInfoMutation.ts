import { useMutation, useQueryClient } from '@tanstack/react-query';

import { updateCustomerInfo } from '@/api';
import type { ApiError, UpdateCustomerDTO } from '@/api';

export const useUpdateCustomerInfoMutation = () => {
  const queryClient = useQueryClient();

  return useMutation<void, ApiError, UpdateCustomerDTO>({
    mutationKey: ['customer'],
    mutationFn: updateCustomerInfo,
    retry: 3,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user'] });
    },
  });
};
