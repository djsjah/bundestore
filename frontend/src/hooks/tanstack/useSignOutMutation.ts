import { useMutation, useQueryClient } from '@tanstack/react-query';

import { signOut } from '@/api';
import type { ApiError } from '@/api';

export const useSignOutMutation = () => {
  const queryClient = useQueryClient();

  return useMutation<void, ApiError>({
    mutationKey: ['signOut'],
    mutationFn: signOut,
    retry: 1,
    onSuccess: () => {
      queryClient.resetQueries({ queryKey: ['user'] });
      queryClient.resetQueries({ queryKey: ['cart'] });
      queryClient.resetQueries({ queryKey: ['orders'] });
    },
  });
};
