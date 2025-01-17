import { useMutation, useQueryClient } from '@tanstack/react-query';

import { signIn } from '@/api';
import type { ApiError, SignInDTO } from '@/api';

export const useSignInMutation = () => {
  const queryClient = useQueryClient();

  return useMutation<void, ApiError, SignInDTO>({
    mutationKey: ['signIn'],
    mutationFn: signIn,
    retry: 1,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user'] });
    },
  });
};
