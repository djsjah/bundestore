import { useMutation, useQueryClient } from '@tanstack/react-query';

import { verifyEmail } from '@/api';
import type { ApiError, EmailVerificationDTO } from '@/api';

export const useVerifyEmailMutation = () => {
  const queryClient = useQueryClient();

  return useMutation<void, ApiError, EmailVerificationDTO>({
    mutationKey: ['emailVerification'],
    mutationFn: verifyEmail,
    retry: 3,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user'] });
    },
  });
};
