import { useMutation } from '@tanstack/react-query';

import { signUp } from '@/api';
import type { ApiError, SignUpDTO } from '@/api';

export const useSignUpMutation = () =>
  useMutation<void, ApiError, SignUpDTO>({
    mutationKey: ['signUp'],
    mutationFn: signUp,
    retry: 1,
  });
