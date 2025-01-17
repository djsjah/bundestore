import { useQuery } from '@tanstack/react-query';

import { resendVerificationEmail } from '@/api';
import type { ApiError } from '@/api';

export const useResendVerificationEmailQuery = (email: string) =>
  useQuery<string, ApiError>({
    queryKey: ['resendVerificationEmail'],
    queryFn: () => resendVerificationEmail(email),
    retry: 3,
    enabled: false,
  });
