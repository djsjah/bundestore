import { useQuery } from '@tanstack/react-query';

import { recoverPassword } from '@/api';
import type { ApiError } from '@/api';

export const useRecoverPasswordQuery = (email: string) =>
  useQuery<string, ApiError>({
    queryKey: ['recoverPassword'],
    queryFn: () => recoverPassword(email),
    retry: 3,
    enabled: false,
  });
