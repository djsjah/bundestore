import { useMutation, useQueryClient } from '@tanstack/react-query';

import { updateUserInfo } from '@/api';
import type { ApiError, UpdateUserDTO } from '@/api';

export const useUpdateUserInfoMutation = () => {
  const queryClient = useQueryClient();

  return useMutation<void, ApiError, UpdateUserDTO>({
    mutationKey: ['user'],
    mutationFn: updateUserInfo,
    retry: 3,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user'] });
    },
  });
};
