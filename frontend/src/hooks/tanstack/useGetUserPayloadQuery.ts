import { useQuery } from '@tanstack/react-query';

import { getUserPayload } from '@/api';
import type { ApiError, GetUserPayloadDTO } from '@/api';

export const useGetUserPayloadQuery = () =>
  useQuery<GetUserPayloadDTO, ApiError>({
    queryKey: ['user'],
    queryFn: getUserPayload,
    retry: 1,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  });
