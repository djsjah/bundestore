import { Navigate, useLocation } from 'react-router-dom';

import { APP_ROUTER } from '@/constants';
import { useGetUserPayloadQuery } from '@/hooks';

export const ProtectedRoute: React.FC<React.PropsWithChildren> = ({ children }) => {
  const location = useLocation();

  const { error: errorUser } = useGetUserPayloadQuery();

  if (errorUser && errorUser.status === 401) {
    return <Navigate to={APP_ROUTER.SIGN_IN} state={{ from: location }} replace />;
  }

  return children;
};
