import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

import { APP_ROUTER } from '@/constants';
import { useGetUserPayloadQuery } from '@/hooks';
import { SignInForm } from '@/components';

export const SignInPage: React.FC = () => {
  const navigate = useNavigate();

  const { data: userData } = useGetUserPayloadQuery();

  useEffect(() => {
    if (userData) {
      navigate(APP_ROUTER.MAIN);
    }
  }, [navigate, userData]);

  if (userData) {
    return null;
  }

  return (
    <div className="max-w-md mx-auto p-8">
      <div className="mb-8">
        <h1 className="text-xl font-bold text-center mb-2">Sign In</h1>
        <p className="font-semibold text-center text-zinc-500">Welcome back! Ready to show your team spirit?</p>
      </div>
      <SignInForm />
    </div>
  );
};
