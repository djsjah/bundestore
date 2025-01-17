/* eslint-disable max-len */
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

import { RecoverPasswordForm } from '@/components';
import { APP_ROUTER } from '@/constants';
import { useGetUserPayloadQuery } from '@/hooks';

export const RecoverPasswordPage: React.FC = () => {
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
      <h1 className="text-xl font-bold text-center mb-8">Password Recover</h1>
      <div className="flex flex-col gap-2 mb-6 text-center text-sm text-zinc-500 border-2 border-zinc-900 rounded-lg py-3 px-5">
        <p>You will receive an email with a temporary password. You can use it to log in to the system.</p>
        <p>
          We highly recommend that you&nbsp;
          <span className="text-red-500">change your password immediately after logging in</span> for security purposes.
        </p>
      </div>
      <RecoverPasswordForm />
    </div>
  );
};
