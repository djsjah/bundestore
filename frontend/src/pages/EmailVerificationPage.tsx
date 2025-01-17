/* eslint-disable max-len */
import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { APP_ROUTER } from '@/constants';
import { EmailVerificationForm } from '@/components';

export const EmailVerificationPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const email = location.state?.email;

  useEffect(() => {
    if (!email) {
      navigate(APP_ROUTER.MAIN);
    }
  }, [email, navigate]);

  if (!email) {
    return null;
  }

  return (
    <div className="max-w-lg mx-auto p-8">
      <div className="mb-8">
        <h1 className="text-xl font-bold text-center mb-2">Email Confirmation</h1>
        <p className="font-semibold text-center text-zinc-500">
          Please enter the confirmation token sent to your email.
        </p>
      </div>
      <div className="flex flex-col gap-2 mb-6 text-center text-sm text-zinc-500 border-2 border-zinc-900 rounded-lg py-3 px-5">
        <p>
          You must verify your account to start making purchases. If you do not verify your email,&nbsp;
          <span className="text-red-500">your account will be deleted</span>.
        </p>
        <p>In order to start shopping, you will need to register again.</p>
      </div>
      <EmailVerificationForm email={email} />
    </div>
  );
};
