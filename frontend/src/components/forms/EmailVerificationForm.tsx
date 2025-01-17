import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';

import { APP_ROUTER } from '@/constants';
import type { ApiError } from '@/api';
import { useAlert, useResendVerificationEmailQuery, useVerifyEmailMutation } from '@/hooks';
import { cn } from '@/utils';

import { Button, Input, Label } from '../shadcn';
import { ErrorMessage } from '../common';

type EmailVerificationFormProps = {
  email: string;
};

export const EmailVerificationForm: React.FC<EmailVerificationFormProps> = ({ email }) => {
  const navigate = useNavigate();

  const { openAlert } = useAlert();

  const [resendCooldown, setResendCooldown] = useState(0);

  const {
    register,
    handleSubmit,
    formState: { errors },
    setError,
  } = useForm<FormData>({
    resolver: zodResolver(validationSchema),
  });

  const { mutateAsync: verifyEmailMutation, isPending: isVerifyingEmail } = useVerifyEmailMutation();

  const { refetch: resendEmail, isFetching: isResendingEmail } = useResendVerificationEmailQuery(email);

  const handleResendEmail = useCallback(async () => {
    if (resendCooldown === 0) {
      const response = await resendEmail();

      if (response.error) {
        console.error('Error resending email: ', response.error);
        openAlert('Something went wrong!', 'destructive');

        return;
      }

      openAlert('Message successfully sent to your email!');

      setResendCooldown(30);
      const interval = setInterval(() => {
        setResendCooldown(prev => {
          if (prev <= 1) {
            clearInterval(interval);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }
  }, [openAlert, resendCooldown, resendEmail]);

  const onSubmit = useCallback(
    async (data: FormData) => {
      try {
        await verifyEmailMutation({ token: data.token });
        navigate(APP_ROUTER.MAIN);
      } catch (e) {
        console.error('Error verifying email: ', e);

        const apiError = e as ApiError;

        if (apiError.status === 401) {
          setError('token', { message: 'Token has been expired. Please request a new one.' });
        } else if (apiError.status === 404) {
          setError('token', { message: 'Invalid token' });
        } else {
          openAlert('Something went wrong!', 'destructive');
        }
      }
    },
    [navigate, openAlert, setError, verifyEmailMutation],
  );

  return (
    <form
      autoComplete="off"
      onSubmit={handleSubmit(onSubmit)}
      className={cn('flex flex-col gap-6', { ['pointer-events-none opacity-80']: isVerifyingEmail })}
    >
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <Label htmlFor="token">Token</Label>
          <div>
            <Input type="text" id="token" {...register('token')} />
            {errors.token && <ErrorMessage>{errors.token?.message}</ErrorMessage>}
          </div>
        </div>
      </div>
      <div className="flex flex-col gap-4 items-center">
        <Button type="submit" variant="secondary" className="w-32">
          Confirm
        </Button>
        <Button
          type="button"
          variant="ghost"
          className="w-32"
          disabled={isResendingEmail || resendCooldown > 0}
          onClick={handleResendEmail}
        >
          {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : 'Resend Email'}
        </Button>
      </div>
    </form>
  );
};

const validationSchema = z.object({
  token: z.string().min(6, 'Token must be at least 6 characters long'),
});

type FormData = z.infer<typeof validationSchema>;
