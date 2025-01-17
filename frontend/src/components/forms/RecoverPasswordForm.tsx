import { useCallback, useState } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';

import type { ApiError } from '@/api';
import { useAlert, useRecoverPasswordQuery } from '@/hooks';
import { cn } from '@/utils';

import { Button, Input, Label } from '../shadcn';
import { ErrorMessage } from '../common';

export const RecoverPasswordForm: React.FC = () => {
  const { openAlert } = useAlert();

  const [resendCooldown, setResendCooldown] = useState(0);

  const {
    register,
    watch,
    handleSubmit,
    formState: { errors },
    setError,
  } = useForm<FormData>({
    resolver: zodResolver(validationSchema),
    mode: 'all',
  });

  const email = watch('email');

  const { refetch: recoverPassword, isFetching: isRecoveringPassword } = useRecoverPasswordQuery(email);

  const onSubmit = useCallback(async () => {
    if (resendCooldown === 0) {
      const response = await recoverPassword();

      if (response.error) {
        const apiError = response.error as ApiError;

        console.error('Error recovering password: ', apiError);

        if (apiError.status === 404) {
          setError('email', { message: 'Account not found' });
        } else {
          openAlert('Something went wrong!', 'destructive');
        }

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
  }, [openAlert, recoverPassword, resendCooldown, setError]);

  return (
    <form
      autoComplete="off"
      onSubmit={handleSubmit(onSubmit)}
      className={cn('flex flex-col gap-6', { ['pointer-events-none opacity-80']: isRecoveringPassword })}
    >
      <div className="flex flex-col gap-2">
        <Label htmlFor="email">Email</Label>
        <div>
          <Input type="text" id="email" {...register('email')} />
          {errors.email && <ErrorMessage>{errors.email?.message}</ErrorMessage>}
        </div>
      </div>
      <div className="flex justify-center">
        <Button type="submit" variant="secondary" disabled={resendCooldown > 0} className="w-32">
          {resendCooldown > 0 ? `Try again in ${resendCooldown}s` : 'Recover Password'}
        </Button>
      </div>
    </form>
  );
};

const validationSchema = z.object({
  email: z.string().min(1, 'Email is required').email('Invalid email address'),
});

type FormData = z.infer<typeof validationSchema>;
