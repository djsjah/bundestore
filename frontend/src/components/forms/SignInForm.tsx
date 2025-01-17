import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';

import { APP_ROUTER, MODALS } from '@/constants';
import type { ApiError } from '@/api';
import { useAlert, useModal, useSignInMutation } from '@/hooks';
import { cn } from '@/utils';

import { Button, Input, Label } from '../shadcn';
import { ErrorMessage, PasswordInput } from '../common';

export const SignInForm: React.FC = () => {
  const navigate = useNavigate();

  const { openModal } = useModal();
  const { openAlert } = useAlert();

  const {
    register,
    handleSubmit,
    formState: { errors },
    setError,
  } = useForm<FormData>({
    resolver: zodResolver(validationSchema),
    mode: 'all',
  });

  const { mutateAsync: signInMutation, isPending: isSigningIn } = useSignInMutation();

  const onSubmit = useCallback(
    async (data: FormData) => {
      try {
        await signInMutation({ email: data.email, password: data.password });
        navigate(APP_ROUTER.MAIN);
      } catch (e) {
        console.error('Error signing in: ', e);

        const apiError = e as ApiError;

        if (apiError.status === 404) {
          setError('email', { message: 'Invalid credentials' });
          setError('password', { message: 'Invalid credentials' });
        } else if (apiError.status === 403) {
          openModal(MODALS.EMAIL_VERIFICATION_REQUIRED, { email: data.email });
        } else {
          openAlert('Something went wrong!', 'destructive');
        }
      }
    },
    [navigate, openAlert, openModal, setError, signInMutation],
  );

  return (
    <form
      autoComplete="off"
      onSubmit={handleSubmit(onSubmit)}
      className={cn('flex flex-col gap-6', { ['pointer-events-none opacity-80']: isSigningIn })}
    >
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <Label htmlFor="email">Email</Label>
          <div>
            <Input type="text" id="email" {...register('email')} />
            {errors.email && <ErrorMessage>{errors.email?.message}</ErrorMessage>}
          </div>
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="password">Password</Label>
          <div>
            <PasswordInput id="password" {...register('password')} />
            {errors.password && <ErrorMessage>{errors.password?.message}</ErrorMessage>}
          </div>
        </div>
      </div>
      <div className="flex flex-col gap-4 items-center">
        <Button type="submit" variant="secondary" className="w-32">
          Sign In
        </Button>
        <Button type="button" variant="ghost" className="w-32" onClick={() => navigate(APP_ROUTER.RECOVER_PASSWORD)}>
          Forgot Password
        </Button>
      </div>
    </form>
  );
};

const validationSchema = z.object({
  email: z.string().min(1, 'Email is required').email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
});

type FormData = z.infer<typeof validationSchema>;
