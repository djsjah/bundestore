import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { useHookFormMask } from 'use-mask-input';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { compareAsc, isValid, parse, subYears } from 'date-fns';

import {
  APP_ROUTER,
  DATE_MASK,
  DATE_REGEX,
  NAME_REGEX,
  PASSWORD_REGEX,
  PHONE_NUMBER_MASK,
  PHONE_NUMBER_REGEX,
} from '@/constants';
import type { ApiError } from '@/api';
import { useAlert, useSignUpMutation } from '@/hooks';
import { cn } from '@/utils';

import { Button, Input, Label } from '../shadcn';
import { ErrorMessage, PasswordInput } from '../common';

export const SignUpForm: React.FC = () => {
  const navigate = useNavigate();

  const { openAlert } = useAlert();

  const { mutateAsync: signUpMutation, isPending: isSigningUp } = useSignUpMutation();

  const {
    register,
    setError,
    handleSubmit,
    formState: { errors },
  } = useForm<FormData>({
    resolver: zodResolver(validationSchema),
    mode: 'all',
  });

  const registerWithMask = useHookFormMask(register);

  const onSubmit = useCallback(
    async (data: FormData) => {
      try {
        await signUpMutation({
          firstName: data.firstName,
          lastName: data.lastName,
          email: data.email,
          password: data.password,
          phoneNumber: data.phoneNumber,
          birthDate: data.birthDate.toISOString(),
        });

        navigate(APP_ROUTER.EMAIL_VERIFICATION, { state: { email: data.email } });
      } catch (e) {
        console.error('Error signing up: ', e);

        const apiError = e as ApiError;

        if (apiError.status === 409) {
          setError('email', { message: 'User already exists' });
        } else {
          openAlert('Something went wrong!', 'destructive');
        }
      }
    },
    [navigate, openAlert, setError, signUpMutation],
  );

  return (
    <form
      autoComplete="off"
      onSubmit={handleSubmit(onSubmit)}
      className={cn('flex flex-col gap-6', { ['pointer-events-none opacity-80']: isSigningUp })}
    >
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1 flex flex-col gap-2">
          <Label htmlFor="firstName">First Name</Label>
          <div>
            <Input id="firstName" type="text" {...register('firstName')} />
            {errors.firstName && <ErrorMessage>{errors.firstName?.message}</ErrorMessage>}
          </div>
        </div>
        <div className="flex-1 flex flex-col gap-2">
          <Label htmlFor="lastName">Last Name</Label>
          <div>
            <Input id="lastName" type="text" {...register('lastName')} />
            {errors.lastName && <ErrorMessage>{errors.lastName?.message}</ErrorMessage>}
          </div>
        </div>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="email">Email</Label>
        <div>
          <Input type="text" id="email" {...register('email')} />
          {errors.email && <ErrorMessage>{errors.email?.message}</ErrorMessage>}
        </div>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="phoneNumber">Phone Number</Label>
        <div>
          <Input
            id="phoneNumber"
            type="text"
            placeholder="+X (XXX) XXX-XXXX"
            {...registerWithMask('phoneNumber', PHONE_NUMBER_MASK)}
          />
          {errors.phoneNumber && <ErrorMessage>{errors.phoneNumber?.message}</ErrorMessage>}
        </div>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="birthDate">Birth Date</Label>
        <div>
          <Input id="birthDate" type="text" placeholder="mm/dd/yyyy" {...registerWithMask('birthDate', DATE_MASK)} />
          {errors.birthDate && <ErrorMessage>{errors.birthDate?.message}</ErrorMessage>}
        </div>
      </div>
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1 flex flex-col gap-2">
          <Label htmlFor="password">Password</Label>
          <div>
            <PasswordInput id="password" {...register('password')} />
            {errors.password && <ErrorMessage>{errors.password?.message}</ErrorMessage>}
          </div>
        </div>
        <div className="flex-1 flex flex-col gap-2">
          <Label htmlFor="confirmPassword">Confirm Password</Label>
          <div>
            <PasswordInput id="confirmPassword" {...register('confirmPassword')} />
            {errors.confirmPassword && <ErrorMessage>{errors.confirmPassword?.message}</ErrorMessage>}
          </div>
        </div>
      </div>
      <div className="flex justify-center">
        <Button type="submit" variant="secondary" className="w-32">
          Sign Up
        </Button>
      </div>
    </form>
  );
};

const validationSchema = z
  .object({
    firstName: z
      .string()
      .min(1, 'First Name is required')
      .max(64, 'First Name is too long')
      .regex(NAME_REGEX, 'First Name can only contain letters and hyphens')
      .transform(val => val.trim()),
    lastName: z
      .string()
      .min(1, 'Last Name is required')
      .max(64, 'Last Name is too long')
      .regex(NAME_REGEX, 'Last Name can only contain letters and hyphens')
      .transform(val => val.trim()),
    email: z.string().min(1, 'Email is required').email('Invalid email address'),
    phoneNumber: z
      .string()
      .min(1, 'Phone number is required')
      .regex(PHONE_NUMBER_REGEX, 'Invalid phone number')
      .transform(val => val.trim()),
    birthDate: z
      .string()
      .min(1, 'Birth date is required')
      .regex(DATE_REGEX, 'Invalid date')
      .transform(value => parse(value, 'mm/dd/yyyy', new Date()))
      .refine(value => isValid(value), { message: 'Invalid date' })
      .refine(
        value =>
          compareAsc(subYears(new Date(), 16), value) === 1 && compareAsc(subYears(new Date(), 100), value) === -1,
        { message: 'Invalid age' },
      ),
    password: z
      .string()
      .min(10, 'Password must be at least 10 characters long')
      .max(64, 'Password must be at most 64 characters long')
      .regex(
        PASSWORD_REGEX,
        'Password must contain uppercase letter, lowercase letter, digit, and special character (@$!%*#?&)',
      ),
    confirmPassword: z.string().min(1, 'Please confirm your password'),
  })
  .refine(data => data.password === data.confirmPassword, {
    message: 'Passwords must match',
    path: ['confirmPassword'],
  });

type FormData = z.infer<typeof validationSchema>;
