import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';

import { PASSWORD_REGEX } from '@/constants';
import { useAlert, useSignOutMutation, useUpdateUserInfoMutation } from '@/hooks';
import { cn } from '@/utils';

import { Button, Label } from '../shadcn';
import { PasswordInput, ErrorMessage } from '../common';

type ChangeUserPasswordFormProps = {
  onUserPasswordChange: () => void;
  onCancel: () => void;
};

export const ChangeUserPasswordForm: React.FC<ChangeUserPasswordFormProps> = ({ onUserPasswordChange, onCancel }) => {
  const { openAlert } = useAlert();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<FormData>({
    resolver: zodResolver(validationSchema),
    mode: 'all',
  });

  const { mutateAsync: updateUser, isPending: isUpdatingUser } = useUpdateUserInfoMutation();
  const { mutateAsync: signOutMutation, isPending: isSigningOut } = useSignOutMutation();

  const onSubmit = async (data: FormData) => {
    try {
      await updateUser({ password: data.password });
      openAlert('Your password has been updated successfully!');
      await signOutMutation();
      onUserPasswordChange();
    } catch (e) {
      console.error('Error updating profile/Signing out:', e);
      openAlert('Something went wrong!', 'destructive');
    }
  };

  return (
    <form
      autoComplete="off"
      onSubmit={handleSubmit(onSubmit)}
      className={cn('flex flex-col gap-6', { ['pointer-events-none opacity-80']: isUpdatingUser || isSigningOut })}
    >
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
      <div className="flex flex-col gap-4 items-center">
        <Button type="submit" variant="secondary" className="w-32">
          Save Changes
        </Button>
        <Button type="button" variant="ghost" onClick={onCancel} className="w-32">
          Cancel
        </Button>
      </div>
    </form>
  );
};

const validationSchema = z
  .object({
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
