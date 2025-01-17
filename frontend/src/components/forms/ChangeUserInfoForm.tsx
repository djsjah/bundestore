import { useCallback, useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { useHookFormMask } from 'use-mask-input';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';

import { PHONE_NUMBER_MASK, NAME_REGEX, PHONE_NUMBER_REGEX } from '@/constants';
import { useAlert, useUpdateCustomerInfoMutation } from '@/hooks';
import { cn } from '@/utils';

import { Button, Input, Label } from '../shadcn';
import { ErrorMessage } from '../common';

type ChangeUserInfoFormProps = {
  userCurrentFirstName: string;
  userCurrentLastName: string;
  userCurrentPhoneNumber: string;
  onUserInfoChange: () => void;
  onCancel: () => void;
};

export const ChangeUserInfoForm: React.FC<ChangeUserInfoFormProps> = ({
  userCurrentFirstName,
  userCurrentLastName,
  userCurrentPhoneNumber,
  onUserInfoChange,
  onCancel,
}) => {
  const { openAlert } = useAlert();

  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<FormData>({
    defaultValues: {
      firstName: userCurrentFirstName,
      lastName: userCurrentLastName,
      phoneNumber: userCurrentPhoneNumber,
    },
    resolver: zodResolver(validationSchema),
    mode: 'all',
  });

  const registerWithMask = useHookFormMask(register);

  const { mutateAsync: updateCustomer, isPending: isUpdatingUser } = useUpdateCustomerInfoMutation();

  const [isFormChanged, setIsFormChanged] = useState(false);

  const firstName = watch('firstName');
  const lastName = watch('lastName');
  const phoneNumber = watch('phoneNumber');

  useEffect(() => {
    setIsFormChanged(
      userCurrentFirstName !== firstName || userCurrentLastName !== lastName || userCurrentPhoneNumber !== phoneNumber,
    );
  }, [userCurrentFirstName, userCurrentLastName, userCurrentPhoneNumber, firstName, lastName, phoneNumber]);

  const onSubmit = useCallback(
    async (data: FormData) => {
      try {
        await updateCustomer(data);
        openAlert('Your profile has been updated successfully!');
        onUserInfoChange();
      } catch (e) {
        console.error('Error updating profile:', e);
        openAlert('Something went wrong!', 'destructive');
      }
    },
    [onUserInfoChange, openAlert, updateCustomer],
  );

  return (
    <form
      autoComplete="off"
      onSubmit={handleSubmit(onSubmit)}
      className={cn('flex flex-col gap-6', { ['pointer-events-none opacity-80']: isUpdatingUser })}
    >
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1 flex flex-col gap-2">
          <Label htmlFor="firstName">First Name</Label>
          <div>
            <Input id="firstName" {...register('firstName')} />
            {errors.firstName && <ErrorMessage>{errors.firstName?.message}</ErrorMessage>}
          </div>
        </div>
        <div className="flex-1 flex flex-col gap-2">
          <Label htmlFor="lastName">Last Name</Label>
          <div>
            <Input id="lastName" {...register('lastName')} />
            {errors.lastName && <ErrorMessage>{errors.lastName?.message}</ErrorMessage>}
          </div>
        </div>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="phoneNumber">Phone Number</Label>
        <div>
          <Input
            id="phoneNumber"
            placeholder="+X (XXX) XXX-XXXX"
            {...registerWithMask('phoneNumber', PHONE_NUMBER_MASK, { required: true })}
          />
          {errors.phoneNumber && <ErrorMessage>{errors.phoneNumber?.message}</ErrorMessage>}
        </div>
      </div>
      <div className="flex flex-col gap-4 items-center">
        <Button type="submit" variant="secondary" className="w-32" disabled={isUpdatingUser || !isFormChanged}>
          Save Changes
        </Button>
        <Button type="button" variant="ghost" onClick={onCancel} className="w-32">
          Cancel
        </Button>
      </div>
    </form>
  );
};

const validationSchema = z.object({
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
  phoneNumber: z
    .string()
    .min(1, 'Phone number is required')
    .regex(PHONE_NUMBER_REGEX, 'Invalid phone number')
    .transform(val => val.trim()),
});

type FormData = z.infer<typeof validationSchema>;
