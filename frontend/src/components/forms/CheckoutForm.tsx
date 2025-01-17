import { useCallback } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';

import { MODALS } from '@/constants';
import { useModal, useGetUserPayloadQuery, useCreateOrderMutation, useAlert } from '@/hooks';
import { cn } from '@/utils';

import { Button, Checkbox, Label, RadioGroup, RadioGroupItem } from '../shadcn';
import { ErrorMessage } from '../common';

export const CheckoutForm: React.FC = () => {
  const { openModal } = useModal();
  const { openAlert } = useAlert();

  const { data: userData } = useGetUserPayloadQuery();

  const { mutateAsync: createOrderMutation, isPending: isCreatingOrder } = useCreateOrderMutation();

  const {
    handleSubmit,
    setValue,
    watch,
    formState: { errors },
    reset,
  } = useForm<FormData>({
    resolver: zodResolver(validationSchema),
    mode: 'all',
  });

  const acceptTerms = watch('acceptTerms');
  const contactMethod = watch('contactMethod');

  const onSubmit = useCallback(async () => {
    try {
      await createOrderMutation();
      openModal(MODALS.SUCCESSFUL_ORDER_CREATION);
      reset();
    } catch (e) {
      console.error('Error creating order: ', e);
      openAlert('Something went wrong!', 'destructive');
    }
  }, [createOrderMutation, openAlert, openModal, reset]);

  return (
    <form
      autoComplete="off"
      onSubmit={handleSubmit(onSubmit)}
      className={cn('flex flex-col gap-6', { ['pointer-events-none opacity-80']: isCreatingOrder })}
    >
      <div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="contactMethod" className="block text-lg">
            Preferred contact method:
          </Label>
          <RadioGroup
            value={contactMethod}
            onValueChange={value => setValue('contactMethod', value, { shouldValidate: true })}
            className="flex flex-col gap-2"
          >
            <div className="flex items-center gap-2">
              <RadioGroupItem value="email" id="contact-email" />
              <Label htmlFor="contact-email" className="text-base">
                Email <span className="text-zinc-500">({userData?.email})</span>
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <RadioGroupItem value="phone" id="contact-phone" />
              <Label htmlFor="contact-phone" className="text-base">
                Phone <span className="text-zinc-500">({userData?.phoneNumber})</span>
              </Label>
            </div>
          </RadioGroup>
        </div>
        {errors.contactMethod && <ErrorMessage>{errors.contactMethod.message}</ErrorMessage>}
      </div>
      <div>
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <Checkbox
              id="acceptTerms"
              checked={acceptTerms}
              onCheckedChange={e => setValue('acceptTerms', !!e, { shouldValidate: true })}
            />
            <Label htmlFor="acceptTerms" className="text-base">
              I accept the terms and conditions of the purchase.
            </Label>
          </div>
          <p className="text-zinc-500">
            By proceeding, you agree that a representative will contact you via your chosen method to discuss order
            details.
          </p>
        </div>
        {errors.acceptTerms && <ErrorMessage>{errors.acceptTerms.message}</ErrorMessage>}
      </div>
      <Button type="submit" variant="secondary" className="mt-4">
        Place Order
      </Button>
    </form>
  );
};

const validationSchema = z.object({
  acceptTerms: z.boolean({ required_error: 'You must accept the terms to place an order' }).refine(value => value, {
    message: 'You must accept the terms to place an order',
  }),
  contactMethod: z.string({ required_error: 'Please select a contact method' }),
});

type FormData = z.infer<typeof validationSchema>;
