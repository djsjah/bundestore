/* eslint-disable max-len */
import { useCallback } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';

import { MODALS } from '@/constants';
import type { GetClothingSizeDTO, GetFootwearSizeDTO, GetProductVariantDTO } from '@/api';
import { useAddProductsToCartMutation, useAlert, useModal } from '@/hooks';

import { Button } from '../shadcn';
import { ErrorMessage, ModalBase, SizeOption } from '../common';

type ProductSizeChoiceModalType = {
  productId: string;
  variants: GetProductVariantDTO[];
};

export const ProductSizeChoiceModal: React.FC = () => {
  const { getModalState, closeModal } = useModal();
  const { openAlert } = useAlert();

  const modalArgs = getModalState<ProductSizeChoiceModalType>(MODALS.PRODUCT_SIZE_CHOICE).args;

  const { mutateAsync: addProductMutation, isPending: isAddingProduct } = useAddProductsToCartMutation();

  const {
    handleSubmit,
    control,
    formState: { errors },
    reset,
  } = useForm<FormData>({
    defaultValues: {
      sizes: [],
    },
    resolver: zodResolver(validationSchema),
    mode: 'all',
  });

  const handleModalClose = useCallback(() => {
    closeModal(MODALS.PRODUCT_SIZE_CHOICE);
  }, [closeModal]);

  const onSubmit = useCallback(
    async (data: FormData) => {
      if (modalArgs?.productId) {
        try {
          const productData = data.sizes.map(size => ({
            productId: modalArgs.productId,
            size: size as GetClothingSizeDTO | GetFootwearSizeDTO,
          }));

          await addProductMutation(productData);
          handleModalClose();
          openAlert('Product added to cart!');
          reset();
        } catch (e) {
          console.error('Error adding product to cart: ', e);
          openAlert('Something went wrong!', 'destructive');
        }
      }
    },
    [addProductMutation, handleModalClose, modalArgs?.productId, openAlert, reset],
  );

  if (!modalArgs) {
    return null;
  }

  return (
    <ModalBase modalId={MODALS.PRODUCT_SIZE_CHOICE} title="Select Product Size" onClose={handleModalClose}>
      <form autoComplete="off" onSubmit={handleSubmit(onSubmit)}>
        <div className="mb-6">
          {errors.sizes && <ErrorMessage>{errors.sizes.message}</ErrorMessage>}
          <Controller
            name="sizes"
            control={control}
            render={({ field }) => (
              <div className="flex flex-wrap gap-2">
                {modalArgs.variants.map(variant => (
                  <SizeOption
                    key={variant.size}
                    size={variant.size!}
                    isSelected={field.value.includes(variant.size!)}
                    onSelect={selectedSize => {
                      const newValue = field.value.includes(selectedSize)
                        ? field.value.filter(s => s !== selectedSize)
                        : [...field.value, selectedSize];
                      field.onChange(newValue);
                    }}
                    disabled={variant.stockQuantity === 0}
                  />
                ))}
              </div>
            )}
          />
        </div>
        <div className="flex justify-end">
          <Button type="submit" variant="secondary" disabled={isAddingProduct}>
            Proceed
          </Button>
        </div>
      </form>
    </ModalBase>
  );
};

const validationSchema = z.object({
  sizes: z.array(z.string()).nonempty('Select at least one product size'),
});

type FormData = z.infer<typeof validationSchema>;
