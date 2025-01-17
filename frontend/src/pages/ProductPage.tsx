/* eslint-disable max-len */
import { useCallback, useEffect, useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Controller, useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';

import { AGE_LABELS, APP_ROUTER, CATEGORY_LABELS, GENDER_LABELS, MODALS } from '@/constants';
import type { GetClothingSizeDTO, GetFootwearSizeDTO, GetProductDTO } from '@/api';
import {
  useAddProductsToCartMutation,
  useAlert,
  useGetCartQuery,
  useGetProductQuery,
  useGetUserPayloadQuery,
  useModal,
} from '@/hooks';
import { Button, Card, CardHeader, CardContent, CardFooter, SizeOption, Skeleton, ErrorMessage } from '@/components';

export const ProductPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();

  const { openModal } = useModal();
  const { openAlert } = useAlert();

  const { data: product, isLoading: isLoadingProduct, error: errorProduct } = useGetProductQuery(id);

  const { isLoading: isLoadingUser, error: errorUser } = useGetUserPayloadQuery();

  const { data: cart, isLoading: isLoadingCart, error: errorCart } = useGetCartQuery();

  const { mutateAsync: addProductToCartMutation, isPending: isAddingProduct } = useAddProductsToCartMutation();

  const sizesInCart = useMemo(() => {
    return cart?.orderItems.filter(orderItem => orderItem.productId === id).map(orderItem => orderItem.size) || [];
  }, [cart?.orderItems, id]);

  const validationSchema = useMemo(() => {
    if (product) {
      return getValidationSchema(product);
    }

    return z.object({});
  }, [product]);

  const {
    watch,
    handleSubmit,
    control,
    formState: { errors },
    reset,
  } = useForm<FormData>({
    defaultValues: { sizes: [] },
    resolver: zodResolver(validationSchema),
    mode: 'all',
  });

  const selectedSizes = watch('sizes');

  useEffect(() => {
    if (cart) {
      reset({ sizes: sizesInCart });
    }
  }, [cart, reset, sizesInCart]);

  const hasNewSizes = useMemo(() => {
    return (
      selectedSizes.length > 0 &&
      selectedSizes.some(size => !sizesInCart.includes(size as GetClothingSizeDTO | GetFootwearSizeDTO))
    );
  }, [selectedSizes, sizesInCart]);

  const onSubmit = useCallback(
    async (data: FormData) => {
      if (errorUser && errorUser.status === 401) {
        openModal(MODALS.ACCOUNT_REQUIRED);
        return;
      }

      if (id) {
        try {
          let productData;

          if (data.sizes.length) {
            productData = data.sizes.map(size => ({
              productId: id,
              size: size as GetClothingSizeDTO | GetFootwearSizeDTO,
            }));
          } else {
            productData = [
              {
                productId: id,
              },
            ];
          }

          await addProductToCartMutation(productData);
          openAlert('Product added to cart!');
          reset();
        } catch (e) {
          console.error('Error adding product to cart: ', e);
          openAlert('Something went wrong!', 'destructive');
        }
      }
    },
    [addProductToCartMutation, errorUser, id, openModal, openAlert, reset],
  );

  useEffect(() => {
    if (errorProduct && errorProduct.status !== 404) {
      openAlert('Something went wrong!', 'destructive');
    }
  }, [errorProduct, openAlert]);

  useEffect(() => {
    if (errorUser && errorUser.status === 401) {
      reset({ sizes: [] });
    }
  }, [errorUser, reset]);

  if (isLoadingProduct || isLoadingCart || isLoadingUser) {
    return (
      <div className="container mx-auto p-6">
        <Skeleton className="h-96 mb-10" />
        <div className="border-2 border-zinc-900 p-6">
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-6 lg:flex-row lg:justify-between">
              <Skeleton className="h-12 max-w-96" />
              <Skeleton className="h-12 w-36" />
            </div>
            <Skeleton className="h-36 w-full" />
          </div>
        </div>
      </div>
    );
  }

  if (errorProduct || (errorCart && errorCart.status !== 401) || !product) {
    if (errorProduct?.status === 404) {
      return (
        <div className="flex justify-center items-center mt-10">
          <p className="text-zinc-400 text-lg">No Product found</p>
        </div>
      );
    } else {
      return (
        <div className="flex justify-center items-center mt-2 lg:mt-10">
          <ErrorMessage size="lg">Server Error</ErrorMessage>
        </div>
      );
    }
  }

  return (
    <form autoComplete="off" onSubmit={handleSubmit(onSubmit)} className="container mx-auto p-6">
      <Card className="border-none">
        <CardHeader className="relative mb-10 h-96 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-center bg-cover blur-md"
            style={{ backgroundImage: `url(${product.imageUrl})` }}
          />
          <img src={product.imageUrl} alt={product.name} className="relative h-full z-10 object-contain rounded-md" />
        </CardHeader>
        <div className="border-2 border-zinc-900 p-6">
          <CardContent className="flex flex-col gap-4 p-0 mb-4">
            <div className="flex flex-col gap-6">
              <div className="flex flex-col gap-6 lg:flex-row lg:justify-between">
                <div>
                  <p className="text-zinc-500">{CATEGORY_LABELS[product.category]}</p>
                  <h1 className="text-2xl font-bold mb-2">{product.name}</h1>
                  <div className="flex flex-col text-sm text-zinc-500">
                    <p>
                      Age Group: <span className="font-semibold text-zinc-700">{AGE_LABELS[product.age]}</span>
                    </p>
                    <p>
                      Sex: <span className="font-semibold text-zinc-700">{GENDER_LABELS[product.gender]}</span>
                    </p>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-4 lg:w-[400px]">
                  <div className="flex flex-col items-end">
                    {errors.sizes && <ErrorMessage>{errors.sizes.message}</ErrorMessage>}
                    {product.category !== 'ACCESSORIES' && (
                      <Controller
                        name="sizes"
                        control={control}
                        render={({ field }) => (
                          <div className="flex flex-wrap gap-2">
                            {product.variants.map(variant => {
                              const disabled =
                                variant.stockQuantity === 0 || sizesInCart.includes(variant.size) || isAddingProduct;
                              return (
                                <SizeOption
                                  key={variant.size}
                                  size={variant.size!}
                                  isSelected={field.value.includes(variant.size!)}
                                  disabled={disabled}
                                  onSelect={selectedSize => {
                                    if (disabled) return;
                                    const newValue = field.value.includes(selectedSize)
                                      ? field.value.filter(s => s !== selectedSize)
                                      : [...field.value, selectedSize];
                                    field.onChange(newValue);
                                  }}
                                />
                              );
                            })}
                          </div>
                        )}
                      />
                    )}
                  </div>
                  <p className="text-xl font-semibold mb-4">Price: ${product.price.toFixed(2)}</p>
                </div>
              </div>
              <p className="text-lg text-zinc-500">{product.description}</p>
            </div>
          </CardContent>
          <CardFooter className="p-0 flex justify-end">
            {selectedSizes.length > 0 && !hasNewSizes ? (
              <Button type="button" variant="secondary" onClick={() => navigate(APP_ROUTER.SHOPPING_CART)}>
                In Cart
              </Button>
            ) : (
              <Button type="submit" variant="secondary" disabled={product.stockQuantity === 0 || isAddingProduct}>
                Add To Cart
              </Button>
            )}
          </CardFooter>
        </div>
      </Card>
    </form>
  );
};

const getValidationSchema = (product: GetProductDTO) => {
  if (product.category === 'ACCESSORIES') {
    return z.object({
      sizes: z.array(z.string()),
    });
  }

  return z.object({
    sizes: z.array(z.string()).nonempty('Select at least one product size'),
  });
};

type FormData = z.infer<ReturnType<typeof getValidationSchema>>;
