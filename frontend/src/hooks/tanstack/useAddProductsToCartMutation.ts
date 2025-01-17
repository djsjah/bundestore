import { useMutation, useQueryClient } from '@tanstack/react-query';

import { addProductToCart } from '@/api';
import type { ApiError, AddProductToCartDTO } from '@/api';

export const useAddProductsToCartMutation = () => {
  const queryClient = useQueryClient();

  return useMutation<void, ApiError, AddProductToCartDTO[]>({
    mutationKey: ['cart'],
    mutationFn: async (data: AddProductToCartDTO[]) => {
      for (const productData of data) {
        await addProductToCart(productData);
      }
    },
    retry: 3,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cart'] });
    },
  });
};
