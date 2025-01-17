import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';

import { APP_ROUTER, MODALS } from '@/constants';
import type { GetCategoryDTO, GetProductVariantDTO } from '@/api';
import { useAddProductsToCartMutation, useAlert, useGetUserPayloadQuery, useModal } from '@/hooks';

import { Button, Card, CardHeader, CardContent, CardFooter } from '../shadcn';

type ProductCardProps = {
  id: string;
  category: GetCategoryDTO;
  image: string;
  name: string;
  description: string;
  price: number;
  variants: GetProductVariantDTO[];
  isInCart: boolean;
};

export const ProductCard: React.FC<ProductCardProps> = ({
  id,
  category,
  image,
  name,
  description,
  price,
  variants,
  isInCart,
}) => {
  const navigate = useNavigate();

  const { isFetching: isLoadingUser, error: errorUser } = useGetUserPayloadQuery();

  const { mutateAsync: addProductToCartMutation, isPending: isAddingProduct } = useAddProductsToCartMutation();

  const { openModal } = useModal();
  const { openAlert } = useAlert();

  const handleAddProduct = useCallback(async () => {
    if (errorUser && errorUser.status === 401) {
      openModal(MODALS.ACCOUNT_REQUIRED);
      return;
    }

    if (category !== 'ACCESSORIES') {
      openModal(MODALS.PRODUCT_SIZE_CHOICE, { productId: id, variants });
    } else {
      try {
        await addProductToCartMutation([{ productId: id }]);
        openAlert('Product added to cart!');
      } catch (e) {
        console.error('Error adding product to cart: ', e);
        openAlert('Something went wrong!', 'destructive');
      }
    }
  }, [addProductToCartMutation, id, openAlert, openModal, errorUser, variants, category]);

  const handleViewProduct = () => {
    navigate(`${APP_ROUTER.CATALOG}/${id}`);
  };

  return (
    <Card className="rounded-lg">
      <CardHeader onClick={handleViewProduct} className="cursor-pointer">
        <img src={image} alt={name} className="w-full h-56 object-cover rounded-t-lg" />
        <h2>{name}</h2>
      </CardHeader>
      <CardContent>
        <p className="text-zinc-500 mb-2">{description.split(' ').slice(0, 5).join(' ')}...</p>
        <p className="font-semibold">Price: ${price.toFixed(2)}</p>
      </CardContent>
      <CardFooter className="flex justify-end">
        {isInCart ? (
          <Button type="button" variant="ghost" onClick={() => navigate(APP_ROUTER.SHOPPING_CART)}>
            In Cart
          </Button>
        ) : (
          <Button type="button" variant="ghost" onClick={handleAddProduct} disabled={isAddingProduct || isLoadingUser}>
            Add to Cart
          </Button>
        )}
      </CardFooter>
    </Card>
  );
};
