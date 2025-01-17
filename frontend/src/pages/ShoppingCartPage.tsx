import { useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

import { APP_ROUTER } from '@/constants';
import { useAlert, useDeleteCartItemMutation, useGetCartQuery, useUpdateCartItemQuantityMutation } from '@/hooks';
import { cn } from '@/utils';
import { Button, ErrorMessage, CartItem, OrderSummary, Skeleton } from '@/components';

export const ShoppingCartPage: React.FC = () => {
  const navigate = useNavigate();

  const { openAlert } = useAlert();

  const { data: cart, isLoading: isLoadingCart, error: errorCart } = useGetCartQuery();

  const { mutateAsync: updateCartItemQuantity, isPending: isUpdatingItem } = useUpdateCartItemQuantityMutation();

  const { mutateAsync: deleteCartItemMutation, isPending: isDeletingItem } = useDeleteCartItemMutation();

  useEffect(() => {
    if (errorCart) {
      openAlert('Something went wrong!', 'destructive');
    }
  }, [errorCart, openAlert]);

  const handleQuantityChange = useCallback(
    async (orderItemId: string, quantity: number) => {
      if (cart) {
        try {
          await updateCartItemQuantity({
            orderItemId,
            quantity,
          });
        } catch (e) {
          console.error('Error updating cart: ', e);
          openAlert('Something went wrong!', 'destructive');
        }
      }
    },
    [cart, openAlert, updateCartItemQuantity],
  );

  const handleProductRemove = useCallback(
    async (orderItemId: string) => {
      if (cart) {
        try {
          deleteCartItemMutation(orderItemId);
        } catch (e) {
          console.error('Error deleting cart item: ', e);
          openAlert('Something went wrong!', 'destructive');
        }
      }
    },
    [cart, deleteCartItemMutation, openAlert],
  );

  return (
    <div className={cn('container mx-auto p-6', isUpdatingItem || isDeletingItem ? 'pointer-events-none' : '')}>
      <div className="mb-8">
        <h2 className="text-xl font-bold mb-2">Shopping Cart</h2>
        <p className="font-semibold text-zinc-500">{cart?.orderItems.length} Products</p>
      </div>
      {isLoadingCart ? (
        <div className="flex flex-col gap-6 lg:flex-row">
          <div className="flex flex-col gap-4 flex-1">
            {Array.from({ length: 3 }).map((_, index) => (
              <Skeleton key={index} className="h-32" />
            ))}
          </div>
          <Skeleton className="h-52 w-full lg:w-1/3" />
        </div>
      ) : errorCart || !cart ? (
        <div className="flex justify-center items-center mt-2 lg:mt-10">
          <ErrorMessage size="lg">Server Error</ErrorMessage>
        </div>
      ) : cart.quantity <= 0 ? (
        <div className="flex flex-col gap-4 justify-center items-center mt-2 lg:mt-10">
          <p className="text-zinc-400 text-lg">Your cart is empty!</p>
          <Button type="button" variant="secondary" onClick={() => navigate(APP_ROUTER.CATALOG)}>
            Catalog
          </Button>
        </div>
      ) : (
        <div className="flex flex-col gap-6 lg:flex-row">
          <div className="flex-1 flex flex-col gap-4">
            {cart.orderItems.map(item => (
              <div key={item.id} className={cn({ 'opacity-80': isDeletingItem })}>
                <CartItem
                  key={item.id}
                  id={item.id}
                  productId={item.productId}
                  size={item.size}
                  total={item.total}
                  quantity={item.quantity}
                  stockQuantity={item.stockQuantity}
                  onQuantityChange={handleQuantityChange}
                  onDelete={handleProductRemove}
                />
              </div>
            ))}
          </div>
          <div className="flex flex-col gap-6 rounded-lg border-2 border-zinc-900 max-h-fit p-6 lg:w-1/3">
            <OrderSummary totalPrice={cart.total} totalQuantity={cart.quantity} />
            <Button
              type="button"
              variant="secondary"
              className="w-full"
              disabled={cart.orderItems.some(orderItem => orderItem.quantity > orderItem.stockQuantity)}
              onClick={() => navigate(APP_ROUTER.CHECKOUT)}
            >
              Checkout
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};
