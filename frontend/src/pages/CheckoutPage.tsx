import React, { useEffect } from 'react';

import { useAlert, useGetCartQuery } from '@/hooks';
import { CheckoutForm, ErrorMessage, OrderSummary, Skeleton, SuccessfulOrderCreationModal } from '@/components';

export const CheckoutPage: React.FC = () => {
  const { openAlert } = useAlert();

  const { data: cart, isLoading: isLoadingCart, isError: isErrorCart } = useGetCartQuery();

  useEffect(() => {
    if (isErrorCart) {
      openAlert('Something went wrong!', 'destructive');
    }
  }, [isErrorCart, openAlert]);

  return (
    <React.Fragment>
      <div className="container mx-auto p-6">
        <h2 className="text-xl font-bold mb-8">Checkout</h2>
        {isLoadingCart ? (
          <div className="flex flex-col gap-8">
            <div className="flex flex-col gap-8">
              <Skeleton className="h-48" />
              <Skeleton className="h-20" />
            </div>
            <Skeleton className="h-20 w-3/5" />
          </div>
        ) : isErrorCart || !cart ? (
          <div className="flex justify-center items-center mt-2 lg:mt-10">
            <ErrorMessage size="lg">Server Error</ErrorMessage>
          </div>
        ) : (
          <React.Fragment>
            <div className="flex flex-col gap-8 mb-8 lg:flex-row">
              <div className="p-4 rounded-lg text-zinc-500 border-2 border-zinc-900 flex-1">
                <p>
                  Thank you for placing your order! After checkout, a representative will contact you via your preferred
                  method (email or phone) to discuss the details of your order, including payment and delivery options.
                </p>
                <p className="mt-2">
                  You can track the status of your order on the <strong>My Orders</strong> page. If you have any
                  questions, feel free to reach out to our support team (<strong>bundestort@gmail.com</strong>).
                </p>
              </div>
              <div className="rounded-lg border-2 border-zinc-900 max-h-fit p-6 lg:w-1/3">
                <OrderSummary totalPrice={cart.total} totalQuantity={cart.quantity} />
              </div>
            </div>
            <CheckoutForm />
          </React.Fragment>
        )}
      </div>
      <SuccessfulOrderCreationModal />
    </React.Fragment>
  );
};
