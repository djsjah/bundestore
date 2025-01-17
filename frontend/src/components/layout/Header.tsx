import React from 'react';
import { Link } from 'react-router-dom';

import { APP_ROUTER } from '@/constants';
import { useGetUserPayloadQuery } from '@/hooks';
import LogoIcon from '@/assets/icons/logo.svg?react';
import CartIcon from '@/assets/icons/cart.svg?react';

import { Button } from '../shadcn';

import { QuickAccessDropdown } from './QuickAccessDropdown';

export const Header = () => {
  const { isLoading: isLoadingUser, error: errorUser } = useGetUserPayloadQuery();

  return (
    <header className="sticky top-0 z-50 bg-opacity-90 backdrop-blur-3xl border-b-2 border-b-zinc-900 shadow-md">
      <div className="mx-auto px-4 py-2 flex justify-between items-center">
        <Link to={APP_ROUTER.MAIN} className="flex gap-2 items-center text-xl font-semibold text-zinc-100">
          <LogoIcon className="w-8 h-8" />
          Bundestore
        </Link>
        <div className="flex gap-2">
          {isLoadingUser || (errorUser && errorUser.status === 401) ? (
            <React.Fragment>
              <Link to={APP_ROUTER.SIGN_IN}>
                <Button type="button">Sign In</Button>
              </Link>
              <Link to={APP_ROUTER.SIGN_UP}>
                <Button type="button" variant="ghost">
                  Sign Up
                </Button>
              </Link>
            </React.Fragment>
          ) : (
            <div className="flex items-center gap-4">
              <Link to={APP_ROUTER.SHOPPING_CART}>
                <CartIcon className="h-7 w-7" />
              </Link>
              <QuickAccessDropdown />
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
