import { BrowserRouter, Routes, Route } from 'react-router-dom';

import { APP_ROUTER } from '@/constants';
import { Layout } from '@/layout';
import {
  SignUpPage,
  SignInPage,
  EmailVerificationPage,
  HomePage,
  CatalogPage,
  CheckoutPage,
  ProductPage,
  ShoppingCartPage,
  OrdersPage,
  RecoverPasswordPage,
  ProfilePage,
} from '@/pages';
import { AccountRequiredModal, EmailVerificationRequiredModal } from '@/components';

import { ProtectedRoute } from './ProtectedRoute';

export const AppRouter: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path={APP_ROUTER.MAIN} element={<Layout />}>
          <Route path={APP_ROUTER.MAIN} element={<HomePage />} />
          <Route path={APP_ROUTER.SIGN_UP} element={<SignUpPage />} />
          <Route path={APP_ROUTER.SIGN_IN} element={<SignInPage />} />
          <Route path={APP_ROUTER.EMAIL_VERIFICATION} element={<EmailVerificationPage />} />
          <Route path={APP_ROUTER.RECOVER_PASSWORD} element={<RecoverPasswordPage />} />
          <Route path={APP_ROUTER.CATALOG} element={<CatalogPage />} />
          <Route path={`${APP_ROUTER.CATALOG}/:id`} element={<ProductPage />} />
          <Route
            path={APP_ROUTER.SHOPPING_CART}
            element={
              <ProtectedRoute>
                <ShoppingCartPage />
              </ProtectedRoute>
            }
          />
          <Route
            path={APP_ROUTER.PROFILE}
            element={
              <ProtectedRoute>
                <ProfilePage />
              </ProtectedRoute>
            }
          />
          <Route
            path={APP_ROUTER.ORDERS}
            element={
              <ProtectedRoute>
                <OrdersPage />
              </ProtectedRoute>
            }
          />
          <Route
            path={APP_ROUTER.CHECKOUT}
            element={
              <ProtectedRoute>
                <CheckoutPage />
              </ProtectedRoute>
            }
          />
        </Route>
      </Routes>
      <AccountRequiredModal />
      <EmailVerificationRequiredModal />
    </BrowserRouter>
  );
};
