import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';

import { APP_ROUTER, MODALS } from '@/constants';
import { useModal } from '@/hooks';

import { Button } from '../shadcn';
import { ModalBase } from '../common';

export const AccountRequiredModal: React.FC = () => {
  const navigate = useNavigate();

  const { closeModal } = useModal();

  const handleModalClose = useCallback(() => {
    closeModal(MODALS.ACCOUNT_REQUIRED);
  }, [closeModal]);

  return (
    <ModalBase modalId={MODALS.ACCOUNT_REQUIRED} title="Account Required" onClose={handleModalClose}>
      <div className="flex flex-col gap-4 text-zinc-500 mb-6">
        <p>
          To make purchases and use the shopping cart, you need to have an account. Please sign up or log in to
          continue.
        </p>
      </div>
      <div className="flex flex-col items-end gap-2">
        <Button
          type="button"
          variant="secondary"
          onClick={() => {
            handleModalClose();
            navigate(APP_ROUTER.SIGN_UP);
          }}
        >
          Sign up
        </Button>
        <Button
          type="button"
          variant="ghost"
          onClick={() => {
            handleModalClose();
            navigate(APP_ROUTER.SIGN_IN);
          }}
        >
          Already have an account
        </Button>
      </div>
    </ModalBase>
  );
};
