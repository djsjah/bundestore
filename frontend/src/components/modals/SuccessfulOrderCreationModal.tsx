import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';

import { APP_ROUTER, MODALS } from '@/constants';
import { useModal } from '@/hooks';

import { Button } from '../shadcn';
import { ModalBase } from '../common';

export const SuccessfulOrderCreationModal: React.FC = () => {
  const navigate = useNavigate();

  const { closeModal } = useModal();

  const handleModalClose = useCallback(() => {
    closeModal(MODALS.SUCCESSFUL_ORDER_CREATION);
    navigate(APP_ROUTER.MAIN);
  }, [closeModal, navigate]);

  return (
    <ModalBase modalId={MODALS.SUCCESSFUL_ORDER_CREATION} title="Order Created Successfully" onClose={handleModalClose}>
      <div className="flex flex-col gap-4 text-zinc-500 mb-6">
        <p>
          Thank you for placing your order! Our representative will contact you soon to discuss further details,
          including payment and delivery options.
        </p>
        <p>
          You can track the status of your order on the <strong>My Orders</strong> page. If you have any questions, feel
          free to reach out to our support team (<strong>bundestort@gmail.com</strong>).
        </p>
      </div>
      <div className="flex items-center gap-4 justify-end">
        <Button type="button" variant="secondary" onClick={() => navigate(APP_ROUTER.ORDERS)}>
          My Orders
        </Button>
        <Button type="button" variant="ghost" onClick={handleModalClose}>
          Close
        </Button>
      </div>
    </ModalBase>
  );
};
