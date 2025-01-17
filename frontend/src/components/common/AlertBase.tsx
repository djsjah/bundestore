/* eslint-disable max-len */
import { useEffect } from 'react';
import { createPortal } from 'react-dom';

import { useAlert } from '@/hooks';
import CrossIcon from '@/assets/icons/cross.svg?react';
import TickIcon from '@/assets/icons/tick.svg?react';
import ErrorIcon from '@/assets/icons/error.svg?react';

import { Alert, AlertDescription, Button } from '../shadcn';

export const AlertBase: React.FC = () => {
  const { closeAlert, getAlertState } = useAlert();

  const alertState = getAlertState();

  useEffect(() => {
    if (alertState.isOpen) {
      const timer = setTimeout(() => {
        closeAlert();
      }, 3000);

      return () => clearTimeout(timer);
    }

    return undefined;
  }, [alertState.isOpen, closeAlert]);

  if (!alertState.isOpen) {
    return null;
  }

  return createPortal(
    <Alert
      variant={alertState.variant}
      className="fixed top-20 left-1/2 w-[300px] z-50 transform -translate-x-1/2 flex gap-4 items-center lg:text-center lg:gap-2 lg:w-fit"
    >
      {alertState.variant === 'default' ? (
        <TickIcon className="max-w-5 h-5 flex-shrink-0" />
      ) : (
        <ErrorIcon className="max-w-4 h-4 flex-shrink-0" />
      )}
      <AlertDescription>{alertState.message}</AlertDescription>
      <Button type="button" variant="ghost" className="w-fit h-fit p-2 ml-2" onClick={closeAlert}>
        <CrossIcon className="max-w-3 h-3 fill-white" />
      </Button>
    </Alert>,
    document.body,
  );
};
