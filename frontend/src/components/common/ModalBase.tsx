import { useEffect } from 'react';

import { useModal } from '@/hooks';
import CrossIcon from '@/assets/icons/cross.svg?react';

import { Button, Card, CardContent, CardHeader } from '../shadcn';

import { Overlay } from './Overlay';

type ModalBaseProps = {
  modalId: string;
  title?: string;
  onClose: () => void;
};

export const ModalBase: React.FC<React.PropsWithChildren<ModalBaseProps>> = ({ modalId, title, onClose, children }) => {
  const { getModalState } = useModal();

  const isOpen = getModalState(modalId).isOpen;

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'auto';
    }

    return () => {
      document.body.style.overflow = 'auto';
    };
  }, [isOpen]);

  if (!isOpen) {
    return null;
  }

  return (
    <Overlay>
      <Card className="bg-zinc-950 px-8 py-4 rounded-b-none md:rounded-lg">
        <CardHeader className="p-0 mb-4 relative">
          <h2 className="text-xl">{title}</h2>
          <Button type="button" variant="ghost" className="absolute -top-2 -right-4 w-fit" onClick={onClose}>
            <CrossIcon className="max-w-3 h-3 fill-white" />
          </Button>
        </CardHeader>
        <CardContent className="p-0">{children}</CardContent>
      </Card>
    </Overlay>
  );
};
