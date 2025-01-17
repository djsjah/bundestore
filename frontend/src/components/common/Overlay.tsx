import { createPortal } from 'react-dom';

type OverlayProps = {
  onClick?: React.MouseEventHandler<HTMLDivElement>;
};

export const Overlay: React.FC<React.PropsWithChildren<OverlayProps>> = ({ onClick, children }) => {
  return createPortal(
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-end md:items-center justify-center z-50"
      onClick={onClick}
    >
      <div className="shadow-lg w-full md:max-w-lg" onClick={e => e.stopPropagation()}>
        {children}
      </div>
    </div>,
    document.body,
  );
};
