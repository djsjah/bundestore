import { cn } from '@/utils';

type ErrorMessageProps = {
  size?: 'sm' | 'lg';
};

export const ErrorMessage: React.FC<React.PropsWithChildren<ErrorMessageProps>> = ({ size = 'sm', children }) => {
  return (
    <p
      className={cn('text-red-500', {
        'text-sm': size === 'sm',
        'text-lg': size === 'lg',
        'py-2': size === 'sm',
        'py-4': size === 'lg',
      })}
    >
      {children}
    </p>
  );
};
