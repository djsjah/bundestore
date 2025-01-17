import { createContext, useCallback, useMemo, useState } from 'react';

type AlertState = {
  isOpen: boolean;
  variant: 'default' | 'destructive';
  message: string | null;
};

type AlertsContextType = {
  openAlert: (message: string, variant?: 'default' | 'destructive') => void;
  closeAlert: () => void;
  getAlertState: () => AlertState;
};

export const AlertsContext = createContext<AlertsContextType>({} as AlertsContextType);

export const AlertsProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [alertState, setAlertState] = useState<AlertState>({ isOpen: false, variant: 'default', message: null });

  const openAlert = useCallback((message: string, variant: 'default' | 'destructive' = 'default'): void => {
    setAlertState({
      isOpen: true,
      variant: variant,
      message,
    });
  }, []);

  const closeAlert = useCallback((): void => {
    setAlertState({
      isOpen: false,
      variant: 'default',
      message: null,
    });
  }, []);

  const getAlertState = useCallback((): AlertState => alertState, [alertState]);

  const contextValue: AlertsContextType = useMemo(
    () => ({
      openAlert,
      closeAlert,
      getAlertState,
    }),
    [closeAlert, getAlertState, openAlert],
  );

  return <AlertsContext.Provider value={contextValue}>{children}</AlertsContext.Provider>;
};
