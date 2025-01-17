import { createContext, useCallback, useMemo, useState } from 'react';

type ModalState<T extends Record<string, unknown> = Record<string, unknown>> = {
  isOpen: boolean;
  isDisabled: boolean;
  args: T | null;
};

type ModalsContextType = {
  openModal: <T extends Record<string, unknown>>(key: string, args?: T) => void;
  closeModal: (key: string) => void;
  setDisabled: (key: string, value: boolean) => void;
  setArgs: (key: string, value: Record<string, unknown>) => void;
  getModalState: <T extends Record<string, unknown>>(key: string) => ModalState<T>;
};

export const ModalsContext = createContext<ModalsContextType>({} as ModalsContextType);

export const ModalsProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [modalsRegistry, setModalsRegistry] = useState<Record<string, ModalState>>({});

  const openModal = useCallback(
    <T extends Record<string, unknown>>(key: string, args: T | null = null): void =>
      setModalsRegistry(prevModalsRegistry => ({
        ...prevModalsRegistry,
        [key]: {
          isOpen: true,
          isDisabled: false,
          args,
        },
      })),
    [],
  );

  const closeModal = useCallback(
    (key: string): void =>
      setModalsRegistry(prevModalsRegistry => ({
        ...prevModalsRegistry,
        [key]: {
          isOpen: false,
          isDisabled: prevModalsRegistry[key]?.isDisabled || false,
          args: prevModalsRegistry[key]?.args || null,
        },
      })),
    [],
  );

  const setDisabled = useCallback(
    (key: string, value: boolean): void =>
      setModalsRegistry(prevModalsRegistry => ({
        ...prevModalsRegistry,
        [key]: {
          isOpen: prevModalsRegistry[key]?.isOpen || false,
          isDisabled: value,
          args: prevModalsRegistry[key]?.args || null,
        },
      })),
    [],
  );

  const setArgs = useCallback(
    (key: string, value: Record<string, unknown>): void =>
      setModalsRegistry(prevModalsRegistry => ({
        ...prevModalsRegistry,
        [key]: {
          isOpen: prevModalsRegistry[key]?.isOpen || false,
          isDisabled: prevModalsRegistry[key]?.isDisabled || false,
          args: {
            ...prevModalsRegistry[key]?.args,
            ...value,
          },
        },
      })),
    [],
  );

  const getModalState = useCallback(
    <T extends Record<string, unknown>>(key: string): ModalState<T> =>
      (modalsRegistry[key] as ModalState<T>) || {
        isOpen: false,
        disabled: false,
        args: null,
      },
    [modalsRegistry],
  );

  const contextValue: ModalsContextType = useMemo(
    () => ({
      openModal,
      closeModal,
      setDisabled,
      setArgs,
      getModalState,
    }),
    [closeModal, getModalState, openModal, setArgs, setDisabled],
  );

  return <ModalsContext.Provider value={contextValue}>{children}</ModalsContext.Provider>;
};
