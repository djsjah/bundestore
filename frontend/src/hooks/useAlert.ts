import { useContext } from 'react';

import { AlertsContext } from '@/providers';

export const useAlert = () => useContext(AlertsContext);
