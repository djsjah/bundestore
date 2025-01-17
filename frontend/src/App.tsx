import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { AlertsProvider, ModalsProvider } from '@/providers';
import { AppRouter } from '@/router';
import { AlertBase } from '@/components';

const queryClient = new QueryClient();

export const App = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <ModalsProvider>
        <AlertsProvider>
          <AppRouter />
          <AlertBase />
        </AlertsProvider>
      </ModalsProvider>
    </QueryClientProvider>
  );
};
