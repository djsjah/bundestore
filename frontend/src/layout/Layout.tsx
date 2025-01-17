import { Outlet } from 'react-router-dom';

import { Header, Footer } from '@/components';

export const Layout: React.FC = () => {
  return (
    <div className="main-wrp flex flex-col max-w-7xl mx-auto border-2 border-zinc-900 h-full">
      <Header />
      <main className="flex-grow">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
};
