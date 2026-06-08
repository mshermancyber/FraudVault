import { Outlet } from 'react-router-dom';
import { useDevice } from '@/contexts/DeviceContext';
import { MobileNav } from './MobileNav';
import { Lock } from 'lucide-react';
import { clsx } from 'clsx';

export function MobileLayout() {
  const device = useDevice();
  const isIos = device === 'ios';

  return (
    <div className="flex flex-col h-screen h-[100dvh]">
      {/* Mobile Header */}
      <header
        className={clsx(
          'shrink-0 bg-gray-900 border-b border-gray-800',
          isIos && 'pt-[env(safe-area-inset-top)]',
        )}
      >
        <div className="flex items-center gap-2 px-4 py-3">
          <Lock className="w-6 h-6 text-scanboy-500" />
          <h1 className="text-base font-bold text-white">FraudVault</h1>
        </div>
      </header>

      {/* Scrollable content area — bottom padding clears the tab bar */}
      <main
        className={clsx(
          'flex-1 overflow-auto bg-gray-950 pb-20',
          isIos && 'pb-[calc(5rem+env(safe-area-inset-bottom))]',
        )}
      >
        <Outlet />
      </main>

      <MobileNav />
    </div>
  );
}
