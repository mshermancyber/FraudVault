import { NavLink, useNavigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { useAuthStore } from '@/stores/authStore';
import { useDevice } from '@/contexts/DeviceContext';
import { clsx } from 'clsx';
import {
  LayoutDashboard,
  Upload,
  FileSearch,
  Search,
  MoreHorizontal,
  Shield,
  Settings,
  Database,
  LogOut,
  X,
} from 'lucide-react';

const primaryTabs = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/submit', icon: Upload, label: 'Submit' },
  { to: '/submissions', icon: FileSearch, label: 'Scans' },
  { to: '/search', icon: Search, label: 'Search' },
];

const secondaryItems = [
  { to: '/attack-matrix', icon: Shield, label: 'ATT&CK Matrix', adminOnly: false },
  { to: '/admin', icon: Settings, label: 'Admin', adminOnly: true },
  { to: '/feeds', icon: Database, label: 'Feeds', adminOnly: false },
  { to: '/yara', icon: Shield, label: 'YARA Rules', adminOnly: false },
];

export function MobileNav() {
  const [sheetOpen, setSheetOpen] = useState(false);
  const device = useDevice();
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = () => {
    setSheetOpen(false);
    logout();
    navigate('/login');
  };

  const isIos = device === 'ios';

  useEffect(() => {
    if (!sheetOpen) return;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = '';
    };
  }, [sheetOpen]);

  return (
    <>
      {/* Bottom Tab Bar */}
      <nav
        className={clsx(
          'fixed bottom-0 left-0 right-0 z-50 bg-gray-900 border-t border-gray-800',
          isIos && 'pb-[env(safe-area-inset-bottom)]',
        )}
      >
        <div className="flex items-stretch justify-around">
          {primaryTabs.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                clsx(
                  'flex flex-col items-center justify-center gap-0.5 py-2 min-w-[48px] min-h-[48px] flex-1 transition-colors',
                  isActive
                    ? 'text-scanboy-400'
                    : 'text-gray-500 active:text-gray-300',
                )
              }
            >
              <Icon className="w-5 h-5" />
              <span className="text-[10px] font-medium">{label}</span>
            </NavLink>
          ))}
          <button
            onClick={() => setSheetOpen(true)}
            className={clsx(
              'flex flex-col items-center justify-center gap-0.5 py-2 min-w-[48px] min-h-[48px] flex-1 transition-colors',
              sheetOpen ? 'text-scanboy-400' : 'text-gray-500 active:text-gray-300',
            )}
          >
            <MoreHorizontal className="w-5 h-5" />
            <span className="text-[10px] font-medium">More</span>
          </button>
        </div>
      </nav>

      {/* "More" Bottom Sheet */}
      {sheetOpen && (
        <div className="fixed inset-0 z-[60]" onClick={() => setSheetOpen(false)}>
          {/* Backdrop */}
          <div className="absolute inset-0 bg-black/60" />
          {/* Sheet */}
          <div
            className={clsx(
              'absolute bottom-0 left-0 right-0 bg-gray-900 border-t border-gray-800 animate-slide-up',
              isIos ? 'rounded-t-[20px] pb-[env(safe-area-inset-bottom)]' : 'rounded-t-2xl',
            )}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Drag indicator */}
            <div className="flex justify-center pt-3 pb-1">
              <div className="w-10 h-1 rounded-full bg-gray-700" />
            </div>

            {/* User info */}
            <div className="px-5 py-3 border-b border-gray-800">
              <p className="text-sm font-medium text-white">{user?.username}</p>
              <p className="text-xs text-gray-500">{user?.role}</p>
            </div>

            {/* Secondary nav items */}
            <div className="py-2">
              {secondaryItems.filter((item) => !item.adminOnly || user?.role === 'admin').map(({ to, icon: Icon, label }) => (
                <NavLink
                  key={to}
                  to={to}
                  onClick={() => setSheetOpen(false)}
                  className={({ isActive }) =>
                    clsx(
                      'flex items-center gap-4 px-5 py-3.5 min-h-[48px] transition-colors',
                      isActive
                        ? 'text-scanboy-400 bg-scanboy-600/10'
                        : 'text-gray-300 active:bg-gray-800',
                    )
                  }
                >
                  <Icon className="w-5 h-5" />
                  <span className="text-sm font-medium">{label}</span>
                </NavLink>
              ))}
            </div>

            {/* Logout */}
            <div className="border-t border-gray-800 py-2">
              <button
                onClick={handleLogout}
                className="flex items-center gap-4 px-5 py-3.5 min-h-[48px] w-full text-red-400 active:bg-gray-800 transition-colors"
              >
                <LogOut className="w-5 h-5" />
                <span className="text-sm font-medium">Sign Out</span>
              </button>
            </div>

            {/* Close button */}
            <div className="px-5 py-3">
              <button
                onClick={() => setSheetOpen(false)}
                className="w-full py-3 bg-gray-800 rounded-xl text-sm font-medium text-gray-300 active:bg-gray-700 min-h-[48px] flex items-center justify-center gap-2"
              >
                <X className="w-4 h-4" />
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
