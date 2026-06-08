import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuthStore } from '@/stores/authStore';
import {
  Database,
  LayoutDashboard,
  Upload,
  FileSearch,
  Search,
  Shield,
  Settings,
  LogOut,
  Lock,
} from 'lucide-react';
import { clsx } from 'clsx';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', adminOnly: false },
  { to: '/submit', icon: Upload, label: 'Submit', adminOnly: false },
  { to: '/submissions', icon: FileSearch, label: 'Submissions', adminOnly: false },
  { to: '/search', icon: Search, label: 'Search', adminOnly: false },
  { to: '/attack-matrix', icon: Shield, label: 'ATT&CK Matrix', adminOnly: false },
  { to: '/admin', icon: Settings, label: 'Admin', adminOnly: true },
  { to: '/feeds', icon: Database, label: 'Feeds', adminOnly: false },
  { to: '/yara', icon: Shield, label: 'YARA Rules', adminOnly: false },
];

export function Layout() {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="flex h-screen">
      <aside className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="p-4 border-b border-gray-800">
          <div className="flex items-center gap-2">
            <Lock className="w-8 h-8 text-scanboy-500" />
            <div>
              <h1 className="text-lg font-bold text-white">FraudVault</h1>
              <p className="text-xs text-scanboy-400/70">Contain. Analyze. Convict.</p>
            </div>
          </div>
        </div>
        <nav className="flex-1 p-3 space-y-1">
          {navItems.filter((item) => !item.adminOnly || user?.role === 'admin').map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-scanboy-600/20 text-scanboy-400'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200',
                )
              }
            >
              <Icon className="w-5 h-5" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-gray-800">
          <div className="flex items-center justify-between px-3 py-2">
            <div className="min-w-0">
              <p className="text-sm font-medium text-gray-200 truncate">
                {user?.username}
              </p>
              <p className="text-xs text-gray-500 truncate">{user?.role}</p>
            </div>
            <button
              onClick={handleLogout}
              className="p-1.5 text-gray-400 hover:text-red-400 transition-colors"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>
      <main className="flex-1 overflow-auto bg-gray-950">
        <Outlet />
      </main>
    </div>
  );
}
