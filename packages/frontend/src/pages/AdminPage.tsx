import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import {
  Users,
  Shield,
  Server,
  Settings,
  Plus,
  Trash2,
  AlertCircle,
} from 'lucide-react';
import { clsx } from 'clsx';

type AdminTab = 'users' | 'sandbox' | 'yara' | 'system';

interface User {
  id: string;
  email: string;
  username: string;
  role: string;
  status: string;
  createdAt: string;
  lastLogin: string | null;
}

const roleBadgeColors: Record<string, string> = {
  admin: 'bg-red-900/30 text-red-400',
  malware_researcher: 'bg-purple-900/30 text-purple-400',
  threat_hunter: 'bg-blue-900/30 text-blue-400',
  soc_analyst: 'bg-green-900/30 text-green-400',
  incident_responder: 'bg-orange-900/30 text-orange-400',
  read_only: 'bg-gray-800 text-gray-400',
};

export function AdminPage() {
  const [tab, setTab] = useState<AdminTab>('users');
  const currentUser = useAuthStore((s) => s.user);
  const queryClient = useQueryClient();

  const { data: users } = useQuery<User[]>({
    queryKey: ['admin-users'],
    queryFn: async () => {
      const res = await api.get('/admin/users');
      const payload = res.data.data;
      return Array.isArray(payload) ? payload : (payload?.data ?? []);
    },
    enabled: tab === 'users',
  });

  const disableUser = useMutation({
    mutationFn: async (userId: string) => {
      await api.post(`/admin/users/${userId}/disable`);
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin-users'] }),
  });

  if (currentUser?.role !== 'admin' && currentUser?.role !== 'super_admin') {
    return (
      <div className="p-8 text-center">
        <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-3" />
        <p className="text-white font-medium">Access Denied</p>
        <p className="text-gray-400 mt-1">
          Administrator privileges required
        </p>
      </div>
    );
  }

  const tabs: Array<{ id: AdminTab; icon: typeof Users; label: string }> = [
    { id: 'users', icon: Users, label: 'Users' },
    { id: 'sandbox', icon: Server, label: 'Sandbox Fleet' },
    { id: 'yara', icon: Shield, label: 'YARA Rules' },
    { id: 'system', icon: Settings, label: 'System' },
  ];

  return (
    <div className="p-4 md:p-8">
      <div className="mb-6 md:mb-8">
        <h1 className="text-2xl font-bold text-white">Administration</h1>
        <p className="text-gray-400 mt-1">
          Manage users, sandbox fleet, and system settings
        </p>
      </div>

      <div className="flex gap-2 mb-6 border-b border-gray-800 pb-3">
        {tabs.map(({ id, icon: Icon, label }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={clsx(
              'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
              tab === id
                ? 'bg-scanboy-600/20 text-scanboy-400'
                : 'text-gray-400 hover:bg-gray-800',
            )}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {tab === 'users' && (
        <div>
          <div className="flex justify-end mb-4">
            <button className="flex items-center gap-2 px-4 py-2 bg-scanboy-600 hover:bg-scanboy-700 text-white text-sm font-medium rounded-lg transition-colors">
              <Plus className="w-4 h-4" />
              Create User
            </button>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                    User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                    Role
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                    Created
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {(users ?? []).map((user) => (
                  <tr key={user.id} className="hover:bg-gray-800/50">
                    <td className="px-6 py-4">
                      <p className="text-sm font-medium text-white">
                        {user.username}
                      </p>
                      <p className="text-xs text-gray-500">{user.email}</p>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={clsx(
                          'px-2 py-0.5 text-xs font-medium rounded',
                          roleBadgeColors[user.role] ?? 'bg-gray-800 text-gray-400',
                        )}
                      >
                        {user.role.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={clsx(
                          'text-xs font-medium',
                          user.status === 'active'
                            ? 'text-green-400'
                            : 'text-red-400',
                        )}
                      >
                        {user.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-400">
                      {new Date(user.createdAt).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 text-right">
                      {user.id !== currentUser?.id && (
                        <button
                          onClick={() => disableUser.mutate(user.id)}
                          className="p-1.5 text-gray-400 hover:text-red-400 transition-colors"
                          title="Disable user"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'sandbox' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center text-gray-500">
          <Server className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>Sandbox fleet management</p>
          <p className="text-sm mt-1">
            Configure VM templates, monitor active sandboxes, manage snapshots
          </p>
        </div>
      )}

      {tab === 'yara' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center text-gray-500">
          <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>YARA rule management</p>
          <p className="text-sm mt-1">
            Upload, test, version, and manage YARA rules
          </p>
        </div>
      )}

      {tab === 'system' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center text-gray-500">
          <Settings className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>System configuration</p>
          <p className="text-sm mt-1">
            API keys, integrations, threat intel providers, system health
          </p>
        </div>
      )}
    </div>
  );
}
