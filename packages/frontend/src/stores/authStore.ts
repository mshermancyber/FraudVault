import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { api } from '@/lib/api';

interface User {
  id: string;
  email: string;
  username: string;
  role: string;
}

interface AuthState {
  token: string | null;
  refreshToken: string | null;
  user: User | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  setTokens: (token: string, refreshToken: string) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      refreshToken: null,
      user: null,
      isAuthenticated: false,
      login: async (email: string, password: string) => {
        const response = await api.post('/auth/login', { email, password });
        const { token, refreshToken, user } = response.data.data;
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        set({ token, refreshToken: refreshToken ?? null, user, isAuthenticated: true });
      },
      logout: async () => {
        const state = useAuthStore.getState();
        if (state.token) {
          try {
            await api.post('/auth/logout', { refreshToken: state.refreshToken });
          } catch {
            // Best-effort revocation — clear local state regardless
          }
        }
        delete api.defaults.headers.common['Authorization'];
        set({ token: null, refreshToken: null, user: null, isAuthenticated: false });
      },
      setTokens: (token: string, refreshToken: string) => {
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        set({ token, refreshToken });
      },
    }),
    {
      name: 'fraudvault-auth',
      version: 3,
      storage: {
        getItem: (name: string) => {
          const str = sessionStorage.getItem(name);
          return str ? JSON.parse(str) : null;
        },
        setItem: (name: string, value: unknown) => {
          sessionStorage.setItem(name, JSON.stringify(value));
        },
        removeItem: (name: string) => {
          sessionStorage.removeItem(name);
        },
      },
      migrate: (persisted: unknown, version: number) => {
        if (version < 3) {
          localStorage.removeItem('fraudvault-auth');
          return { token: null, refreshToken: null, user: null, isAuthenticated: false };
        }
        return persisted as AuthState;
      },
      partialize: (state) => ({
        token: state.token,
        refreshToken: state.refreshToken,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    },
  ),
);
