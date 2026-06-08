import axios from 'axios';

export const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  const stored = sessionStorage.getItem('fraudvault-auth');
  if (stored) {
    try {
      const { state } = JSON.parse(stored);
      if (state?.token) {
        config.headers.Authorization = `Bearer ${state.token}`;
      }
    } catch {
      // ignore parse errors
    }
  }
  return config;
});

let refreshPromise: Promise<string> | null = null;

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;

      const stored = sessionStorage.getItem('fraudvault-auth');
      let refreshToken: string | null = null;
      try {
        const { state } = JSON.parse(stored ?? '{}');
        refreshToken = state?.refreshToken ?? null;
      } catch { /* ignore */ }

      if (refreshToken) {
        try {
          // Deduplicate concurrent refresh calls
          if (!refreshPromise) {
            refreshPromise = axios
              .post('/api/v1/auth/refresh', { refreshToken })
              .then((res) => {
                const tokens = res.data?.data?.tokens;
                if (!tokens?.accessToken) throw new Error('No access token');

                // Update store
                const prev = JSON.parse(sessionStorage.getItem('fraudvault-auth') ?? '{}');
                prev.state = {
                  ...prev.state,
                  token: tokens.accessToken,
                  refreshToken: tokens.refreshToken ?? refreshToken,
                };
                sessionStorage.setItem('fraudvault-auth', JSON.stringify(prev));
                api.defaults.headers.common['Authorization'] = `Bearer ${tokens.accessToken}`;
                return tokens.accessToken as string;
              })
              .finally(() => { refreshPromise = null; });
          }

          const newToken = await refreshPromise;
          original.headers.Authorization = `Bearer ${newToken}`;
          return api(original);
        } catch {
          // Refresh failed — fall through to logout
        }
      }

      sessionStorage.removeItem('fraudvault-auth');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  },
);
