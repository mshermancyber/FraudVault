import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from '@/stores/authStore';
import { useDevice } from '@/contexts/DeviceContext';
import { isMobile } from '@/hooks/useDeviceType';
import { Layout } from '@/components/Layout';
import { MobileLayout } from '@/components/MobileLayout';
import { LoginPage } from '@/pages/LoginPage';
import { DashboardPage } from '@/pages/DashboardPage';
import { SubmissionsPage } from '@/pages/SubmissionsPage';
import { SubmissionDetailPage } from '@/pages/SubmissionDetailPage';
import { SubmitPage } from '@/pages/SubmitPage';
import { SearchPage } from '@/pages/SearchPage';
import { AttackMatrixPage } from '@/pages/AttackMatrixPage';
import { AdminPage } from '@/pages/AdminPage';
import { FeedsPage } from '@/pages/FeedsPage';
import { YaraPage } from '@/pages/YaraPage';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function AdminRoute({ children }: { children: React.ReactNode }) {
  const role = useAuthStore((s) => s.user?.role);
  if (role !== 'admin' && role !== 'super_admin') return <Navigate to="/" replace />;
  return <>{children}</>;
}

function AppLayout() {
  const device = useDevice();
  return isMobile(device) ? <MobileLayout /> : <Layout />;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="submissions" element={<SubmissionsPage />} />
        <Route path="submissions/:id" element={<SubmissionDetailPage />} />
        <Route path="submit" element={<SubmitPage />} />
        <Route path="search" element={<SearchPage />} />
        <Route path="attack-matrix" element={<AttackMatrixPage />} />
        <Route path="admin" element={<AdminRoute><AdminPage /></AdminRoute>} />
        <Route path="feeds" element={<FeedsPage />} />
        <Route path="yara" element={<YaraPage />} />
      </Route>
    </Routes>
  );
}
