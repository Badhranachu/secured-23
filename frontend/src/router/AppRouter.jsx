import { Navigate, Route, Routes } from 'react-router-dom';

import { useAuth } from '../app/auth';
import { AppShell } from '../components/layout/AppShell';
import { AdminDashboardPage } from '../pages/admin/AdminDashboardPage';
import { AdminProjectsPage } from '../pages/admin/AdminProjectsPage';
import { AdminScansPage } from '../pages/admin/AdminScansPage';
import { AdminUsersPage } from '../pages/admin/AdminUsersPage';
import { ForgotPasswordPage } from '../pages/auth/ForgotPasswordPage';
import { LoginPage } from '../pages/auth/LoginPage';
import { RegisterPage } from '../pages/auth/RegisterPage';
import { HomePage } from '../pages/home/HomePage';
import { ProjectDetailPage } from '../pages/projects/ProjectDetailPage';
import { ProjectFormPage } from '../pages/projects/ProjectFormPage';
import { ProjectListPage } from '../pages/projects/ProjectListPage';
import { ReportsPage } from '../pages/reports/ReportsPage';
import { ScanCodeReviewPage } from '../pages/scans/ScanCodeReviewPage';
import { ScanDetailPage } from '../pages/scans/ScanDetailPage';
import { SettingsPage } from '../pages/settings/SettingsPage';
import { UserDashboardPage } from '../pages/user/UserDashboardPage';

function ProtectedRoute({ children, adminOnly = false }) {
  const auth = useAuth();
  if (!auth.isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  if (adminOnly && !auth.isAdmin) {
    return <Navigate to="/dashboard" replace />;
  }
  return children;
}

function PublicRoute({ children }) {
  const auth = useAuth();
  if (auth.isAuthenticated) {
    return <Navigate to={auth.isAdmin ? '/admin/dashboard' : '/dashboard'} replace />;
  }
  return children;
}

export function AppRouter() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/login" element={<PublicRoute><LoginPage /></PublicRoute>} />
      <Route path="/register" element={<PublicRoute><RegisterPage /></PublicRoute>} />
      <Route path="/forgot-password" element={<PublicRoute><ForgotPasswordPage /></PublicRoute>} />

      <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
        <Route path="/dashboard" element={<UserDashboardPage />} />
        <Route path="/projects" element={<ProjectListPage />} />
        <Route path="/projects/new" element={<ProjectFormPage mode="create" />} />
        <Route path="/projects/:projectId/edit" element={<ProjectFormPage mode="edit" />} />
        <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
        <Route path="/scans/:scanId" element={<ScanDetailPage />} />
        <Route path="/scans/:scanId/code-review" element={<ScanCodeReviewPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/admin/dashboard" element={<ProtectedRoute adminOnly><AdminDashboardPage /></ProtectedRoute>} />
        <Route path="/admin/users" element={<ProtectedRoute adminOnly><AdminUsersPage /></ProtectedRoute>} />
        <Route path="/admin/projects" element={<ProtectedRoute adminOnly><AdminProjectsPage /></ProtectedRoute>} />
        <Route path="/admin/scans" element={<ProtectedRoute adminOnly><AdminScansPage /></ProtectedRoute>} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

