import { useEffect, useState } from 'react';
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom';

import { useAuth } from '../../app/auth';
import apiClient from '../../api/client';
import { BackButton } from '../common/BackButton';

const userLinks = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/projects', label: 'Projects' },
  { to: '/reports', label: 'Reports' },
  { to: '/settings', label: 'Settings' },
];

const adminLinks = [
  { to: '/admin/dashboard', label: 'Admin Dashboard' },
  { to: '/admin/users', label: 'Admin Users' },
  { to: '/admin/projects', label: 'Admin Projects' },
  { to: '/admin/scans', label: 'Admin Scans' },
];

function MalwarePopup() {
  const [malwareAlerts, setMalwareAlerts] = useState([]);
  const [dismissed, setDismissed] = useState(() => sessionStorage.getItem('aegis_malware_dismissed') === '1');

  useEffect(() => {
    if (dismissed) return;
    apiClient.get('/scans/results/', { params: { page_size: 20 } })
      .then(({ data }) => {
        const results = data?.results || data || [];
        const alerts = results
          .filter((scan) => {
            const malware = scan?.raw_json?.detailed_report?.malware_summary;
            return malware?.detected;
          })
          .map((scan) => ({
            id: scan.id,
            projectName: scan.project_name,
            count: scan.raw_json?.detailed_report?.malware_summary?.issue_count || 0,
          }));
        setMalwareAlerts(alerts);
      })
      .catch(() => {});
  }, [dismissed]);

  const handleDismiss = () => {
    sessionStorage.setItem('aegis_malware_dismissed', '1');
    setDismissed(true);
  };

  if (dismissed || !malwareAlerts.length) return null;

  const alert = malwareAlerts[0];

  return (
    <div className="malware-popup">
      <div className="malware-popup-header">
        <div className="malware-popup-title">
          <span className="malware-popup-pulse" />
          ⚠️ Malware Detected
        </div>
        <button className="malware-popup-close" onClick={handleDismiss}>Dismiss</button>
      </div>
      <div className="malware-popup-body">
        <strong>{alert.projectName}</strong> has {alert.count || 'suspicious'} malware signal(s) that require <strong>immediate action</strong>.
        {malwareAlerts.length > 1 ? ` (+${malwareAlerts.length - 1} more project${malwareAlerts.length > 2 ? 's' : ''})` : ''}
      </div>
      <Link className="malware-popup-action" to={`/scans/${alert.id}`} onClick={handleDismiss}>
        View Scan Details →
      </Link>
    </div>
  );
}

export function AppShell() {
  const auth = useAuth();
  const navigate = useNavigate();
  const links = auth.isAdmin ? [...userLinks, ...adminLinks] : userLinks;

  const handleLogout = async () => {
    await auth.logout();
    navigate('/login');
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link to="/projects" className="brand-block" style={{ textDecoration: 'none', display: 'block' }}>
          <div className="brand-kicker" style={{ color: 'var(--muted)' }}>Local SaaS Security Scanner</div>
          <h1 style={{ color: 'var(--ink)', display: 'flex', alignItems: 'center', gap: '8px', marginTop: '8px', marginBottom: '8px' }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--brand)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            AEGIS AI
          </h1>
          <p style={{ color: 'var(--muted)', margin: 0 }}>Scan projects, track findings, and ship safer builds.</p>
        </Link>

        <nav className="sidebar-nav">
          {links.map((item) => (
            <NavLink key={item.to} to={item.to} className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <button className="ghost-button" onClick={handleLogout}>Logout</button>
      </aside>

      <main className="content-shell">
        <header className="topbar">
          <div className="topbar-meta">
            <BackButton fallbackTo={auth.isAdmin ? '/admin/dashboard' : '/dashboard'} />
            <div className="eyebrow">Signed in as</div>
            <div className="topbar-user">{auth.user?.name || auth.user?.email}</div>
          </div>
          <div className="role-pill">{auth.user?.role || 'user'}</div>
        </header>
        <section className="page-body">
          <Outlet />
        </section>
      </main>

      <MalwarePopup />
    </div>
  );
}
