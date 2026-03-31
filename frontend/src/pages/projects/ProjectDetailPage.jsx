import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import apiClient from '../../api/client';
import { Card, Loader, StatCard } from '../../components/common/UI';
import { DataTable, LinkCell, StatusBadge } from '../../components/tables/DataTable';
import { formatDateTime } from '../../utils/formatters';

function scanDetailText(scanMode) {
  if (scanMode === 'advanced') {
    return 'Analyzing GitHub, candidate APIs, and deeper technical issues.';
  }
  if (scanMode === 'server') {
    return 'Analyzing website posture, repositories, candidate APIs, and stored server-review context.';
  }
  return 'Collecting DNS, headers, TLS, public files, and surface-risk data.';
}

export function ProjectDetailPage() {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const [project, setProject] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanMessage, setScanMessage] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanLabel, setScanLabel] = useState('Preparing scan...');
  const [scanDetail, setScanDetail] = useState('');
  const progressTimer = useRef(null);

  const stopProgress = () => {
    if (progressTimer.current) {
      window.clearInterval(progressTimer.current);
      progressTimer.current = null;
    }
  };

  const startProgress = () => {
    stopProgress();
    progressTimer.current = window.setInterval(() => {
      setScanProgress((current) => {
        if (current >= 92) return current;
        if (current < 25) return current + 8;
        if (current < 55) return current + 6;
        if (current < 80) return current + 3;
        return current + 1;
      });
    }, 350);
  };

  useEffect(() => {
    return () => stopProgress();
  }, []);

  const loadData = async () => {
    setLoading(true);
    const [projectResponse, historyResponse] = await Promise.all([
      apiClient.get(`/projects/${projectId}/`),
      apiClient.get(`/projects/${projectId}/scan-history/`),
    ]);
    setProject(projectResponse.data);
    setHistory(historyResponse.data);
    setLoading(false);
  };

  useEffect(() => { loadData(); }, [projectId]);

  const triggerScan = async (sync = true) => {
    setScanning(true);
    setScanProgress(10);
    setScanLabel('Running security scan...');
    setScanDetail(scanDetailText(project?.scan_mode));
    startProgress();

    try {
      const { data } = await apiClient.post(`/projects/${projectId}/scan-now/`, { sync }, { timeout: sync ? 120000 : undefined });
      setScanProgress(100);
      setScanLabel('Scan complete');
      setScanDetail('Opening the detailed scan report.');
      stopProgress();
      setScanMessage(data.detail || 'Scan triggered');
      if (data.scan_result?.id) {
        navigate(`/scans/${data.scan_result.id}`);
        return;
      }
      await loadData();
    } finally {
      stopProgress();
      setScanning(false);
    }
  };

  const toggleSchedule = async () => {
    await apiClient.post(`/projects/${projectId}/toggle-schedule/`, { scan_enabled: !project.scan_enabled, scan_frequency: project.scan_frequency });
    await loadData();
  };

  if (loading) return <Loader label="Loading project detail..." />;

  if (scanning) {
    return (
      <div className="page-grid">
        <div className="page-header-row">
          <div>
            <div className="eyebrow">Project Detail</div>
            <h2>{project?.name || 'Security scan'}</h2>
            <p>{project?.domain || 'Preparing project scan'}</p>
          </div>
        </div>
        <Loader label={scanLabel} progress={scanProgress} detail={scanDetail} />
      </div>
    );
  }

  const frontendRepoUrl = project.frontend_github_url || project.github_url || 'N/A';
  const backendRepoUrl = project.backend_github_url || (frontendRepoUrl !== 'N/A' ? `${frontendRepoUrl} (same repo)` : 'N/A');

  return (
    <div className="page-grid">
      <div className="page-header-row">
        <div>
          <div className="eyebrow">Project Detail</div>
          <h2>{project.name}</h2>
          <p>{project.domain}</p>
        </div>
        <div className="button-row">
          <Link className="secondary-button" to={`/projects/${projectId}/edit`}>Edit</Link>
          <button className="primary-button" onClick={() => triggerScan(true)}>Scan Now</button>
          <button className="ghost-button" onClick={toggleSchedule}>{project.scan_enabled ? 'Disable Daily Scan' : 'Enable Daily Scan'}</button>
        </div>
      </div>
      {scanMessage ? <div className="alert success">{scanMessage}</div> : null}
      <div className="stats-grid">
        <StatCard label="Mode" value={project.scan_mode} />
        <StatCard label="API Endpoints" value={project.api_items_count} hint={`Base: ${project.effective_api_base_url || 'N/A'}`} />
        <StatCard label="Schedule" value={project.scan_enabled ? project.scan_frequency : 'manual'} hint={`Next: ${formatDateTime(project.next_scan_at)}`} />
        <StatCard label="Latest Status" value={project.latest_scan?.status || 'Not scanned'} hint={`Last scan: ${formatDateTime(project.last_scanned_at)}`} />
      </div>
      <Card title="Configuration">
        <div className="detail-grid">
          <div><strong>Scan Mode:</strong> {project.scan_mode}</div>
          <div><strong>Frontend Repo:</strong> {frontendRepoUrl || 'N/A'}</div>
          <div><strong>Backend Repo:</strong> {backendRepoUrl}</div>
          <div><strong>API Base:</strong> {project.effective_api_base_url || 'N/A'}</div>
          <div><strong>Stack:</strong> {project.stack_name || 'N/A'}</div>
          <div><strong>Notification Email:</strong> {project.notification_email || 'N/A'}</div>
          <div><strong>Test Account:</strong> {project.test_email || 'N/A'}</div>
          <div><strong>Has Test Password:</strong> {project.has_test_password ? 'Yes' : 'No'}</div>
          <div><strong>Server IP / Host:</strong> {project.server_ip_address || 'N/A'}</div>
          <div><strong>Has Server Password:</strong> {project.has_server_password ? 'Yes' : 'No'}</div>
          <div><strong>Token:</strong> {project.masked_token || 'N/A'}</div>
        </div>
      </Card>
      <DataTable
        columns={[
          { key: 'status', label: 'Status', render: (row) => <StatusBadge status={row.status} /> },
          { key: 'score', label: 'Score' },
          { key: 'vibe_score', label: 'Vibe' },
          { key: 'critical_count', label: 'Critical' },
          { key: 'started_at', label: 'Started', render: (row) => formatDateTime(row.started_at) },
          { key: 'open', label: 'Open', render: (row) => <LinkCell to={`/scans/${row.id}`}>Detailed report</LinkCell> },
        ]}
        rows={history}
      />
    </div>
  );
}
