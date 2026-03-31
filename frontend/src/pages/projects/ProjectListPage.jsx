import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import apiClient from '../../api/client';
import { Badge, Card, Loader } from '../../components/common/UI';
import { DataTable, LinkCell, StatusBadge } from '../../components/tables/DataTable';
import { formatDateTime } from '../../utils/formatters';

function EmptyProjectModes() {
  return (
    <div className="page-grid">
      <div className="page-header-row">
        <div>
          <div className="eyebrow">Projects</div>
          <h2>Choose how you want to scan</h2>
          <p>Start with a fast domain-only pass, run the deeper GitHub + API discovery flow, or prepare a server review setup.</p>
        </div>
      </div>

      <div className="mode-card-grid">
        <Card className="choice-card" title="Basic Scan">
          <p>Enter only the domain. AEGIS AI will check reachability, TLS, headers, common exposure, and produce a quick risk summary.</p>
          <Link className="primary-button" to="/projects/new?mode=basic">Create Basic Project</Link>
        </Card>

        <Card className="choice-card" title="Advanced Scan">
          <p>Enter the domain and GitHub repo. AEGIS AI will try to discover working API routes, probe them safely, and create a detailed report.</p>
          <Link className="primary-button" to="/projects/new?mode=advanced">Create Advanced Project</Link>
        </Card>

        <Card className="choice-card" title="Server Scan">
          <p>Enter the domain, repo links, test account, and server access details so you can review malware exposure, APIs, and server issues.</p>
          <Link className="primary-button" to="/projects/new?mode=server">Create Server Project</Link>
        </Card>
      </div>
    </div>
  );
}

function scanProgressDetail(project) {
  if (project.scan_mode === 'advanced') {
    return `Analyzing ${project.name} for deeper technical issues.`;
  }
  if (project.scan_mode === 'server') {
    return `Reviewing ${project.name} with website, repo, API, and server-review context.`;
  }
  return `Collecting domain surface data for ${project.name}.`;
}

export function ProjectListPage() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [deletingId, setDeletingId] = useState(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);
  const [scanningId, setScanningId] = useState(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
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

  const loadProjects = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get('/projects/');
      setProjects(response.data.results || response.data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProjects();
  }, []);

  const handleDelete = async (project) => {
    if (confirmDeleteId !== project.id) {
      setConfirmDeleteId(project.id);
      return;
    }

    setConfirmDeleteId(null);
    setDeletingId(project.id);
    setMessage('');
    setError('');

    try {
      await apiClient.delete(`/projects/${project.id}/`);
      setProjects((current) => current.filter((item) => item.id !== project.id));
      setMessage(`Deleted "${project.name}".`);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Unable to delete the project.');
    } finally {
      setDeletingId(null);
    }
  };

  const handleScanNow = async (project) => {
    setScanningId(project.id);
    setScanProgress(10);
    setScanLabel('Running security scan...');
    setScanDetail(scanProgressDetail(project));
    setMessage('');
    setError('');
    startProgress();

    try {
      const { data } = await apiClient.post(`/projects/${project.id}/scan-now/`, { sync: true }, { timeout: 120000 });
      setScanProgress(100);
      setScanLabel('Scan complete');
      setScanDetail('Opening the detailed scan report.');
      stopProgress();
      if (data.scan_result?.id) {
        navigate(`/scans/${data.scan_result.id}`);
        return;
      }
      await loadProjects();
      setMessage(`Scan completed for "${project.name}".`);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Unable to run the scan for this project.');
    } finally {
      stopProgress();
      setScanningId(null);
    }
  };

  if (loading) return <Loader label="Loading projects..." />;
  if (!projects.length) return <EmptyProjectModes />;

  return (
    <div className="page-grid">
      <div className="page-header-row">
        <div><div className="eyebrow">Projects</div><h2>Tracked applications</h2></div>
        <div className="button-row">
          <Link className="secondary-button" to="/projects/new?mode=basic">Basic Project</Link>
          <Link className="secondary-button" to="/projects/new?mode=advanced">Advanced Project</Link>
          <Link className="primary-button" to="/projects/new?mode=server">Server Project</Link>
        </div>
      </div>
      {scanningId ? <Loader label={scanLabel} progress={scanProgress} detail={scanDetail} /> : null}
      {message ? <div className="alert success">{message}</div> : null}
      {error ? <div className="alert error">{error}</div> : null}
      <DataTable
        columns={[
          { key: 'name', label: 'Name', render: (row) => <LinkCell to={`/projects/${row.id}`}>{row.name}</LinkCell> },
          { key: 'scan_mode', label: 'Mode' },
          { key: 'domain', label: 'Domain' },
          { key: 'server_ip_address', label: 'Server Host', render: (row) => row.server_ip_address || 'N/A' },
          { key: 'scan_enabled', label: 'Schedule', render: (row) => row.scan_enabled ? 'Enabled' : 'Disabled' },
          { key: 'scan_frequency', label: 'Frequency' },
          { key: 'last_scanned_at', label: 'Last Scan', render: (row) => row.last_scanned_at ? formatDateTime(row.last_scanned_at) : 'Not scanned yet' },
          { key: 'next_scan_at', label: 'Next Scan', render: (row) => row.next_scan_at ? formatDateTime(row.next_scan_at) : 'Manual only' },
          {
            key: 'latest_scan',
            label: 'Latest Status',
            render: (row) => row.latest_scan ? <StatusBadge status={row.latest_scan.status} /> : <Badge>Not scanned</Badge>,
          },
          {
            key: 'actions',
            label: 'Action',
            render: (row) => (
              <div className="table-action-row">
                <button
                  type="button"
                  className="secondary-button table-action-button"
                  onClick={() => handleScanNow(row)}
                  disabled={scanningId === row.id || deletingId === row.id}
                >
                  {scanningId === row.id ? 'Scanning...' : 'Scan Now'}
                </button>
                <button
                  type="button"
                  className="danger-button table-action-button"
                  onClick={() => handleDelete(row)}
                  onMouseLeave={() => setConfirmDeleteId(null)}
                  disabled={deletingId === row.id || scanningId === row.id}
                >
                  {deletingId === row.id ? 'Deleting...' : (confirmDeleteId === row.id ? 'Sure?' : 'Delete')}
                </button>
              </div>
            ),
          },
        ]}
        rows={projects}
      />
    </div>
  );
}
