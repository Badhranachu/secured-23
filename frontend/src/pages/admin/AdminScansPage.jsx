import { useEffect, useState } from 'react';

import apiClient from '../../api/client';
import { Loader } from '../../components/common/UI';
import { DataTable, LinkCell, StatusBadge } from '../../components/tables/DataTable';
import { formatDateTime } from '../../utils/formatters';

export function AdminScansPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient.get('/scans/results/').then((response) => setScans(response.data.results || response.data)).finally(() => setLoading(false));
  }, []);

  if (loading) return <Loader label="Loading scans..." />;

  return <div className="page-grid"><div className="page-header-row"><div><div className="eyebrow">Admin Scans</div><h2>Global scan history</h2></div></div><DataTable columns={[{ key: 'project_name', label: 'Project', render: (row) => <LinkCell to={`/scans/${row.id}`}>{row.project_name}</LinkCell> }, { key: 'user_email', label: 'Owner' }, { key: 'status', label: 'Status', render: (row) => <StatusBadge status={row.status} /> }, { key: 'score', label: 'Score' }, { key: 'critical_count', label: 'Critical' }, { key: 'started_at', label: 'Started', render: (row) => formatDateTime(row.started_at) }]} rows={scans} /></div>;
}
