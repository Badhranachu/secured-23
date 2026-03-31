import { useEffect, useState } from 'react';

import apiClient from '../../api/client';
import { Loader } from '../../components/common/UI';
import { DataTable, LinkCell } from '../../components/tables/DataTable';
import { formatDateTime } from '../../utils/formatters';

export function AdminProjectsPage() {
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient.get('/projects/').then((response) => setProjects(response.data.results || response.data)).finally(() => setLoading(false));
  }, []);

  if (loading) return <Loader label="Loading projects..." />;

  return <div className="page-grid"><div className="page-header-row"><div><div className="eyebrow">Admin Projects</div><h2>All tracked projects</h2></div></div><DataTable columns={[{ key: 'name', label: 'Project', render: (row) => <LinkCell to={`/projects/${row.id}`}>{row.name}</LinkCell> }, { key: 'domain', label: 'Domain' }, { key: 'user', label: 'Owner ID' }, { key: 'scan_enabled', label: 'Schedule', render: (row) => row.scan_enabled ? 'Enabled' : 'Disabled' }, { key: 'next_scan_at', label: 'Next Scan', render: (row) => formatDateTime(row.next_scan_at) }, { key: 'updated_at', label: 'Updated', render: (row) => formatDateTime(row.updated_at) }]} rows={projects} /></div>;
}
