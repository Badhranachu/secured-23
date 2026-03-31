import { useEffect, useState } from 'react';

import apiClient from '../../api/client';
import { Loader } from '../../components/common/UI';
import { DataTable, LinkCell } from '../../components/tables/DataTable';
import { formatDateTime } from '../../utils/formatters';

export function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient.get('/reports/').then((response) => setReports(response.data.results || response.data)).finally(() => setLoading(false));
  }, []);

  if (loading) return <Loader label="Loading reports..." />;

  return (
    <div className="page-grid">
      <div className="page-header-row"><div><div className="eyebrow">Reports</div><h2>Generated PDFs</h2></div></div>
      <DataTable
        columns={[
          { key: 'project_name', label: 'Project' },
          { key: 'generated_at', label: 'Generated', render: (row) => formatDateTime(row.generated_at) },
          { key: 'download', label: 'Download', render: (row) => <a className="text-link" href={`${apiClient.defaults.baseURL}/reports/${row.id}/download/`} target="_blank" rel="noreferrer">Download PDF</a> },
          { key: 'scan_result', label: 'Scan', render: (row) => <LinkCell to={`/scans/${row.scan_result}`}>Open scan</LinkCell> },
        ]}
        rows={reports}
      />
    </div>
  );
}
