import { useEffect, useState } from 'react';

import apiClient from '../../api/client';
import { CategoryPieChart, LineMetricChart } from '../../components/charts/DashboardCharts';
import { Loader, StatCard } from '../../components/common/UI';
import { DataTable } from '../../components/tables/DataTable';
import { formatDateTime } from '../../utils/formatters';

export function AdminDashboardPage() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient.get('/dashboard/admin-summary/').then((response) => setSummary(response.data)).finally(() => setLoading(false));
  }, []);

  if (loading) return <Loader label="Loading admin dashboard..." />;
  if (!summary) return null;

  return (
    <div className="page-grid">
      <div className="page-header-row"><div><div className="eyebrow">Admin Dashboard</div><h2>Global platform analytics</h2></div></div>
      <div className="stats-grid">
        <StatCard label="Users" value={summary.total_users} />
        <StatCard label="Projects" value={summary.total_projects} />
        <StatCard label="Scans" value={summary.total_scans} />
        <StatCard label="Failed Scans" value={summary.failed_scans} hint={`Active projects: ${summary.active_projects}`} />
      </div>
      <div className="grid-two">
        <LineMetricChart title="Total Scans Per Day" data={summary.daily_scan_volume || []} dataKey="total" color="#2563eb" />
        <LineMetricChart title="Failed Scans Per Day" data={summary.daily_scan_volume || []} dataKey="failed" color="#dc2626" />
        <LineMetricChart title="Active Users Over Time" data={summary.active_users_over_time || []} dataKey="active_users" color="#0f766e" />
        <CategoryPieChart title="Most Common Issue Categories" data={summary.most_common_issue_types || []} />
      </div>
      <DataTable
        columns={[
          { key: 'project__name', label: 'Project' },
          { key: 'project__user__email', label: 'Owner' },
          { key: 'risk', label: 'Avg Score' },
          { key: 'last_scan', label: 'Last Scan', render: (row) => formatDateTime(row.last_scan) },
        ]}
        rows={summary.highest_risk_projects || []}
      />
    </div>
  );
}
