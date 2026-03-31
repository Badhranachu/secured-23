import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import apiClient from '../../api/client';
import { CategoryPieChart, LineMetricChart } from '../../components/charts/DashboardCharts';
import { Badge, Card, EmptyState, Loader, StatCard } from '../../components/common/UI';
import { DataTable, LinkCell, StatusBadge } from '../../components/tables/DataTable';
import { formatDateTime, formatScore } from '../../utils/formatters';

function certificateTone(days) {
  if (days === null || days === undefined) return 'neutral';
  if (days <= 15) return 'danger';
  if (days <= 45) return 'warning';
  return 'success';
}

function scoreTone(score) {
  if (score === null || score === undefined) return 'neutral';
  if (score < 40) return 'danger';
  if (score < 70) return 'warning';
  return 'success';
}

function riskTone(level) {
  if (level === 'CRITICAL') return 'danger';
  if (level === 'HIGH') return 'warning';
  return 'success';
}

export function UserDashboardPage() {
  const [summary, setSummary] = useState(null);
  const [domainSummary, setDomainSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      apiClient.get('/dashboard/user-summary/'),
      apiClient.get('/domain-scans/dashboard-summary/').catch(() => ({ data: null })),
    ])
      .then(([summaryResponse, domainSummaryResponse]) => {
        setSummary(summaryResponse.data);
        setDomainSummary(domainSummaryResponse?.data || null);
      })
      .finally(() => setLoading(false));
  }, []);

  const latestScan = summary?.scan_history?.[0] || null;
  const hasDomainMetrics = Boolean(domainSummary && (domainSummary.total_scans || domainSummary.average_risk_score || domainSummary.scan_count_by_day?.length));
  const certificateRows = useMemo(
    () => (domainSummary?.certificate_expiry_trend || []).map((item, index) => ({ id: `${item.domain}-${index}`, ...item })),
    [domainSummary],
  );
  const expiringSoonRows = useMemo(
    () => certificateRows.filter((item) => item.days_to_expiry !== null && item.days_to_expiry !== undefined && item.days_to_expiry <= 15),
    [certificateRows],
  );
  const highestRiskDomain = certificateRows[0] || null;

  if (loading) return <Loader label="Loading dashboard..." />;
  if (!summary) return <EmptyState title="No dashboard data" description="Create a project and run a scan to populate your dashboard." action={<Link className="primary-button" to="/projects/new">Create project</Link>} />;

  return (
    <div className="page-grid report-stack dashboard-shell">
      <section className="dashboard-hero card">
        <div className="dashboard-hero-copy">
          <div className="eyebrow">User Dashboard</div>
          <h2>Security posture at a glance</h2>
          <p>
            Track project health, review scan momentum, and spot certificate or risk issues before they become production incidents.
          </p>
          <div className="dashboard-hero-badges">
            <Badge tone={scoreTone(summary.current_security_score)}>Security score {formatScore(summary.current_security_score)}</Badge>
            <Badge tone={summary.critical_findings ? 'danger' : 'success'}>{summary.critical_findings} critical findings</Badge>
            <Badge tone="neutral">Next scan {summary.next_scheduled_scan ? formatDateTime(summary.next_scheduled_scan) : 'not scheduled'}</Badge>
          </div>
        </div>
        <div className="dashboard-hero-panel">
          <div className="dashboard-panel-label">Latest scan</div>
          {latestScan ? (
            <>
              <strong>{latestScan.project}</strong>
              <div className="dashboard-panel-row"><span>Status</span><StatusBadge status={latestScan.status} /></div>
              <div className="dashboard-panel-row"><span>Started</span><span>{formatDateTime(latestScan.started_at)}</span></div>
              <div className="dashboard-panel-row"><span>Score</span><span>{formatScore(latestScan.score)}</span></div>
              <div className="dashboard-panel-row"><span>Vibe</span><span>{formatScore(latestScan.vibe_score)}</span></div>
            </>
          ) : (
            <p className="note-text">No scans yet. Start from a project to generate dashboard metrics.</p>
          )}
          <div className="button-row">
            <Link className="primary-button" to="/projects/new">New Project</Link>
            <Link className="ghost-button" to="/projects">Open Projects</Link>
          </div>
        </div>
      </section>

      <div className="stats-grid">
        <StatCard label="Total Projects" value={summary.total_projects} hint={`Last scan: ${summary.last_scan_time ? formatDateTime(summary.last_scan_time) : 'No scans yet'}`} />
        <StatCard label="Security Score" value={formatScore(summary.current_security_score)} hint="Latest overall score across your projects" />
        <StatCard label="Vibe Risk Score" value={formatScore(summary.vibe_risk_score)} hint="Code-style and unsafe shortcut risk from the latest scan" />
        <StatCard label="Critical Findings" value={summary.critical_findings} hint={`Warnings: ${summary.warning_findings}`} />
      </div>

      {hasDomainMetrics ? (
        <section className="dashboard-watch-strip">
          <article className="dashboard-watch-card card">
            <div className="eyebrow">Certificate watch</div>
            <h3>{expiringSoonRows.length ? `${expiringSoonRows.length} domain${expiringSoonRows.length > 1 ? 's' : ''} need attention soon` : 'No urgent certificate expiries'}</h3>
            <p>
              {expiringSoonRows.length
                ? `The earliest certificate expiry is in ${expiringSoonRows[0].days_to_expiry} day${expiringSoonRows[0].days_to_expiry === 1 ? '' : 's'} for ${expiringSoonRows[0].domain}.`
                : 'Your latest successful domain scans are not showing any certificates expiring within the next 15 days.'}
            </p>
          </article>
          <article className="dashboard-watch-card card">
            <div className="eyebrow">Highest-risk domain snapshot</div>
            <h3>{highestRiskDomain ? highestRiskDomain.domain : 'No domain data yet'}</h3>
            <div className="dashboard-watch-metrics">
              <Badge tone={highestRiskDomain ? riskTone(highestRiskDomain.risk_level) : 'neutral'}>{highestRiskDomain?.risk_level || 'N/A'}</Badge>
              <Badge tone={highestRiskDomain ? scoreTone(highestRiskDomain.risk_score) : 'neutral'}>Score {formatScore(highestRiskDomain?.risk_score)}</Badge>
              <Badge tone={highestRiskDomain ? certificateTone(highestRiskDomain.days_to_expiry) : 'neutral'}>{highestRiskDomain?.days_to_expiry ?? 'N/A'} days left</Badge>
            </div>
            <p>{highestRiskDomain?.final_url || 'Run more domain scans to populate the watchlist and certificate status.'}</p>
          </article>
        </section>
      ) : null}

      <div className="grid-two dashboard-insight-grid">
        <LineMetricChart title="Security Score Over Time" data={summary.score_over_time || []} dataKey="score" color="#0f766e" />
        <LineMetricChart title="Vibe Risk Over Time" data={summary.vibe_over_time || []} dataKey="vibe_score" color="#dc2626" />
        <LineMetricChart title="Critical Findings Over Time" data={summary.critical_over_time || []} dataKey="critical_count" color="#b91c1c" />
        <CategoryPieChart title="Issue Category Distribution" data={summary.issue_category_breakdown || []} />
      </div>

      <Card title="Recent Scan Activity" className="dashboard-table-card">
        <DataTable
          columns={[
            { key: 'project', label: 'Project' },
            { key: 'status', label: 'Status', render: (row) => <StatusBadge status={row.status} /> },
            { key: 'score', label: 'Score', render: (row) => formatScore(row.score) },
            { key: 'vibe_score', label: 'Vibe', render: (row) => formatScore(row.vibe_score) },
            { key: 'critical_count', label: 'Critical' },
            { key: 'started_at', label: 'Started', render: (row) => formatDateTime(row.started_at) },
            { key: 'id', label: 'Open', render: (row) => <LinkCell to={`/scans/${row.id}`}>View scan</LinkCell> },
          ]}
          rows={summary.scan_history || []}
          emptyText="No scans yet. Trigger your first scan from a project detail page."
        />
      </Card>

      {hasDomainMetrics ? (
        <>
          <Card title="Domain Surface Scan Summary" className="dashboard-domain-summary">
            <div className="stats-grid compact-stats-grid">
              <StatCard label="Total Domain Scans" value={domainSummary.total_scans} hint={`Unique domains tracked: ${domainSummary.unique_domains_tracked || 0}`} />
              <StatCard label="Average Risk Score" value={formatScore(domainSummary.average_risk_score)} hint="Average across successful surface scans" />
              <StatCard label="High-Risk Domains" value={domainSummary.high_risk_domains_count} hint="Domains currently marked high or critical" />
              <StatCard label="Expiring Certificates" value={domainSummary.expiring_certificates_count} hint="Certificates expiring in 15 days or less" />
            </div>
          </Card>

          <div className="grid-two dashboard-insight-grid">
            <LineMetricChart title="Domain Risk Score Over Time" data={domainSummary.risk_score_over_time || []} dataKey="score" color="#0f766e" />
            <LineMetricChart title="Missing Security Headers" data={domainSummary.missing_headers_over_time || []} dataKey="missing_headers" color="#d97706" />
            <LineMetricChart title="Domain Scans By Day" data={domainSummary.scan_count_by_day || []} dataKey="total" color="#2563eb" />
            <Card title="Certificate Expiry Watchlist" className="dashboard-certificate-card">
              <p className="note-text">The table now keeps only the latest successful scan per host, so repeated scans and URL variants no longer show as separate rows.</p>
              <DataTable
                columns={[
                  {
                    key: 'domain',
                    label: 'Domain',
                    render: (row) => (
                      <div className="dashboard-domain-cell">
                        <strong>{row.domain}</strong>
                        <span>{row.final_url || row.raw_domain || 'No final URL recorded'}</span>
                      </div>
                    ),
                  },
                  { key: 'days_to_expiry', label: 'Days Left', render: (row) => <Badge tone={certificateTone(row.days_to_expiry)}>{row.days_to_expiry ?? 'N/A'}</Badge> },
                  { key: 'risk_level', label: 'Risk', render: (row) => <Badge tone={riskTone(row.risk_level)}>{row.risk_level || 'N/A'}</Badge> },
                  { key: 'risk_score', label: 'Score', render: (row) => formatScore(row.risk_score) },
                  { key: 'last_scanned_at', label: 'Last Scan', render: (row) => formatDateTime(row.last_scanned_at) },
                ]}
                rows={certificateRows}
                emptyText="No certificate expiry data is available yet."
              />
            </Card>
          </div>
        </>
      ) : null}
    </div>
  );
}
