import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import apiClient from '../../api/client';
import { CategoryPieChart } from '../../components/charts/DashboardCharts';
import { Badge, Card, Loader, StatCard } from '../../components/common/UI';
import { hasCodeChangeSuggestions } from '../../components/scans/CodeChangeWorkbench';
import { DataTable, SeverityBadge, StatusBadge } from '../../components/tables/DataTable';
import { formatDateTime } from '../../utils/formatters';

const severityRank = { critical: 0, warning: 1, info: 2 };

function summarizeCheck(check) {
  const metadata = check?.metadata || {};
  switch (check?.name) {
    case 'domain_headers':
      return metadata.final_url ? `Reached ${metadata.final_url} with status ${metadata.status_code || 'Not available'}` : 'Domain check summary unavailable';
    case 'ssl_tls':
      return metadata.tls_version ? `TLS ${metadata.tls_version}${metadata.days_remaining !== undefined ? `, ${metadata.days_remaining} days remaining` : ''}` : 'TLS probe unavailable';
    case 'github_repository':
      if (metadata.failed_repo_count) {
        return `Scanned ${metadata.scanned_file_count || 0} files, discovered ${metadata.discovered_route_count || 0} candidate routes, and ${metadata.failed_repo_count} repository scan(s) failed`;
      }
      return `Scanned ${metadata.scanned_file_count || 0} files, discovered ${metadata.discovered_route_count || 0} candidate routes`;
    case 'api_inventory':
      return `Prepared ${metadata.candidate_endpoint_count || 0} candidate endpoints against ${metadata.effective_api_base_url || 'Not available'}`;
    case 'api_endpoints':
      return `${metadata.working_count || 0} working endpoints, ${metadata.public_count || 0} public, ${metadata.protected_count || 0} protected`;
    case 'vibe_code':
      return `Scanned ${metadata.sample_count || 0} code samples for risky AI-style shortcuts`;
    case 'jwt_token':
      return metadata.expires_at ? `JWT expires at ${metadata.expires_at}` : 'JWT decoded';
    case 'test_auth':
      if (!metadata.attempted) return 'No test-account credentials were supplied, so login testing was not attempted';
      return metadata.authenticated ? 'Test account login succeeded and returned a token' : 'Test account login did not return a token';
    case 'credential_strength':
      return `Test password ${metadata.test_password?.label || 'Not available'}, server password ${metadata.server_password?.label || 'Not available'}`;
    case 'domain_normalization':
      return `Normalized to ${metadata.normalized_domain || 'hostname unavailable'}`;
    case 'dns_information':
      return metadata.zone_lookup_name && metadata.zone_lookup_name !== metadata.host_lookup_name
        ? `Collected host DNS for ${metadata.host_lookup_name} and email-auth records for ${metadata.zone_lookup_name}`
        : 'Collected public DNS and email-auth records for the domain';
    case 'http_https':
      return `HTTP ${metadata.http_status || 'Not available'}, HTTPS ${metadata.https_status || 'Not available'}, final URL ${metadata.final_url || 'Not available'}`;
    case 'security_headers':
      return `${metadata.missing_count || 0} missing headers, ${metadata.weak_count || 0} weak headers`;
    case 'tls_information':
      return metadata.days_to_expiry !== undefined && metadata.days_to_expiry !== null ? `Certificate issuer captured, ${metadata.days_to_expiry} days to expiry` : 'TLS metadata unavailable';
    case 'certificate_transparency':
      return `${metadata.count || 0} public hostnames discovered from certificate history`;
    case 'public_files':
      return `Checked public files and homepage metadata${metadata.title ? ` for ${metadata.title}` : ''}`;
    case 'email_security':
      return `MX ${metadata.mx_present ? 'present' : 'not found'}, SPF ${metadata.spf_present ? 'present' : 'not found'}, DMARC ${metadata.dmarc_present ? 'present' : 'not found'}`;
    case 'fingerprinting':
      return `${(metadata.hosting_clues || []).join(', ') || 'Minimal hosting clues'}, confidence ${metadata.confidence || 'low'}`;
    default:
      return 'Detailed metadata recorded in scan payload';
  }
}

function asText(value, fallback = 'Not available') {
  if (value === null || value === undefined || value === '') return fallback;
  if (Array.isArray(value)) return value.length ? value.join(', ') : fallback;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return `${value}`;
}

function realWorldExampleForFinding(item) {
  const title = `${item?.title || ''}`.toLowerCase();
  const category = `${item?.category || ''}`.toLowerCase();
  if (title.includes('content-security-policy') || title.includes('csp') || category === 'security_headers') {
    return 'A third-party chat widget or ad script could inject malicious JavaScript and steal sessions.';
  }
  if (title.includes('spf') || title.includes('dmarc') || title.includes('email')) {
    return 'Attackers could send fake invoice or password-reset emails that look like they came from your domain.';
  }
  if (title.includes('https') || title.includes('tls') || title.includes('certificate')) {
    return 'Someone on public Wi-Fi could read or tamper with traffic if transport protections are weak.';
  }
  if (title.includes('admin') || title.includes('auth') || category === 'auth_checks' || category === 'api_endpoints') {
    return 'A leaked token or weak role check could let someone open admin or sensitive API routes.';
  }
  if (title.includes('secret') || category === 'github_secrets') {
    return 'A leaked API key can be reused to access your services or cloud resources.';
  }
  return 'An attacker could use this weakness to move deeper into the app or expose user data.';
}

function distinctNarrativeFindings(vulnerabilities = [], limit = 3) {
  const seen = new Set();
  return [...vulnerabilities]
    .sort((left, right) => (severityRank[left.severity] ?? 99) - (severityRank[right.severity] ?? 99))
    .filter((item) => {
      const key = `${(item.title || '').toLowerCase()}|${(item.category || '').toLowerCase()}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, limit);
}

function buildConciseNarrative(scan, vulnerabilities = []) {
  const projectName = scan?.project_name || 'This project';
  const critical = scan?.critical_count || 0;
  const warning = scan?.warning_count || 0;
  if (!vulnerabilities.length) {
    return `${projectName} completed its scan successfully. No detailed issue narrative was stored for this run.`;
  }

  const topItems = distinctNarrativeFindings(vulnerabilities, 2);
  const headline = `${projectName} has ${critical} critical and ${warning} warning issues that need attention.`;
  const bullets = topItems.map((item, index) => `${index + 1}. ${item.title}: ${realWorldExampleForFinding(item)}`);
  return [headline, ...bullets].join('\n');
}

function buildThreatStory(scan, vulnerabilities = []) {
  const projectName = scan?.project_name || 'This project';
  const topItems = distinctNarrativeFindings(vulnerabilities, 2);
  if (!topItems.length) {
    return `${projectName} did not store enough evidence to build a threat story for this run.`;
  }

  const opening = topItems[0] ? realWorldExampleForFinding(topItems[0]) : 'An attacker could turn a small weakness into a larger compromise.';
  const followUp = topItems[1] ? realWorldExampleForFinding(topItems[1]) : 'If left unresolved, the issue could expand from exposure into service abuse or data loss.';
  return `${opening} ${followUp}`;
}

function normalizeDnsRecord(record) {
  if (Array.isArray(record)) {
    return {
      status: record.length ? 'success' : 'not_found',
      ttl: null,
      values: record,
    };
  }

  if (record && typeof record === 'object') {
    return {
      status: record.status || (record.values?.length ? 'success' : 'not_found'),
      ttl: record.ttl ?? null,
      values: record.values || [],
    };
  }

  return { status: 'not_available', ttl: null, values: [] };
}

function formatDnsValues(values) {
  if (!values || !values.length) return 'Not found';
  return values.map((item) => {
    if (typeof item === 'string') return item;
    if (item && typeof item === 'object') {
      if (item.priority !== undefined && item.exchange) return `${item.priority} ${item.exchange}`;
      return Object.values(item).join(' / ');
    }
    return `${item}`;
  }).join(', ');
}

function remediationOwnerForFinding(item) {
  const category = (item?.category || '').toLowerCase();
  const title = (item?.title || '').toLowerCase();
  const description = (item?.description || '').toLowerCase();

  if (item?.file_path) return 'code';
  if (['github_code', 'github_secrets', 'dependency_hygiene', 'vibe_code', 'auth_checks', 'api_endpoints'].includes(category)) return 'code';
  if (['dns_information', 'email_security', 'tls_information', 'ssl_tls', 'certificate_transparency'].includes(category)) return 'manual';
  if (category === 'public_files' || category === 'security_headers') return 'code';
  if (title.includes('spf') || title.includes('dmarc') || title.includes('certificate') || title.includes('dns') || description.includes('dns ') || description.includes('hosting')) return 'manual';
  return item?.endpoint ? 'code' : 'manual';
}

function remediationLabel(owner) {
  return owner === 'code' ? 'Code / config' : 'Manual / infra';
}

function remediationTone(owner) {
  return owner === 'code' ? 'success' : 'warning';
}

function locationForFinding(item) {
  return item?.file_path || item?.endpoint || item?.evidence?.evidence_source || 'General surface finding';
}

function HeaderStatusBadge({ item }) {
  const normalized = item.classification || item.status || 'not_available';
  const tone = normalized === 'acceptable' || normalized === 'success'
    ? 'success'
    : normalized === 'weak' || normalized === 'partial'
      ? 'warning'
      : normalized === 'missing' || normalized === 'check_failed'
        ? 'danger'
        : 'neutral';
  return <Badge tone={tone}>{normalized.replace(/_/g, ' ')}</Badge>;
}

function SectionStatus({ label, status }) {
  return (
    <div className="detail-pair">
      <strong>{label}:</strong> <StatusBadge status={status} />
    </div>
  );
}

function passwordStrengthTone(level) {
  if (level === 'strong' || level === 'good') return 'success';
  if (level === 'fair') return 'warning';
  if (level === 'weak') return 'danger';
  return 'neutral';
}

function PasswordStrengthSummaryCard({ title, strength, accountHint }) {
  const suggestions = (strength?.suggestions || []).slice(0, 3);
  const score = strength?.score || 0;
  const maxScore = strength?.max_score || 6;
  const fillWidth = Math.max(10, Math.round((score / maxScore) * 100));
  const level = strength?.level || 'not_available';

  return (
    <Card title={title}>
      <div className="password-strength-report">
        <div className="password-strength-report-top">
          <Badge tone={passwordStrengthTone(level)}>{strength?.label || 'Not available'}</Badge>
          <span>{accountHint}</span>
        </div>
        <div className="password-strength-track">
          <div className={`password-strength-fill ${level}`} style={{ width: `${fillWidth}%` }} />
        </div>
        <p className="note-text">{strength?.summary || 'No password was stored for this credential.'}</p>
        <ul className="risk-list">
          {suggestions.length ? suggestions.map((tip) => <li key={tip}>{tip}</li>) : <li>No extra improvements recorded.</li>}
        </ul>
      </div>
    </Card>
  );
}

function scrollToSection(sectionId) {
  const element = document.getElementById(sectionId);
  if (!element) return;
  element.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

export function ScanDetailPage() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient.get(`/scans/results/${scanId}/`).then((response) => setScan(response.data)).finally(() => setLoading(false));
  }, [scanId]);

  const [reporting, setReporting] = useState(false);
  const [reportError, setReportError] = useState('');

  const generateReport = async () => {
    setReporting(true);
    setReportError('');
    try {
      const { data } = await apiClient.post(`/scans/results/${scanId}/generate-report/`);
      const downloadResponse = await apiClient.get(`/reports/${data.id}/download/`, { responseType: 'blob', timeout: 120000 });
      
      const blob = new Blob([downloadResponse.data], { type: 'application/pdf' });
      if (blob.size < 100) {
        throw new Error('The generated PDF appears to be empty or invalid.');
      }

      const disposition = downloadResponse.headers['content-disposition'] || '';
      const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
      const filename = filenameMatch?.[1] || `scan-report-${scanId}.pdf`;
      const blobUrl = window.URL.createObjectURL(blob);
      
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(blobUrl);
    } catch (err) {
      console.error('PDF generation failed:', err);
      setReportError('Unable to generate or download the PDF report.');
    } finally {
      setReporting(false);
    }
  };

  const checks = scan?.raw_json?.checks || [];
  const detailedReport = scan?.raw_json?.detailed_report || {};
  const surfaceScan = scan?.raw_json?.surface_scan || {};
  const vulnerabilities = scan?.vulnerabilities || [];
  const isSurfaceScan = Boolean((surfaceScan && Object.keys(surfaceScan).length) || detailedReport.dns || detailedReport.public_files);

  const workingEndpoints = detailedReport.working_endpoints || [];
  const endpointResults = detailedReport.endpoint_results || [];
  const discoveredRoutes = detailedReport.discovered_routes || [];
  const candidateEndpoints = detailedReport.candidate_endpoints || [];
  const githubSummary = detailedReport.github || {};

  const dnsSnapshot = detailedReport.dns || surfaceScan.dns || {};
  const dnsStatus = detailedReport.dns_status || surfaceScan.dns_status || {};
  const redirectSnapshot = detailedReport.redirects || surfaceScan.redirects || surfaceScan.reachability?.redirect_analysis || {};
  const headerSnapshot = detailedReport.headers || surfaceScan.headers || {};
  const tlsSnapshot = detailedReport.tls || surfaceScan.tls || {};
  const tlsStatus = detailedReport.tls_status || surfaceScan.tls_status || {};
  const ctSnapshot = detailedReport.certificate_transparency || surfaceScan.certificate_transparency || {};
  const ctStatus = detailedReport.ct_status || surfaceScan.ct_status || {};
  const publicFiles = detailedReport.public_files || surfaceScan.public_files || {};
  const publicValidation = detailedReport.public_file_validation || publicFiles.files || {};
  const fingerprint = detailedReport.fingerprint || surfaceScan.fingerprint || {};
  const emailSecurity = detailedReport.email_security || surfaceScan.email_security || {};
  const timing = detailedReport.timing || surfaceScan.timing || {};
  const credentialSecurity = detailedReport.credential_security || {};
  const malwareSummary = detailedReport.malware_summary || {};
  const riskPayload = surfaceScan.risk || {};
  const recommendations = detailedReport.recommendations || riskPayload.top_recommendations || riskPayload.recommendations || [];
  const topFindings = detailedReport.top_findings || riskPayload.top_findings || [];
  const scoringBreakdown = detailedReport.scoring_breakdown || riskPayload.scoring_breakdown || [];
  const openIssueCount = vulnerabilities.length;

  const checkRows = useMemo(() => checks.map((check, index) => ({ id: `${check.name}-${index}`, name: check.name, status: check.status || 'not_available', summary: summarizeCheck(check) })), [checks]);
  const dnsRows = useMemo(() => {
    const records = dnsSnapshot.records || {};
    return [
      { id: 'a', record: 'A', ...normalizeDnsRecord(records.a) },
      { id: 'aaaa', record: 'AAAA', ...normalizeDnsRecord(records.aaaa) },
      { id: 'cname', record: 'CNAME', ...normalizeDnsRecord(records.cname) },
      { id: 'mx', record: 'MX', ...normalizeDnsRecord(records.mx) },
      { id: 'ns', record: 'NS', ...normalizeDnsRecord(records.ns) },
      { id: 'txt', record: 'TXT', ...normalizeDnsRecord(records.txt) },
      { id: 'dmarc', record: 'DMARC', ...normalizeDnsRecord(records.dmarc) },
    ].map((row) => ({ ...row, valuesLabel: formatDnsValues(row.values) }));
  }, [dnsSnapshot]);
  const headerRows = useMemo(() => (headerSnapshot.evaluations || []).map((item) => ({ ...item, id: item.name })), [headerSnapshot]);
  const ctRows = useMemo(() => {
    if (ctSnapshot.hostnames?.length) {
      return ctSnapshot.hostnames.map((hostname, index) => ({ id: `${hostname}-${index}`, hostname, source: ctSnapshot.ct_source || 'crt.sh', status: 'public cert history only; may not be live' }));
    }
    return (ctSnapshot.discovered || []).map((item, index) => ({ id: `${item.hostname}-${index}`, ...item }));
  }, [ctSnapshot]);
  const publicFileRows = useMemo(() => Object.entries(publicValidation || {}).map(([path, details]) => ({
    id: path,
    path,
    status: details.status || (details.is_valid_expected_file ? 'success' : 'not_available'),
    status_code: details.status_code,
    final_url: details.final_url,
    content_type: details.content_type,
    content_length: details.content_length,
    is_valid_expected_file: details.is_valid_expected_file,
    validation_notes: (details.validation_notes || []).join('; ') || 'No notes recorded',
  })), [publicValidation]);
  const timingRows = useMemo(() => Object.entries(timing || {}).map(([key, value]) => ({
    id: key,
    metric: key.replace(/_/g, ' '),
    value: value === null || value === undefined ? 'Not available' : `${value}`,
  })), [timing]);
  const scoringRows = useMemo(() => (scoringBreakdown || []).map((item, index) => ({ id: `${item.key || index}-${index}`, ...item })), [scoringBreakdown]);
  const githubRepoRows = useMemo(() => (githubSummary.repos || []).map((repo, index) => ({
    id: `${repo.label || index}-${index}`,
    label: repo.label || 'repository',
    repo: repo.repo || repo.url || 'Not available',
    status: repo.status || 'success',
    scanned_file_count: repo.scanned_file_count ?? 0,
    discovered_route_count: repo.discovered_route_count ?? 0,
    default_branch: repo.default_branch || 'Not available',
  })), [githubSummary]);
  const githubRepoErrors = useMemo(() => (githubSummary.repos || []).filter((repo) => repo.error).map((repo) => ({
    id: `${repo.label}-${repo.repo || repo.url || 'repo'}`,
    label: repo.label || 'repository',
    repo: repo.repo || repo.url || 'Not available',
    error: repo.error,
  })), [githubSummary]);
  const endpointRows = useMemo(() => (endpointResults || []).map((item, index) => ({
    id: `${item.route || index}-${index}`,
    ...item,
  })), [endpointResults]);
  const githubIssueRows = useMemo(() => vulnerabilities.filter((item) => ['github_secrets', 'github_code', 'github_malware', 'dependency_hygiene', 'vibe_code'].includes(item.category)).map((item) => ({
    id: item.id,
    severity: item.severity,
    category: item.category,
    title: item.title,
    file_path: item.file_path || 'Not available',
    description: item.description,
    recommendation: item.recommendation || 'Not available',
  })), [vulnerabilities]);
  const evidenceRows = useMemo(() => vulnerabilities.map((item) => ({
    id: item.id,
    severity: item.severity,
    title: item.title,
    category: item.category,
    observed_value: item.evidence?.observed_value || item.evidence?.value || 'Not available',
    expected_value: item.evidence?.expected_value || 'Not available',
    evidence_source: item.evidence?.evidence_source || 'Not available',
    module_name: item.evidence?.module_name || 'Not available',
    confidence: item.evidence?.confidence || 'Not available',
    recommendation: item.recommendation || 'Not available',
  })), [vulnerabilities]);
  const severityChartData = useMemo(() => {
    if (vulnerabilities.length) {
      const counts = vulnerabilities.reduce((accumulator, item) => {
        accumulator[item.severity] = (accumulator[item.severity] || 0) + 1;
        return accumulator;
      }, {});
      return [
        { name: 'Critical', value: counts.critical || 0 },
        { name: 'Warning', value: counts.warning || 0 },
        { name: 'Info', value: counts.info || 0 },
      ].filter((item) => item.value > 0);
    }

    return [
      { name: 'Critical', value: scan?.critical_count || 0 },
      { name: 'Warning', value: scan?.warning_count || 0 },
      { name: 'Info', value: scan?.info_count || 0 },
    ].filter((item) => item.value > 0);
  }, [scan, vulnerabilities]);
  const remediationBreakdown = useMemo(() => vulnerabilities.reduce((accumulator, item) => {
    const owner = remediationOwnerForFinding(item);
    accumulator[owner] = (accumulator[owner] || 0) + 1;
    return accumulator;
  }, { code: 0, manual: 0 }), [vulnerabilities]);
  const remediationChartData = useMemo(() => ([
    { name: 'Code / config', value: remediationBreakdown.code || 0 },
    { name: 'Manual / infra', value: remediationBreakdown.manual || 0 },
  ].filter((item) => item.value > 0)), [remediationBreakdown]);
  const codeFixPercent = openIssueCount ? Math.round(((remediationBreakdown.code || 0) / openIssueCount) * 100) : 0;
  const manualFixPercent = openIssueCount ? Math.round(((remediationBreakdown.manual || 0) / openIssueCount) * 100) : 0;
  const hasPushableCodeSuggestions = hasCodeChangeSuggestions(scan, vulnerabilities);
  const conciseNarrative = useMemo(() => buildConciseNarrative(scan, vulnerabilities), [scan, vulnerabilities]);
  const malwareFindings = useMemo(() => vulnerabilities.filter((item) => item.category === 'github_malware'), [vulnerabilities]);
  const threatStory = useMemo(() => buildThreatStory(scan, vulnerabilities), [scan, vulnerabilities]);
  const hasCodeFixCoverageWithoutMappedFiles = !hasPushableCodeSuggestions && (remediationBreakdown.code || 0) > 0;

  const [currentStage, setCurrentStage] = useState(0);
  const [healAccepted, setHealAccepted] = useState(false);
  const stageLabels = ['Overview', 'Deep Analysis', 'Security Findings', 'Heal & Accept'];
  const healPercent = healAccepted ? codeFixPercent : 0;

  const handleSeveritySliceClick = (entry) => {
    const sectionMap = {
      critical: 'remediation-steps',
      warning: 'remediation-steps',
      info: 'remediation-steps',
    };
    const normalized = `${entry?.name || ''}`.toLowerCase();
    scrollToSection(sectionMap[normalized] || 'remediation-steps');
  };

  const handleOwnershipSliceClick = (entry) => {
    const normalized = `${entry?.name || ''}`.toLowerCase();
    if (normalized.includes('code')) {
      scrollToSection('github-scan-summary');
      return;
    }
    scrollToSection('remediation-steps');
  };

  const remediationSteps = useMemo(() => {
    const seen = new Set();
    return vulnerabilities
      .slice()
      .sort((left, right) => (severityRank[left.severity] ?? 99) - (severityRank[right.severity] ?? 99))
      .map((item) => {
        const key = `${item.title}|${item.file_path}|${item.endpoint}|${item.recommendation}`;
        if (seen.has(key)) return null;
        seen.add(key);
        const owner = remediationOwnerForFinding(item);
        return {
          id: item.id,
          owner,
          severity: item.severity,
          title: item.title,
          why: item.description || item.evidence?.observed_value || 'No additional context was recorded.',
          action: item.recommendation || 'Review the issue and apply the appropriate remediation.',
          location: locationForFinding(item),
          category: item.category,
        };
      })
      .filter(Boolean)
      .slice(0, 10);
  }, [vulnerabilities]);

  if (loading) return <Loader label="Loading scan detail..." />;
  if (!scan) return null;

  return (
    <div className="page-grid report-stack healing-wrapper">
      <div className="page-header-row">
        <div>
          <div className="eyebrow">Detailed Scan Report</div>
          <h2>{scan.project_name}</h2>
          <p>{scan.raw_json?.scan_mode ? `${scan.raw_json.scan_mode} mode scan` : 'Security scan report'}</p>
        </div>
        <div className="button-row" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '8px' }}>
          <button className="secondary-button" onClick={generateReport} disabled={reporting}>
            {reporting ? 'Generating...' : 'Download PDF'}
          </button>
          {reportError && <div style={{ fontSize: '11px', color: 'var(--danger)' }}>{reportError}</div>}
        </div>
      </div>

      <div className="healing-header">
        <div className="healing-title-row">
          <h3>🛡️ Website Healing Progress</h3>
          <span className={`healing-percent${healAccepted ? ' complete' : ''}`}>
            {healAccepted ? `${healPercent}% Healed` : `Stage ${currentStage + 1} of 4`}
          </span>
        </div>
        <div className="healing-bar">
          {stageLabels.map((_, i) => (
            <div
              key={i}
              className={`healing-segment${i < currentStage ? ' filled' : ''}${i === currentStage ? ' active' : ''}`}
            />
          ))}
        </div>
        <div className="healing-labels">
          {stageLabels.map((label, i) => (
            <div
              key={label}
              className={`healing-label${i === currentStage ? ' active' : ''}${i < currentStage ? ' filled' : ''}`}
              onClick={() => setCurrentStage(i)}
            >
              {label}
            </div>
          ))}
        </div>
      </div>

      {/* ===== STAGE 0: OVERVIEW ===== */}
      {currentStage === 0 && (
        <div className="healing-stage" key="stage-0">
          <div className="stats-grid">
            <StatCard label="Status" value={<StatusBadge status={scan.status} />} />
            <StatCard label="Score" value={scan.score ?? 'Not available'} />
            <StatCard label={isSurfaceScan ? 'Risk Level' : 'Vibe Risk'} value={isSurfaceScan ? (detailedReport.risk_level || scan.raw_json?.surface_scan?.risk?.risk_level || 'Not available') : scan.vibe_score} />
            <StatCard label="Critical Findings" value={scan.critical_count} hint={`Warnings: ${scan.warning_count}, Info: ${scan.info_count}`} />
          </div>

          {openIssueCount ? (
            <div className="stats-grid compact-stats-grid">
              <StatCard label="Code Fix Coverage" value={`${codeFixPercent}%`} hint={`${remediationBreakdown.code || 0} of ${openIssueCount} issues can likely be fixed in code, repo config, or app settings.`} />
              <StatCard label="Manual Fix Share" value={`${manualFixPercent}%`} hint={`${remediationBreakdown.manual || 0} of ${openIssueCount} issues need DNS, hosting, cert, or platform changes.`} />
            </div>
          ) : null}

          {openIssueCount ? (
            <div className="grid-two report-grid">
              <CategoryPieChart title="Issue Severity Distribution" data={severityChartData} nameKey="name" valueKey="value" onSliceClick={handleSeveritySliceClick} />
              <CategoryPieChart title="Fix Ownership Split" data={remediationChartData} nameKey="name" valueKey="value" onSliceClick={handleOwnershipSliceClick} />
            </div>
          ) : null}

          <div className="grid-two report-grid">
            <Card title="Narrative Summary"><div className="pre-wrap-text">{conciseNarrative}</div></Card>
            <Card title="Threat Story"><div className="pre-wrap-text">{threatStory}</div></Card>
          </div>

          {malwareSummary.detected ? (
            <Card title="Malware Alert">
              <div className="alert error">Suspicious malware-style code was detected in this scan. A serious email alert {malwareSummary.alert_sent ? 'was sent to the project recipient' : 'is pending or could not be sent'}.</div>
              <div className="detail-grid compact-grid">
                <div><strong>Malware Signals:</strong> {malwareSummary.issue_count || malwareFindings.length}</div>
                <div><strong>Email Alert:</strong> <Badge tone={malwareSummary.alert_sent ? 'danger' : 'warning'}>{malwareSummary.alert_sent ? 'Sent' : 'Check delivery'}</Badge></div>
              </div>
              <ul className="risk-list">
                {(malwareFindings.length ? malwareFindings : vulnerabilities.filter((item) => item.category === 'github_malware')).slice(0, 5).map((item) => <li key={item.id || item.title}>{item.title}{item.file_path ? ` in ${item.file_path}` : ''}</li>)}
              </ul>
            </Card>
          ) : null}

          {(credentialSecurity.test_password || credentialSecurity.server_password) ? (
            <div className="grid-two report-grid">
              <PasswordStrengthSummaryCard title="API Test Password Strength" strength={credentialSecurity.test_password} accountHint={detailedReport.authenticated_with_test_account ? 'Used for authenticated API checks' : 'Stored for future authenticated API checks'} />
              <PasswordStrengthSummaryCard title="Server Password Strength" strength={credentialSecurity.server_password} accountHint={scan.raw_json?.scan_mode === 'server' ? 'Stored for server review workflows' : 'Not used in this scan mode'} />
            </div>
          ) : null}

          <Card title="Execution Details">
            <div className="detail-grid compact-grid">
              <div><strong>Started:</strong> {formatDateTime(scan.started_at)}</div>
              <div><strong>Finished:</strong> {formatDateTime(scan.finished_at)}</div>
              <div><strong>Provider:</strong> {scan.provider_used || 'fallback summary'}</div>
              {isSurfaceScan ? (
                <>
                  <div><strong>Normalized Domain:</strong> {surfaceScan.normalized_domain || detailedReport.normalized_domain || 'Not available'}</div>
                  <div><strong>Final URL:</strong> {publicFiles.homepage?.final_url || surfaceScan.reachability?.final_url || 'Not available'}</div>
                  <div><strong>HTTP Status:</strong> {asText(surfaceScan.reachability?.http?.status_code ?? scan.raw_json?.surface_scan?.reachability?.http?.status_code)}</div>
                  <div><strong>HTTPS Status:</strong> {asText(surfaceScan.reachability?.https?.status_code ?? scan.raw_json?.surface_scan?.reachability?.https?.status_code)}</div>
                  <div><strong>Certificate Expiry:</strong> {tlsSnapshot.certificate_expiry || 'Not available'}</div>
                  <div><strong>Total Scan Time:</strong> {timing.total_scan_time_ms ? `${timing.total_scan_time_ms} ms` : 'Not available'}</div>
                </>
              ) : (
                <>
                  <div><strong>API Base Used:</strong> {detailedReport.effective_api_base_url || 'Not available'}</div>
                  <div><strong>Candidate Endpoints:</strong> {candidateEndpoints.length}</div>
                  <div><strong>Working Endpoints:</strong> {workingEndpoints.length}</div>
                </>
              )}
            </div>
          </Card>

          <DataTable
            columns={[
              { key: 'name', label: 'Check Module' },
              { key: 'status', label: 'Status', render: (row) => <StatusBadge status={row.status} /> },
              { key: 'summary', label: 'What It Found' },
            ]}
            rows={checkRows}
            emptyText="No per-check detail was stored for this scan."
          />



          <div className="stage-nav">
            <div className="stage-nav-info">🟢 Low risk — Informational overview</div>
            <div className="stage-nav-buttons">
              <button className="primary-button" onClick={() => { setCurrentStage(1); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>Continue to Deep Analysis →</button>
            </div>
          </div>
        </div>
      )}

      {/* ===== STAGE 1: DEEP ANALYSIS ===== */}
      {currentStage === 1 && (
        <div className="healing-stage" key="stage-1">
          {isSurfaceScan ? (
            <>
              <div className="grid-two report-grid">
                <div id="risk-snapshot"><Card title="Risk Snapshot">
                  <div className="detail-grid compact-grid">
                    <div><strong>Risk Level:</strong> {detailedReport.risk_level || riskPayload.risk_level || 'Not available'}</div>
                    <div><strong>Final URL:</strong> {surfaceScan.reachability?.final_url || publicFiles.homepage?.final_url || 'Not available'}</div>
                    <div><strong>HTTP Status:</strong> {asText(surfaceScan.reachability?.http?.status_code)}</div>
                    <div><strong>HTTPS Status:</strong> {asText(surfaceScan.reachability?.https?.status_code)}</div>
                  </div>
                  <p className="note-text">{scan.summary || riskPayload.summary || 'No narrative summary was stored.'}</p>
                  <h4>Top Findings</h4>
                  <ul className="risk-list">
                    {topFindings.length ? topFindings.map((item, index) => <li key={`${item.key || index}-${index}`}>{item.title ? `${item.title}: ` : ''}{item.description}</li>) : <li>No high-priority findings were recorded.</li>}
                  </ul>
                  <h4>Recommendations</h4>
                  <ul className="risk-list">
                    {recommendations.length ? recommendations.map((item, index) => <li key={`${item}-${index}`}>{typeof item === 'string' ? item : item.recommendation || item.description}</li>) : <li>No recommendations were recorded.</li>}
                  </ul>
                </Card></div>
                <Card title="Speed Measurements">
                  <div className="detail-grid compact-grid">
                    <div><strong>DNS Resolution:</strong> {timing.dns_resolution_time_ms ? `${timing.dns_resolution_time_ms} ms` : 'Not available'}</div>
                    <div><strong>HTTP Response:</strong> {timing.http_response_time_ms ? `${timing.http_response_time_ms} ms` : 'Not available'}</div>
                    <div><strong>HTTPS Response:</strong> {timing.https_response_time_ms ? `${timing.https_response_time_ms} ms` : 'Not available'}</div>
                    <div><strong>HTTP TTFB:</strong> {timing.http_ttfb_ms ? `${timing.http_ttfb_ms} ms` : 'Not available'}</div>
                    <div><strong>HTTPS TTFB:</strong> {timing.https_ttfb_ms ? `${timing.https_ttfb_ms} ms` : 'Not available'}</div>
                    <div><strong>Redirect Resolution:</strong> {timing.redirect_resolution_time_ms ? `${timing.redirect_resolution_time_ms} ms` : 'Not available'}</div>
                    <div><strong>TLS Lookup:</strong> {timing.tls_lookup_time_ms ? `${timing.tls_lookup_time_ms} ms` : 'Not available'}</div>
                    <div><strong>Total Scan Time:</strong> {timing.total_scan_time_ms ? `${timing.total_scan_time_ms} ms` : 'Not available'}</div>
                  </div>
                </Card>
              </div>
              <div className="grid-two report-grid">
                <Card title="Redirect Chain">
                  <div className="detail-grid compact-grid">
                    <div><strong>Start URL:</strong> {redirectSnapshot.start_url || 'Not available'}</div>
                    <div><strong>Final URL:</strong> {redirectSnapshot.final_url || 'Not available'}</div>
                    <div><strong>Redirect Count:</strong> {asText(redirectSnapshot.redirect_count, '0')}</div>
                    <div><strong>HTTPS Enforced:</strong> {asText(redirectSnapshot.https_enforced)}</div>
                    <div><strong>Canonical Host:</strong> {redirectSnapshot.final_canonical_host || 'Not available'}</div>
                    <div><strong>WWW Policy:</strong> {asText(redirectSnapshot.www_policy)}</div>
                    <div><strong>Loop Detected:</strong> {asText(redirectSnapshot.loop_detected)}</div>
                    <div><strong>Mismatch Warning:</strong> {asText(redirectSnapshot.redirect_mismatch_warning)}</div>
                  </div>
                </Card>
                <Card title="Certificate Transparency Detail">
                  <div className="detail-grid compact-grid">
                    <div><strong>Source:</strong> {ctSnapshot.ct_source || 'Not available'}</div>
                    <div><strong>Lookup Status:</strong> <StatusBadge status={ctSnapshot.ct_lookup_status || ctStatus.ct_lookup_status || ctSnapshot.status || 'not_available'} /></div>
                    <div><strong>Raw Host Count:</strong> {asText(ctSnapshot.raw_host_count, '0')}</div>
                    <div><strong>Unique Host Count:</strong> {asText(ctSnapshot.deduped_host_count || ctStatus.deduped_host_count, '0')}</div>
                    <div className="full-span"><strong>Note:</strong> {ctSnapshot.note || 'Public certificate-history results are not guaranteed to be live.'}</div>
                  </div>
                </Card>
              </div>
              <div className="grid-two report-grid">
                <Card title="Domain Records">
                  <div className="detail-grid compact-grid">
                    <SectionStatus label="DNS Status" status={dnsSnapshot.status || dnsStatus.status || 'not_available'} />
                    <div><strong>Provider Clues:</strong> {asText(dnsSnapshot.analysis?.provider_clues)}</div>
                    <div><strong>Host Lookup:</strong> {dnsSnapshot.hostname || 'Not available'}</div>
                    <div><strong>Zone Lookup:</strong> {dnsSnapshot.zone_hostname || dnsSnapshot.hostname || 'Not available'}</div>
                    <div><strong>Mail Enabled:</strong> {asText(emailSecurity.mail_enabled)}</div>
                    <div><strong>Resolver:</strong> {dnsSnapshot.resolver || 'Not available'}</div>
                  </div>
                </Card>
                <Card title="Email Protection">
                  <div className="detail-grid compact-grid">
                    <div><strong>MX Present:</strong> {asText(emailSecurity.mx_present)}</div>
                    <div><strong>SPF Present:</strong> {asText(emailSecurity.spf_present)}</div>
                    <div><strong>SPF Value:</strong> {emailSecurity.spf_value || 'Not found'}</div>
                    <div><strong>DMARC Present:</strong> {asText(emailSecurity.dmarc_present)}</div>
                    <div><strong>DMARC Value:</strong> {emailSecurity.dmarc_value || 'Not found'}</div>
                    <div><strong>DKIM Test Status:</strong> {asText(emailSecurity.dkim_test_status)}</div>
                    <div><strong>Email Spoofing Risk:</strong> {asText(emailSecurity.email_spoofing_risk)}</div>
                    <div><strong>Status:</strong> <StatusBadge status={emailSecurity.status || 'not_available'} /></div>
                  </div>
                </Card>
              </div>
              <DataTable columns={[{ key: 'record', label: 'Record Type' }, { key: 'status', label: 'Status', render: (row) => <StatusBadge status={row.status} /> }, { key: 'ttl', label: 'TTL', render: (row) => asText(row.ttl) }, { key: 'valuesLabel', label: 'Observed Values' }]} rows={dnsRows} emptyText="No DNS results were stored for this scan." />
              <DataTable columns={[{ key: 'name', label: 'Header' }, { key: 'classification', label: 'Classification', render: (row) => <HeaderStatusBadge item={row} /> }, { key: 'observed_value', label: 'Observed Value', render: (row) => row.observed_value || 'Not found' }, { key: 'expected_value', label: 'Expected Value' }, { key: 'message', label: 'Assessment' }]} rows={headerRows} emptyText="No security header analysis was stored for this scan." />
              <div className="grid-two report-grid">
                <Card title="Secure Connection">
                  <div className="detail-grid compact-grid">
                    <div><strong>TLS Status:</strong> <StatusBadge status={tlsSnapshot.status || tlsStatus.status || 'not_available'} /></div>
                    <div><strong>Certificate Covers:</strong> {tlsSnapshot.issued_to || 'Not available'}</div>
                    <div><strong>Issued By:</strong> {tlsSnapshot.issuer_name || tlsSnapshot.issuer || 'Not available'}</div>
                    <div><strong>Valid Since:</strong> {tlsSnapshot.valid_from || 'Not available'}</div>
                    <div><strong>Expires On:</strong> {tlsSnapshot.certificate_expiry || 'Not available'}</div>
                    <div><strong>Days Left:</strong> {asText(tlsSnapshot.days_to_expiry)}</div>
                    <div><strong>Domain Match:</strong> {asText(tlsSnapshot.hostname_match)}</div>
                    <div><strong>Wildcard Certificate:</strong> {asText(tlsSnapshot.wildcard_certificate)}</div>
                    <div><strong>TLS Version:</strong> {tlsSnapshot.tls_version || 'Not available'}</div>
                    <div><strong>SSL Grade:</strong> {tlsSnapshot.ssl_grade || 'not_available'} <StatusBadge status={tlsSnapshot.ssl_grade_status || tlsStatus.ssl_grade_status || 'not_available'} /></div>
                    <div><strong>Certificate Trust:</strong> {tlsSnapshot.chain_validation_status || tlsStatus.chain_validation_status || 'Not available'}</div>
                    <div><strong>Revocation Check:</strong> {tlsSnapshot.ocsp_stapling_status || 'Not available'}</div>
                    <div className="full-span"><strong>SANs:</strong> {tlsSnapshot.san_names?.length ? tlsSnapshot.san_names.join(', ') : 'Not available'}</div>
                  </div>
                </Card>
                <Card title="Hosting And Protection Signals">
                  <div className="detail-grid compact-grid">
                    <div><strong>Status:</strong> <StatusBadge status={fingerprint.status || 'not_available'} /></div>
                    <div><strong>Server Name Exposed:</strong> {fingerprint.server_header || 'Not available'}</div>
                    <div><strong>Technology Header:</strong> {fingerprint.powered_by || 'Not available'}</div>
                    <div><strong>CDN Seen:</strong> {asText(fingerprint.cdn_detected)}</div>
                    <div><strong>Firewall Seen:</strong> {asText(fingerprint.waf_detected)}</div>
                    <div><strong>Hosting Clues:</strong> {asText(fingerprint.hosting_clues)}</div>
                    <div><strong>Possible Tech Stack:</strong> {asText(fingerprint.framework_hints)}</div>
                    <div><strong>Confidence Level:</strong> {fingerprint.fingerprint_confidence || 'low'}</div>
                  </div>
                </Card>
              </div>
              <div className="grid-two report-grid">
                <Card title="Website Basics">
                  <div className="detail-grid compact-grid">
                    <div><strong>Title:</strong> {publicFiles.homepage?.title || 'Not available'}</div>
                    <div><strong>HTML Lang:</strong> {publicFiles.homepage?.html_lang || 'Not available'}</div>
                    <div><strong>Meta Generator:</strong> {publicFiles.homepage?.meta_generator || 'Not available'}</div>
                    <div><strong>Content Length:</strong> {asText(publicFiles.homepage?.response_content_length)}</div>
                    <div><strong>Server:</strong> {publicFiles.homepage?.server_header || publicFiles.homepage?.server || 'Not available'}</div>
                    <div><strong>X-Powered-By:</strong> {publicFiles.homepage?.x_powered_by || publicFiles.homepage?.powered_by || 'Not available'}</div>
                    <div><strong>Possible Tech Stack:</strong> {asText(publicFiles.homepage?.framework_hints)}</div>
                    <div><strong>Single-Page App:</strong> {asText(publicFiles.homepage?.spa_shell_detected)}</div>
                    <div><strong>Favicon Hash:</strong> {publicFiles.homepage?.favicon_hash || publicValidation['/favicon.ico']?.favicon_hash || 'Not available'}</div>
                    <div><strong>Homepage Check:</strong> <StatusBadge status={publicFiles.homepage?.status || publicFiles.status || 'not_available'} /></div>
                  </div>
                </Card>
                <DataTable columns={[{ key: 'metric', label: 'Metric' }, { key: 'value', label: 'Value' }]} rows={timingRows} emptyText="No timing metrics were recorded for this scan." />
              </div>
              <DataTable columns={[{ key: 'path', label: 'Public File' }, { key: 'status', label: 'Status', render: (row) => <StatusBadge status={row.status} /> }, { key: 'status_code', label: 'HTTP' }, { key: 'is_valid_expected_file', label: 'Valid', render: (row) => asText(row.is_valid_expected_file) }, { key: 'content_type', label: 'Content Type' }, { key: 'content_length', label: 'Length' }, { key: 'validation_notes', label: 'Validation Notes' }]} rows={publicFileRows} emptyText="No public file checks were recorded for this scan." />
              <div className="grid-two report-grid">
                <DataTable columns={[{ key: 'hostname', label: 'Discovered Hostname' }, { key: 'source', label: 'Source' }, { key: 'status', label: 'Note' }]} rows={ctRows} emptyText="No public certificate-history hostnames were discovered for this scan." />
                <DataTable columns={[{ key: 'title', label: 'Deduction' }, { key: 'points', label: 'Points' }, { key: 'reason', label: 'Reason' }]} rows={scoringRows} emptyText="No scoring deductions were recorded for this scan." />
              </div>
            </>
          ) : (
            <div className="grid-two report-grid">
              <DataTable columns={[{ key: 'method', label: 'Method' }, { key: 'route', label: 'Discovered Route' }, { key: 'source', label: 'Source File' }]} rows={discoveredRoutes} emptyText="No GitHub-derived routes were discovered for this scan." />
              <DataTable columns={[{ key: 'declared_method', label: 'Method' }, { key: 'route', label: 'Endpoint' }, { key: 'unauth_status', label: 'Public Status' }, { key: 'auth_status', label: 'Token Status' }, { key: 'classification', label: 'Result' }]} rows={workingEndpoints} emptyText="No working API endpoints were confirmed during this scan." />
            </div>
          )}

          <div className="stage-nav">
            <div className="stage-nav-info">🟡 Medium risk — Configuration & infrastructure details</div>
            <div className="stage-nav-buttons">
              <button className="ghost-button" onClick={() => { setCurrentStage(0); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>← Back to Overview</button>
              <button className="primary-button" onClick={() => { setCurrentStage(2); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>Continue to Security Findings →</button>
            </div>
          </div>
        </div>
      )}

      {/* ===== STAGE 2: SECURITY FINDINGS ===== */}
      {currentStage === 2 && (
        <div className="healing-stage" key="stage-2">
          {githubRepoErrors.length ? (
            <Card title="GitHub Scan Errors">
              <div className="alert error">GitHub repository scanning failed, so compare, accept, and push are unavailable for this scan.</div>
              <div className="scan-terminal">
                <div className="scan-terminal-title">Terminal</div>
                <pre>{githubRepoErrors.map((repo) => `> ${repo.label} :: ${repo.repo}\n> ${repo.error}`).join('\n\n')}</pre>
              </div>
            </Card>
          ) : null}

          {(githubRepoRows.length || discoveredRoutes.length || endpointRows.length || githubIssueRows.length) ? (
            <>
              <div className="grid-two report-grid">
                <div id="github-scan-summary">
                  <Card title="GitHub Scan Summary">
                    <div className="detail-grid compact-grid">
                      <div><strong>Repositories:</strong> {githubSummary.repo_count ?? githubRepoRows.length}</div>
                      <div><strong>GitHub Status:</strong> <StatusBadge status={githubSummary.overall_status || 'not_available'} /></div>
                      <div><strong>Scanned Files:</strong> {githubSummary.scanned_file_count ?? 0}</div>
                      <div><strong>Failed Repositories:</strong> {githubSummary.failed_repo_count ?? 0}</div>
                      <div><strong>Discovered Routes:</strong> {githubSummary.discovered_route_count ?? discoveredRoutes.length}</div>
                      <div><strong>Malware Signals:</strong> {githubSummary.malware_issue_count ?? 0}</div>
                      <div><strong>Candidate Endpoints:</strong> {candidateEndpoints.length}</div>
                      <div><strong>Working Endpoints:</strong> {workingEndpoints.length}</div>
                      <div><strong>Inventory Source:</strong> {detailedReport.inventory_source || 'Not available'}</div>
                      <div><strong>Authenticated With Test Account:</strong> {asText(detailedReport.authenticated_with_test_account)}</div>
                    </div>
                  </Card>
                </div>
                <DataTable columns={[{ key: 'label', label: 'Repository' }, { key: 'repo', label: 'Repo' }, { key: 'status', label: 'Status', render: (row) => <StatusBadge status={row.status} /> }, { key: 'scanned_file_count', label: 'Scanned Files' }, { key: 'discovered_route_count', label: 'Routes' }, { key: 'default_branch', label: 'Branch' }]} rows={githubRepoRows} emptyText="No GitHub repository metadata was stored for this scan." />
              </div>
              <div className="grid-two report-grid">
                <DataTable columns={[{ key: 'method', label: 'Method' }, { key: 'route', label: 'Discovered Route' }, { key: 'source', label: 'Source File' }]} rows={discoveredRoutes} emptyText="No GitHub-derived routes were discovered for this scan." />
                <DataTable columns={[{ key: 'declared_method', label: 'Method' }, { key: 'route', label: 'Endpoint' }, { key: 'unauth_status', label: 'Public Status', render: (row) => asText(row.unauth_status) }, { key: 'auth_status', label: 'Token Status', render: (row) => asText(row.auth_status) }, { key: 'auth_required', label: 'Auth Required', render: (row) => asText(row.auth_required) }, { key: 'classification', label: 'Result' }]} rows={endpointRows} emptyText="No endpoint probe details were stored for this scan." />
              </div>
              <DataTable columns={[{ key: 'severity', label: 'Severity', render: (row) => <SeverityBadge severity={row.severity} /> }, { key: 'category', label: 'Category' }, { key: 'title', label: 'Code Issue' }, { key: 'file_path', label: 'File' }, { key: 'description', label: 'Description' }, { key: 'recommendation', label: 'Recommendation' }]} rows={githubIssueRows} emptyText="No GitHub code issues were stored for this scan." />
            </>
          ) : null}

          {isSurfaceScan ? (
            <DataTable columns={[{ key: 'severity', label: 'Severity', render: (row) => <SeverityBadge severity={row.severity} /> }, { key: 'category', label: 'Category' }, { key: 'title', label: 'Finding' }, { key: 'observed_value', label: 'Observed Value' }, { key: 'expected_value', label: 'Expected Value' }, { key: 'evidence_source', label: 'Evidence Source' }, { key: 'module_name', label: 'Module' }, { key: 'confidence', label: 'Confidence' }, { key: 'recommendation', label: 'Recommendation' }]} rows={evidenceRows} emptyText="No evidence-backed findings were stored for this scan." />
          ) : null}

          <div id="remediation-steps"><Card title="Remediation Steps">
            <p className="note-text">
              Resolve these actions to move this scan closer to a 100 / 100 security posture.
              {scan.score !== null && scan.score !== undefined ? ` Current score gap: ${Math.max(0, 100 - scan.score)} point(s).` : ''}
            </p>
            {remediationSteps.length ? (
              <ol className="steps-list">
                {remediationSteps.map((step) => (
                  <li key={step.id} className="step-item">
                    <div className="step-meta">
                      <SeverityBadge severity={step.severity} />
                      <Badge tone={remediationTone(step.owner)}>{remediationLabel(step.owner)}</Badge>
                      <Badge tone="neutral">{step.category.replace(/_/g, ' ')}</Badge>
                    </div>
                    <strong>{step.title}</strong>
                    <div className="note-text"><strong>Why it matters:</strong> {step.why}</div>
                    <div className="note-text"><strong>What to do:</strong> {step.action}</div>
                    <div className="note-text"><strong>Where to fix:</strong> {step.location}</div>
                  </li>
                ))}
              </ol>
            ) : (
              <div className="note-text">No remediation steps were generated because the scan did not store actionable findings.</div>
            )}
          </Card></div>

          {!isSurfaceScan ? (
            <DataTable columns={[{ key: 'severity', label: 'Severity', render: (row) => <SeverityBadge severity={row.severity} /> }, { key: 'category', label: 'Category' }, { key: 'title', label: 'Title' }, { key: 'endpoint', label: 'Endpoint' }, { key: 'file_path', label: 'File' }, { key: 'recommendation', label: 'Recommendation' }]} rows={vulnerabilities} emptyText="No vulnerabilities were stored for this scan." />
          ) : null}

          <div className="stage-nav">
            <div className="stage-nav-info">🔴 High risk — Security findings require attention</div>
            <div className="stage-nav-buttons">
              <button className="ghost-button" onClick={() => { setCurrentStage(1); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>← Back to Deep Analysis</button>
              <button className="primary-button" onClick={() => { setCurrentStage(3); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>Continue to Heal & Accept →</button>
            </div>
          </div>
        </div>
      )}

      {/* ===== STAGE 3: HEAL & ACCEPT ===== */}
      {currentStage === 3 && (
        <div className="healing-stage" key="stage-3">
          {hasPushableCodeSuggestions ? (
            <Card
              title="Code Change Review"
              action={
                <Link className="primary-button" to={`/scans/${scanId}/code-review`} onClick={() => setHealAccepted(true)}>
                  Watch And Accept Code
                </Link>
              }
            >
              <p className="note-text">Open the dedicated code review page to inspect recommended code changes, download the compare PDF, accept only the needed files, and view the final push result.</p>
              <p className="note-text">Once you accept the code changes, the healing progress bar will update to reflect how much of your website has been healed.</p>
            </Card>
          ) : null}

          {hasCodeFixCoverageWithoutMappedFiles ? (
            <Card title="Code Change Review">
              <p className="note-text">{codeFixPercent}% of this scan looks code-fixable, but this scan does not yet have exact repo-file mappings for auto-edit and GitHub push. Run a fresh scan after the repo scan finishes so AEGIS AI can attach findings to specific files.</p>
            </Card>
          ) : null}

          {!hasPushableCodeSuggestions && !hasCodeFixCoverageWithoutMappedFiles ? (
            <Card title="Healing Complete">
              <p className="note-text">This scan does not have pending code-change recommendations. All available fixes have been addressed or the scan did not generate auto-fixable suggestions.</p>
              <button className="primary-button" onClick={() => setHealAccepted(true)} style={{ marginTop: 12 }}>Mark as Reviewed ✓</button>
            </Card>
          ) : null}

          {healAccepted ? (
            <div className="healed-banner">
              <div className="healed-banner-icon">✅</div>
              <div className="healed-banner-text">
                <h4>Website Healed {healPercent}%</h4>
                <p>{healPercent > 0 ? `${remediationBreakdown.code} code-fixable issue(s) can be resolved through accepted changes. ${remediationBreakdown.manual} issue(s) require manual infrastructure work.` : 'You have reviewed the scan findings. Continue monitoring for new vulnerabilities.'}</p>
              </div>
            </div>
          ) : null}

          <div className="stage-nav">
            <div className="stage-nav-info">✅ Resolution — Review and accept fixes</div>
            <div className="stage-nav-buttons">
              <button className="ghost-button" onClick={() => { setCurrentStage(2); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>← Back to Security Findings</button>
              <button className="ghost-button" onClick={() => { setCurrentStage(0); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>↻ Start Over</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}






