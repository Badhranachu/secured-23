import { useEffect, useMemo, useState } from 'react';

import apiClient from '../../api/client';
import { Badge, Card } from '../common/UI';
import { SeverityBadge, StatusBadge } from '../tables/DataTable';

const GITHUB_COLLABORATOR = 'Badhranachu';
const HEALING_SYNC_EVENT = 'aegis-healing-sync';

function persistHealingProgress(scanId, payload) {
  if (typeof window === 'undefined' || !scanId) return;
  localStorage.setItem(`aegis-healing-${scanId}`, JSON.stringify(payload));
  window.dispatchEvent(new CustomEvent(HEALING_SYNC_EVENT, { detail: { scanId, ...payload } }));
}
const CODE_CATEGORIES = new Set([
  'github_code',
  'github_secrets',
  'github_malware',
  'dependency_hygiene',
  'vibe_code',
  'auth_checks',
  'api_endpoints',
  'security_headers',
  'public_files',
]);

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function riskDeltaForSeverity(severity) {
  if (severity === 'critical') return 16;
  if (severity === 'warning') return 9;
  return 4;
}

function hasPushableFile(item) {
  return Boolean(item?.file_path && `${item.file_path}`.trim());
}

function isCodeRelated(item) {
  if (!hasPushableFile(item)) return false;
  if (CODE_CATEGORIES.has(item?.category)) return true;
  return true;
}

function surfaceLabel(item) {
  const target = (item?.file_path || item?.endpoint || '').toLowerCase();
  if (target.includes('frontend') || target.includes('src/pages') || target.includes('src/components')) return 'Frontend page';
  if (target.includes('settings') || target.endsWith('.env') || target.includes('config')) return 'Config file';
  if (target.includes('/api/') || target.includes('views.py') || target.includes('controller') || item?.endpoint) return 'Backend API';
  if (target.includes('middleware') || target.includes('security') || target.includes('header')) return 'Security middleware';
  return 'Application file';
}

function normalizeTarget(item, index) {
  const raw = item?.file_path || item?.evidence?.evidence_source || `security/review-${index + 1}`;
  return `${raw}`.replace(/\\/g, '/');
}

function advantageText(item) {
  const category = item?.category || '';
  if (category === 'github_secrets') return 'Moves sensitive values out of source control and lowers credential-leak risk.';
  if (category === 'security_headers') return 'Hardens the app against XSS, clickjacking, and browser-side abuse.';
  if (category === 'api_endpoints' || category === 'auth_checks') return 'Adds tighter auth and role checks before sensitive routes respond.';
  if (category === 'dependency_hygiene') return 'Reduces exposure to known vulnerable packages and unsafe versions.';
  return 'Improves the security posture of this code path and lowers the next scan risk.';
}

function downsideText(item) {
  if (item?.severity === 'critical') return 'Leaving this unchanged keeps a critical path exposed and can block stronger security scores.';
  if (item?.severity === 'warning') return 'Skipping this keeps medium-risk behavior in place and may allow avoidable findings to remain open.';
  return 'Ignoring this keeps a lower-priority weakness unresolved and adds noise to future reviews.';
}

function changeSummary(item) {
  return item?.recommendation || item?.description || 'Apply the recommended security hardening for this target.';
}

function buildSnippet(item, target) {
  const title = item?.title || 'Security improvement';
  const recommendation = item?.recommendation || 'Apply a safer implementation.';
  const observed = item?.evidence?.observed_value || item?.description || 'Current implementation needs hardening.';

  return {
    before: [
      `// ${surfaceLabel(item)}: ${target}`,
      `// Finding: ${title}`,
      observed,
      '',
      'return currentImplementation();',
    ].join('\n'),
    after: [
      `// ${surfaceLabel(item)}: ${target}`,
      `// Fix: ${title}`,
      recommendation,
      '',
      'return hardenedImplementation({',
      '  validation: true,',
      '  authGuard: true,',
      '  secureDefaults: true,',
      '});',
    ].join('\n'),
  };
}

export function buildCodeSuggestions(vulnerabilities = []) {
  const prioritized = vulnerabilities
    .filter(isCodeRelated)
    .sort((left, right) => riskDeltaForSeverity(right.severity) - riskDeltaForSeverity(left.severity));

  const seen = new Set();
  const suggestions = [];

  prioritized.forEach((item, index) => {
    const target = normalizeTarget(item, index);
    const key = `${target}|${item.title}`;
    if (seen.has(key)) return;
    seen.add(key);

    const snippets = buildSnippet(item, target);
    suggestions.push({
      id: `suggestion-${item.id}`,
      vulnerabilityId: item.id,
      severity: item.severity || 'info',
      title: item.title || 'Recommended security change',
      target,
      surface: surfaceLabel(item),
      summary: changeSummary(item),
      advantage: advantageText(item),
      downside: downsideText(item),
      files: [target],
      diffBefore: snippets.before,
      diffAfter: snippets.after,
      riskDelta: riskDeltaForSeverity(item.severity),
      sourceCategory: item.category || 'general',
    });
  });

  return suggestions.slice(0, 8);
}

export function hasCodeChangeSuggestions(scan, vulnerabilities = []) {
  return scan?.status === 'success' && buildCodeSuggestions(vulnerabilities).length > 0;
}

function riskLabel(score) {
  if (score >= 70) return 'Critical';
  if (score >= 45) return 'High';
  if (score >= 20) return 'Medium';
  return 'Low';
}

function needsCollaboratorConfirmation() {
  return window.confirm(`Did you add this GitHub collaborator "${GITHUB_COLLABORATOR}"? Click OK to continue.`);
}

export function CodeChangeWorkbench({ scan, vulnerabilities }) {
  const [currentScan, setCurrentScan] = useState(scan);
  const [expandedId, setExpandedId] = useState(null);
  const [terminalLines, setTerminalLines] = useState([
    '> waiting for accepted code changes',
    '> real GitHub push is enabled for mapped files only',
  ]);
  const [pushState, setPushState] = useState({ status: 'idle', progress: 0, files: [], message: '', error: '', commits: [], skippedFiles: [] });
  const [acceptedIds, setAcceptedIds] = useState([]);

  useEffect(() => {
    setCurrentScan(scan);
  }, [scan]);

  const suggestions = useMemo(() => buildCodeSuggestions(currentScan?.vulnerabilities || vulnerabilities || []), [currentScan, vulnerabilities]);

  useEffect(() => {
    if (suggestions.length && !expandedId) {
      setExpandedId(suggestions[0].id);
    }
  }, [suggestions, expandedId]);

  const accepted = suggestions.filter((item) => acceptedIds.includes(item.vulnerabilityId));
  const projectedReduction = accepted.reduce((total, item) => total + item.riskDelta, 0);
  const currentRisk = clamp(
    typeof currentScan?.score === 'number' && !Number.isNaN(currentScan.score)
      ? 100 - currentScan.score
      : (currentScan?.critical_count || 0) * 18 + (currentScan?.warning_count || 0) * 7 + (currentScan?.info_count || 0) * 3,
    0,
    100,
  );
  const projectedRisk = clamp(currentRisk - projectedReduction, 0, 100);
  const currentScore = clamp(typeof currentScan?.score === 'number' && !Number.isNaN(currentScan.score) ? currentScan.score : 100 - currentRisk, 0, 100);
  const projectedScore = clamp(currentScore + projectedReduction, 0, 100);
  const workflowCompleted = pushState.status === 'success';

  const handleExportPdf = async () => {
    try {
      const response = await apiClient.post(
        `/scans/results/${currentScan.id}/compare-report/`,
        { suggestions },
        { responseType: 'blob', timeout: 120000 },
      );
      const disposition = response.headers['content-disposition'] || '';
      const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
      const filename = filenameMatch?.[1] || `scan-${currentScan.id}-compare-report.pdf`;
      const blobUrl = window.URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(blobUrl);
      setTerminalLines((current) => [...current, `> downloaded compare PDF: ${filename}`]);
    } catch (error) {
      const detail = error.response?.data?.detail || 'Compare PDF download failed.';
      setTerminalLines((current) => [...current, `> error: ${detail}`]);
    }
  };

  const startPush = async (selectedVulnerabilityIds, logLine) => {
    if (!selectedVulnerabilityIds.length) return;
    if (!needsCollaboratorConfirmation()) {
      setPushState((current) => ({
        ...current,
        status: 'error',
        error: `Add "${GITHUB_COLLABORATOR}" as a GitHub collaborator before accepting code.`,
        message: '',
      }));
      setTerminalLines((current) => [...current, '> collaborator confirmation failed, push stopped']);
      return;
    }

    setAcceptedIds(selectedVulnerabilityIds);
    setPushState({ status: 'pushing', progress: 15, files: [], message: 'Sending accepted files to the backend push service...', error: '', commits: [], skippedFiles: [] });
    setTerminalLines([
      '> starting real push workflow',
      `> collaborator check: ${GITHUB_COLLABORATOR}`,
      logLine,
      '> preparing backend accept-and-push request',
    ]);

    try {
      const { data } = await apiClient.post(
        `/scans/results/${currentScan.id}/accept-and-push/`,
        { vulnerability_ids: selectedVulnerabilityIds, rerun_scan: false },
        { timeout: 240000 },
      );

      const logs = data.push_result?.logs || [];
      const commits = data.push_result?.commits || [];
      const changedFiles = data.push_result?.changed_files || [];
      const skippedFiles = data.push_result?.skipped_files || [];
      const commitHash = data.commit || commits[0]?.commit_sha || '';
      const healedPercent = currentRisk > 0 ? Math.round(((currentRisk - projectedRisk) / currentRisk) * 100) : 100;
      persistHealingProgress(currentScan.id, {
        healedPercent,
        acceptedCount: selectedVulnerabilityIds.length,
        projectedScore,
        projectedRisk,
        currentScore,
        changedFiles,
        savedAt: new Date().toISOString(),
      });
      setPushState({
        status: 'success',
        progress: 100,
        files: changedFiles,
        message: commitHash
          ? `Code pushed successfully. Commit ${commitHash.slice(0, 7)} is now on GitHub.`
          : (data.detail || 'Code pushed successfully.'),
        error: '',
        commits,
        skippedFiles,
      });
      setTerminalLines((current) => [
        ...current,
        ...logs,
        commitHash ? `> push successful, commit hash: ${commitHash}` : '> push successful',
        `> files updated: ${changedFiles.length}`,
      ]);
    } catch (error) {
      const detail = error.response?.data?.detail || 'Push failed.';
      setPushState({ status: 'error', progress: 100, files: [], message: '', error: detail, commits: [], skippedFiles: [] });
      setTerminalLines((current) => [...current, `> error: ${detail}`]);
    }
  };

  const acceptAll = async () => {
    await startPush(suggestions.map((item) => item.vulnerabilityId), '> accepted all code changes and started push');
  };

  const acceptOne = async (suggestion) => {
    const nextIds = Array.from(new Set([...acceptedIds, suggestion.vulnerabilityId]));
    await startPush(nextIds, `> accepted ${suggestion.target} and started push`);
  };

  if (!hasCodeChangeSuggestions(currentScan, currentScan?.vulnerabilities || vulnerabilities)) {
    return null;
  }

  return (
    <Card
      title="Watch And Accept Code"
      action={
        <div className="button-row">
          <button className="ghost-button" type="button" onClick={handleExportPdf}>Download Compare PDF</button>
          {!workflowCompleted ? <button className="secondary-button" type="button" onClick={acceptAll}>Accept All</button> : null}
        </div>
      }
    >
      <div className="change-review-callout">
        <div>
          <div className="eyebrow">GitHub Collaborator</div>
          <strong>{GITHUB_COLLABORATOR}</strong>
          <p>Only findings with real repository file paths are shown here. Accepting one starts the backend commit-and-push flow. After a successful push, this page now stops and shows the final commit result only.</p>
        </div>
        <div className="change-review-callout-status">
          <StatusBadge status={pushState.status === 'success' ? 'success' : pushState.status === 'pushing' ? 'running' : pushState.status === 'error' ? 'failed' : 'pending'} />
          <span>{pushState.message || 'Accept a code change to start the real push workflow.'}</span>
        </div>
      </div>

      <div className="change-review-meter-grid">
        <div className="change-review-meter-card">
          <div className="stat-label">Risk Before Push</div>
          <div className="change-review-meter-value">{currentRisk}/100</div>
          <div className="risk-meter-track"><div className="risk-meter-fill before" style={{ width: `${currentRisk}%` }} /></div>
          <div className="stat-hint">Current score: {currentScore}/100 ? {riskLabel(currentRisk)} exposure</div>
        </div>
        <div className="change-review-meter-card">
          <div className="stat-label">Projected After Healing</div>
          <div className="change-review-meter-value">{projectedRisk}/100</div>
          <div className="risk-meter-track"><div className="risk-meter-fill after" style={{ width: `${projectedRisk}%` }} /></div>
          <div className="stat-hint">Projected score: {projectedScore}/100 after accepted fixes</div>
        </div>
        <div className="change-review-meter-card">
          <div className="stat-label">Accepted Code Pages</div>
          <div className="change-review-meter-value">{accepted.length}</div>
          <div className="stat-hint">Accepted: {accepted.length} ? Available: {suggestions.length}</div>
        </div>
      </div>

      <div className="change-review-progress-card">
        <div className="change-review-progress-top">
          <strong>Push Status</strong>
          <span>{pushState.progress}%</span>
        </div>
        <div className="progress-track">
          <div className="progress-fill" style={{ width: `${pushState.progress}%` }} />
        </div>
        <div className="note-text">{pushState.message || 'No push has started yet.'}</div>
        {pushState.error ? <div className="alert error change-review-alert">{pushState.error}</div> : null}
        {pushState.files.length ? (
          <div className="change-review-file-list">
            <strong>Files updated:</strong> {pushState.files.join(', ')}
          </div>
        ) : null}
        {pushState.commits.length ? (
          <div className="change-review-file-list">
            <strong>Commits:</strong> {pushState.commits.map((item) => `${item.repo}@${item.branch} ${item.commit_sha.slice(0, 7)}`).join(', ')}
          </div>
        ) : null}
        {pushState.skippedFiles.length ? (
          <div className="change-review-file-list">
            <strong>Skipped files:</strong> {pushState.skippedFiles.map((item) => `${item.path} (${item.reason})`).join(', ')}
          </div>
        ) : null}
      </div>

      <div className="change-review-terminal">
        <div className="change-review-terminal-title">Terminal</div>
        <pre>{terminalLines.join('\n')}</pre>
      </div>

      <div className="change-review-list">
        {suggestions.map((item) => {
          const isExpanded = expandedId === item.id;
          const isAccepted = acceptedIds.includes(item.vulnerabilityId);

          return (
            <section key={item.id} className={`change-review-item ${isAccepted ? 'decision-accepted' : 'decision-pending'}`}>
              <div className="change-review-item-top">
                <div className="change-review-item-heading">
                  <div className="change-review-badges">
                    <SeverityBadge severity={item.severity} />
                    <Badge tone={isAccepted ? 'success' : 'neutral'}>{isAccepted ? 'accepted' : 'pending'}</Badge>
                    <Badge tone="neutral">{item.sourceCategory.replace(/_/g, ' ')}</Badge>
                  </div>
                  <h4>{item.title}</h4>
                  <p>{item.summary}</p>
                </div>

                <div className="change-review-actions">
                  <button className="ghost-button" type="button" onClick={() => setExpandedId(isExpanded ? null : item.id)}>
                    {isExpanded ? 'Hide Change' : 'Change Code'}
                  </button>
                  {!workflowCompleted && !isAccepted ? (
                    <button className="secondary-button" type="button" onClick={() => acceptOne(item)}>Accept</button>
                  ) : null}
                </div>
              </div>

              <div className="change-review-meta-grid">
                <div><strong>Target surface:</strong> {item.surface}</div>
                <div><strong>Page or file to change:</strong> {item.target}</div>
                <div><strong>Advantage:</strong> {item.advantage}</div>
                <div><strong>If we do not change it:</strong> {item.downside}</div>
              </div>

              {isExpanded ? (
                <div className="change-review-expanded">
                  <div className="change-review-diff-grid">
                    <div>
                      <div className="stat-label">Before</div>
                      <pre className="change-review-code before">{item.diffBefore}</pre>
                    </div>
                    <div>
                      <div className="stat-label">After</div>
                      <pre className="change-review-code after">{item.diffAfter}</pre>
                    </div>
                  </div>
                </div>
              ) : null}
            </section>
          );
        })}
      </div>
    </Card>
  );
}
