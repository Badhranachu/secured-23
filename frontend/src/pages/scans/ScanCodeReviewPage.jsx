import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import apiClient from '../../api/client';
import { CodeChangeWorkbench, hasCodeChangeSuggestions } from '../../components/scans/CodeChangeWorkbench';
import { BackButton } from '../../components/common/BackButton';
import { Loader } from '../../components/common/UI';

export function ScanCodeReviewPage() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient.get(`/scans/results/${scanId}/`).then((response) => setScan(response.data)).finally(() => setLoading(false));
  }, [scanId]);

  if (loading) return <Loader label="Loading code review..." />;
  if (!scan) return null;

  const vulnerabilities = scan.vulnerabilities || [];
  const hasCodeReview = hasCodeChangeSuggestions(scan, vulnerabilities);

  return (
    <div className="page-grid report-stack">
      <div className="page-header-row">
        <div>
          <BackButton fallbackTo={`/scans/${scanId}`} className="auth-back-button" />
          <div className="eyebrow">Code Review Workspace</div>
          <h2>{scan.project_name}</h2>
          <p>Review recommended code changes, export a compare PDF with old and recommended code, then accept what you want and push it to GitHub.</p>
        </div>
        <div className="button-row">
          <Link className="ghost-button" to={`/scans/${scanId}`}>Back To Scan</Link>
        </div>
      </div>

      {hasCodeReview ? (
        <CodeChangeWorkbench scan={scan} vulnerabilities={vulnerabilities} />
      ) : (
        <div className="card empty-state">
          <h3>No code review items</h3>
          <p>This scan does not have completed code-change recommendations to review.</p>
        </div>
      )}
    </div>
  );
}
