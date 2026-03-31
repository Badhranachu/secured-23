import { useEffect, useRef, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';

import apiClient from '../../api/client';
import { Loader } from '../../components/common/UI';
import { ProjectForm } from '../../components/forms/ProjectForm';

function extractApiFieldErrors(requestError) {
  const payload = requestError?.response?.data;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {};
  }

  const fieldErrors = {};
  Object.entries(payload).forEach(([key, value]) => {
    if (key === 'detail') return;
    if (Array.isArray(value) && value[0]) {
      fieldErrors[key] = value[0];
      return;
    }
    if (typeof value === 'string' && value) {
      fieldErrors[key] = value;
    }
  });
  return fieldErrors;
}

function extractApiErrorMessage(requestError, fallback, fieldErrors = {}) {
  const payload = requestError?.response?.data;
  if (!payload) return fallback;
  if (typeof payload === 'string') return payload;
  if (typeof payload.detail === 'string') return payload.detail;
  if (Array.isArray(payload.non_field_errors) && payload.non_field_errors[0]) {
    return payload.non_field_errors[0];
  }
  const firstFieldError = Object.values(fieldErrors)[0];
  if (firstFieldError) return firstFieldError;
  if (typeof payload === 'object') {
    for (const value of Object.values(payload)) {
      if (Array.isArray(value) && value[0]) return value[0];
      if (typeof value === 'string' && value) return value;
    }
  }
  return fallback;
}

function modeDescription(scanMode) {
  if (scanMode === 'advanced') {
    return 'Advanced mode accepts a domain, IP address, or URL with port and optional frontend/backend GitHub repositories. The scan will fetch website risk details and GitHub code issues together in one detailed report.';
  }
  if (scanMode === 'server') {
    return 'Server mode accepts a domain, GitHub repositories, API test-account credentials, and server access details so you can prepare a deeper malware, API, and server-issue review.';
  }
  return 'Basic mode accepts a domain, IP address, or URL with port and returns a focused risk summary.';
}

function runningScanDetail(scanMode) {
  if (scanMode === 'advanced') {
    return 'Fetching website risk details and GitHub code signals, then building the combined security report.';
  }
  if (scanMode === 'server') {
    return 'Preparing the website, GitHub, API, and server-review context for the first detailed scan.';
  }
  return 'Collecting DNS, headers, TLS, public files, and surface-risk data for the target.';
}

export function ProjectFormPage({ mode }) {
  const navigate = useNavigate();
  const { projectId } = useParams();
  const [searchParams] = useSearchParams();
  const requestedMode = searchParams.get('mode') || 'basic';
  const [project, setProject] = useState(null);
  const [loading, setLoading] = useState(mode === 'edit');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [fieldErrors, setFieldErrors] = useState({});
  const [progress, setProgress] = useState(0);
  const [progressLabel, setProgressLabel] = useState('Preparing scan...');
  const [progressDetail, setProgressDetail] = useState('');
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
      setProgress((current) => {
        if (current >= 92) return current;
        if (current < 35) return current + 9;
        if (current < 65) return current + 6;
        if (current < 85) return current + 3;
        return current + 1;
      });
    }, 350);
  };

  useEffect(() => {
    return () => stopProgress();
  }, []);

  useEffect(() => {
    if (mode !== 'edit' || !projectId) return;
    apiClient.get(`/projects/${projectId}/`).then((response) => setProject(response.data)).finally(() => setLoading(false));
  }, [mode, projectId]);

  const openLatestAvailableScan = async (targetProjectId) => {
    try {
      const latestResponse = await apiClient.get(`/projects/${targetProjectId}/latest-scan/`);
      const latestScanId = latestResponse.data?.id;
      if (latestScanId) {
        navigate(`/scans/${latestScanId}`);
        return true;
      }
    } catch (_error) {
      return false;
    }
    return false;
  };

  const handleSubmit = async (payload) => {
    setSaving(true);
    setSaveError('');
    setFieldErrors({});
    let createdProjectId = null;

    try {
      if (mode === 'edit') {
        await apiClient.put(`/projects/${projectId}/`, payload);
        navigate(`/projects/${projectId}`);
        return;
      }

      setProgress(8);
      setProgressLabel('Creating project...');
      setProgressDetail('Saving the target and preparing the first detailed security scan.');
      startProgress();

      const { data } = await apiClient.post('/projects/', payload);
      createdProjectId = data.id;

      setProgress((current) => Math.max(current, 34));
      setProgressLabel('Running initial scan...');
      setProgressDetail(runningScanDetail(payload.scan_mode));

      const scanResponse = await apiClient.post(`/projects/${data.id}/scan-now/`, { sync: true }, { timeout: 300000 });
      const scanResultId = scanResponse.data?.scan_result?.id;

      setProgress(100);
      setProgressLabel('Scan complete');
      setProgressDetail('Opening the detailed security report.');
      stopProgress();

      if (scanResultId) {
        navigate(`/scans/${scanResultId}`);
      } else if (!(await openLatestAvailableScan(data.id))) {
        navigate(`/projects/${data.id}`);
      }
    } catch (requestError) {
      stopProgress();
      setProgress(0);
      if (createdProjectId) {
        const openedLatestScan = await openLatestAvailableScan(createdProjectId);
        if (!openedLatestScan) {
          navigate(`/projects/${createdProjectId}`);
        }
        return;
      }
      const nextFieldErrors = extractApiFieldErrors(requestError);
      setFieldErrors(nextFieldErrors);
      setSaveError(extractApiErrorMessage(requestError, 'Unable to create the project and run the first scan.', nextFieldErrors));
    } finally {
      stopProgress();
      setSaving(false);
    }
  };

  if (loading) return <Loader label="Loading project..." />;

  if (saving && mode !== 'edit') {
    return (
      <div className="page-grid">
        <div className="page-header-row">
          <div>
            <div className="eyebrow">Project Setup</div>
            <h2>Creating project</h2>
            <p>Your first scan is running now. AEGIS AI will open the detailed report as soon as the results are ready.</p>
          </div>
        </div>
        <Loader label={progressLabel} progress={progress} detail={progressDetail} />
      </div>
    );
  }

  const currentMode = project?.scan_mode || requestedMode;

  return (
    <div className="page-grid">
      <div className="page-header-row">
        <div>
          <div className="eyebrow">Project Setup</div>
          <h2>{mode === 'edit' ? 'Edit project' : 'Create project'}</h2>
          <p>{modeDescription(currentMode)}</p>
        </div>
      </div>
      {saveError ? <div className="alert error">{saveError}</div> : null}
      <ProjectForm initialValues={project} initialMode={currentMode} onSubmit={handleSubmit} loading={saving} fieldErrors={fieldErrors} />
    </div>
  );
}
