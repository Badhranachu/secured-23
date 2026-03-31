import { useEffect, useMemo, useState } from 'react';

import { Badge } from '../common/UI';
import { evaluatePasswordStrength, passwordTone } from '../../utils/passwordStrength';

const initialState = {
  name: '',
  domain: '',
  scan_mode: 'basic',
  github_url: '',
  frontend_github_url: '',
  backend_github_url: '',
  api_base_url: '',
  api_list: '',
  stack_name: '',
  subdomains: '',
  test_email: '',
  test_password: '',
  server_ip_address: '',
  server_password: '',
  access_token: '',
  scan_enabled: false,
  scan_frequency: 'manual',
  notification_email: '',
};

const targetPlaceholder = 'example.com, 192.168.1.10:8080, or http://192.168.1.10:8080';

const modeContent = {
  basic: {
    title: 'Basic Target Scan',
    description: 'Enter a target domain, IP address, or URL with port. AEGIS AI will inspect reachability, TLS, headers, common exposure, and produce a quick risk summary.',
    button: 'Start Basic Scan',
  },
  advanced: {
    title: 'Advanced Website + GitHub Scan',
    description: 'Enter the target domain, IP, or URL with port and add the main GitHub repository. If you also have a separate backend repository, add it in the second GitHub field. AEGIS AI will inspect the site, find repo issues, map them to files, and prepare auto-pushable fixes.',
    button: 'Start Advanced Scan',
  },
  server: {
    title: 'Server + GitHub Review Scan',
    description: 'Enter the target domain, both GitHub repositories when available, a test account for API checks, and the server access details. AEGIS AI will keep the project ready for malware review, API verification, and server issue investigation.',
    button: 'Start Server Scan',
  },
};

function renderFieldError(fieldErrors, name) {
  if (!fieldErrors || !fieldErrors[name]) return null;
  return <div className="field-error">{fieldErrors[name]}</div>;
}

function PasswordStrengthHint({ label, strength }) {
  const percent = Math.max(10, Math.round(((strength?.score || 0) / (strength?.max_score || 6)) * 100));
  const level = strength?.level || 'not_available';
  const tone = passwordTone(level);

  return (
    <div className={`password-strength ${level}`}>
      <div className="password-strength-top">
        <strong>{label}</strong>
        <Badge tone={tone}>{strength?.label || 'Not available'}</Badge>
      </div>
      <div className="password-strength-track">
        <div className={`password-strength-fill ${level}`} style={{ width: `${percent}%` }} />
      </div>
      <div className="password-strength-summary">{strength?.summary || 'No password entered yet.'}</div>
      <ul className="password-strength-tips">
        {(strength?.suggestions || []).slice(0, 3).map((tip) => <li key={tip}>{tip}</li>)}
      </ul>
    </div>
  );
}

function renderTextField(form, handleChange, fieldErrors, name, label, placeholder, options = {}) {
  const { required = false, type = 'text', children = null } = options;
  return (
    <label key={name} className="field">
      <span>{label}</span>
      <input
        type={type}
        name={name}
        value={form[name] || ''}
        onChange={handleChange}
        placeholder={placeholder}
        required={required}
      />
      {children}
      {renderFieldError(fieldErrors, name)}
    </label>
  );
}

export function ProjectForm({ initialValues, initialMode = 'basic', onSubmit, loading, fieldErrors = {} }) {
  const [form, setForm] = useState({ ...initialState, scan_mode: initialMode || 'basic' });

  useEffect(() => {
    if (initialValues) {
      const legacyRepo = initialValues.github_url || '';
      setForm({
        ...initialState,
        ...initialValues,
        frontend_github_url: initialValues.frontend_github_url || (!initialValues.backend_github_url ? legacyRepo : ''),
        backend_github_url: initialValues.backend_github_url || '',
        github_url: legacyRepo,
        test_password: '',
        server_password: '',
        access_token: '',
      });
    }
  }, [initialValues]);

  useEffect(() => {
    if (!initialValues) {
      setForm((current) => ({ ...current, scan_mode: initialMode || current.scan_mode || 'basic' }));
    }
  }, [initialMode, initialValues]);

  const copy = useMemo(() => modeContent[form.scan_mode] || modeContent.basic, [form.scan_mode]);
  const typedTestPasswordStrength = useMemo(() => evaluatePasswordStrength(form.test_password, [form.name, form.domain, form.test_email, form.notification_email]), [form.test_password, form.name, form.domain, form.test_email, form.notification_email]);
  const typedServerPasswordStrength = useMemo(() => evaluatePasswordStrength(form.server_password, [form.name, form.domain, form.server_ip_address, form.notification_email]), [form.server_password, form.name, form.domain, form.server_ip_address, form.notification_email]);
  const testPasswordStrength = form.test_password ? typedTestPasswordStrength : (initialValues?.test_password_strength || typedTestPasswordStrength);
  const serverPasswordStrength = form.server_password ? typedServerPasswordStrength : (initialValues?.server_password_strength || typedServerPasswordStrength);

  const handleChange = (event) => {
    const { name, value, type, checked } = event.target;
    setForm((current) => ({ ...current, [name]: type === 'checkbox' ? checked : value }));
  };

  const setMode = (mode) => {
    setForm((current) => ({ ...current, scan_mode: mode }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    const payload = { ...form };
    if (!payload.name) {
      delete payload.name;
    }
    if (payload.scan_mode === 'basic') {
      payload.github_url = '';
      payload.frontend_github_url = '';
      payload.backend_github_url = '';
      payload.api_base_url = '';
      payload.api_list = '';
      payload.stack_name = '';
      payload.subdomains = '';
      payload.test_email = '';
      payload.test_password = '';
      payload.server_ip_address = '';
      payload.server_password = '';
      payload.access_token = '';
    } else if (payload.scan_mode === 'advanced') {
      payload.github_url = payload.frontend_github_url || '';
      payload.stack_name = '';
      payload.notification_email = '';
      payload.access_token = '';
      payload.test_email = '';
      payload.test_password = '';
      payload.server_ip_address = '';
      payload.server_password = '';
      payload.subdomains = '';
      payload.api_list = '';
      payload.scan_enabled = false;
      payload.scan_frequency = 'manual';
    } else {
      payload.github_url = payload.frontend_github_url || '';
      payload.stack_name = '';
      payload.notification_email = '';
      payload.access_token = '';
      payload.subdomains = '';
      payload.api_list = '';
      payload.scan_enabled = false;
      payload.scan_frequency = 'manual';
    }
    await onSubmit(payload);
  };

  return (
    <form className="project-form card" onSubmit={handleSubmit}>
      <div className="mode-picker">
        <button type="button" className={form.scan_mode === 'basic' ? 'mode-card active' : 'mode-card'} onClick={() => setMode('basic')}>
          <div className="mode-chip">Basic</div>
          <h3>Domain / IP</h3>
          <p>Fast risk overview from a target host or IP.</p>
        </button>
        <button type="button" className={form.scan_mode === 'advanced' ? 'mode-card active' : 'mode-card'} onClick={() => setMode('advanced')}>
          <div className="mode-chip">Advanced</div>
          <h3>Website + GitHub</h3>
          <p>Fetch domain risk details and inspect connected GitHub code in one scan.</p>
        </button>
        <button type="button" className={form.scan_mode === 'server' ? 'mode-card active' : 'mode-card'} onClick={() => setMode('server')}>
          <div className="mode-chip">Server</div>
          <h3>Server + GitHub</h3>
          <p>Prepare a deeper review with repo, API test account, and server access details.</p>
        </button>
      </div>

      <div className="mode-explainer">
        <div className="eyebrow">Selected Flow</div>
        <h2>{copy.title}</h2>
        <p>{copy.description}</p>
      </div>

      {form.scan_mode === 'basic' ? (
        <div className="basic-form-grid">
          <label className="field full-width">
            <span>Target Domain / IP / URL With Port</span>
            <input name="domain" value={form.domain || ''} onChange={handleChange} placeholder={targetPlaceholder} required />
            {renderFieldError(fieldErrors, 'domain')}
          </label>

          <div className="form-grid two-columns">
            <label className="toggle-field">
              <input type="checkbox" name="scan_enabled" checked={Boolean(form.scan_enabled)} onChange={handleChange} />
              <span>Enable scheduled scanning</span>
            </label>
            <label className="field">
              <span>Scan Frequency</span>
              <select name="scan_frequency" value={form.scan_frequency} onChange={handleChange}>
                <option value="manual">Manual</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
              {renderFieldError(fieldErrors, 'scan_frequency')}
            </label>
          </div>
        </div>
      ) : form.scan_mode === 'advanced' ? (
        <div className="form-grid two-columns">
          {[
            ['domain', 'Target Domain / IP / URL With Port', targetPlaceholder, { required: true }],
            ['frontend_github_url', 'Main GitHub Repo URL', 'Required. Use this for a single repo or your frontend repo.', { required: true }],
            ['api_base_url', 'API Base URL', 'Optional, defaults from the target. Use http://... for custom running ports.'],
            ['backend_github_url', 'Backend GitHub Repo URL (Optional)', 'Optional. Add only when backend is in a separate GitHub repo.'],
          ].map(([name, label, placeholder, options]) => renderTextField(form, handleChange, fieldErrors, name, label, placeholder, options || {}))}
        </div>
      ) : (
        <>
          <div className="form-grid two-columns">
            {[
              ['domain', 'Target Domain / IP / URL With Port', targetPlaceholder, { required: true }],
              ['frontend_github_url', 'Main GitHub Repo URL', 'Required. Use this for a single repo or your frontend repo.', { required: true }],
              ['api_base_url', 'API Base URL', 'Optional, defaults from the target. Use http://... for custom running ports.'],
              ['backend_github_url', 'Backend GitHub Repo URL (Optional)', 'Optional. Add only when backend is in a separate GitHub repo.'],
              ['test_email', 'Test Account Email', 'Optional. Used when checking authenticated APIs.', { type: 'email' }],
              ['test_password', 'Test Account Password', 'Optional. Stored securely and used for API login checks.', { type: 'password', children: <PasswordStrengthHint label="Test account strength" strength={testPasswordStrength} /> }],
              ['server_ip_address', 'Server IP / Host', 'Required for server review mode. Example: 192.168.1.10 or server.example.com', { required: true }],
              ['server_password', 'Server Password', 'Optional. Stored securely for server-access workflows.', { type: 'password', children: <PasswordStrengthHint label="Server password strength" strength={serverPasswordStrength} /> }],
            ].map(([name, label, placeholder, options]) => renderTextField(form, handleChange, fieldErrors, name, label, placeholder, options || {}))}
          </div>

          <div className="grid-two">
            <div className="subtle-card card">
              <h3>Password rules</h3>
              <p>For safer scans, use at least 12 characters, mix upper/lowercase letters, numbers, and symbols, and avoid project names, domains, or easy words like admin or password.</p>
            </div>
            <div className="subtle-card card">
              <h3>What AEGIS will suggest</h3>
              <p>If a password is weak, the scan will add hardening advice, mark the strength level with colors, and include the issue in remediation guidance. Malware-like code patterns will also trigger a serious alert email.</p>
            </div>
          </div>
        </>
      )}

      <div className="form-actions">
        <button className="primary-button" type="submit" disabled={loading}>{loading ? 'Saving...' : copy.button}</button>
      </div>
    </form>
  );
}
