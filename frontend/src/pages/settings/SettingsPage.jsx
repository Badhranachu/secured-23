import { useEffect, useState } from 'react';

import { useAuth } from '../../app/auth';
import apiClient from '../../api/client';
import { Card, Loader } from '../../components/common/UI';
import { DataTable, StatusBadge } from '../../components/tables/DataTable';
import { formatDateTime } from '../../utils/formatters';

export function SettingsPage() {
  const auth = useAuth();
  const [activeTab, setActiveTab] = useState('profile');
  const [name, setName] = useState(auth.user?.name || '');
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [notificationData, setNotificationData] = useState(null);
  const [notificationLoading, setNotificationLoading] = useState(false);
  const [notificationMessage, setNotificationMessage] = useState('');
  const [notificationError, setNotificationError] = useState('');
  const [sendingProjectId, setSendingProjectId] = useState(null);

  useEffect(() => {
    setName(auth.user?.name || '');
  }, [auth.user]);

  useEffect(() => {
    if (activeTab !== 'notifications' || notificationData) return;
    setNotificationLoading(true);
    apiClient.get('/notifications/center/')
      .then((response) => setNotificationData(response.data))
      .catch((error) => setNotificationError(error.response?.data?.detail || 'Unable to load notification data.'))
      .finally(() => setNotificationLoading(false));
  }, [activeTab, notificationData]);

  const save = async (event) => {
    event.preventDefault();
    setSaving(true);
    await auth.updateProfile({ name });
    setMessage('Profile updated.');
    setSaving(false);
  };

  const sendLatestSummary = async (projectId) => {
    setSendingProjectId(projectId);
    setNotificationMessage('');
    setNotificationError('');
    try {
      const { data } = await apiClient.post('/notifications/send-latest-summary/', { project_id: projectId, attach_pdf: false });
      setNotificationMessage(data.detail || 'Summary email sent.');
      const refreshed = await apiClient.get('/notifications/center/');
      setNotificationData(refreshed.data);
    } catch (error) {
      setNotificationError(error.response?.data?.detail || 'Unable to send the latest summary email.');
    } finally {
      setSendingProjectId(null);
    }
  };

  if (!auth.user) return <Loader />;

  return (
    <div className="page-grid">
      <div className="page-header-row">
        <div><div className="eyebrow">Settings</div><h2>Profile and notifications</h2></div>
      </div>

      <div className="button-row">
        <button type="button" className={activeTab === 'profile' ? 'primary-button' : 'secondary-button'} onClick={() => setActiveTab('profile')}>Profile</button>
        <button type="button" className={activeTab === 'notifications' ? 'primary-button' : 'secondary-button'} onClick={() => setActiveTab('notifications')}>Notifications</button>
      </div>

      {activeTab === 'profile' ? (
        <Card title="Profile">
          <form className="settings-form" onSubmit={save}>
            {message ? <div className="alert success">{message}</div> : null}
            <label className="field"><span>Name</span><input value={name} onChange={(e) => setName(e.target.value)} /></label>
            <label className="field"><span>Email</span><input value={auth.user.email || ''} disabled /></label>
            <label className="field"><span>Role</span><input value={auth.user.role || ''} disabled /></label>
            <button className="primary-button" type="submit" disabled={saving}>{saving ? 'Saving...' : 'Save changes'}</button>
          </form>
        </Card>
      ) : notificationLoading ? (
        <Loader label="Loading notifications..." />
      ) : (
        <>
          {notificationMessage ? <div className="alert success">{notificationMessage}</div> : null}
          {notificationError ? <div className="alert error">{notificationError}</div> : null}

          <div className="grid-two report-grid">
            <Card title="Delivery Overview">
              <div className="detail-grid compact-grid">
                <div><strong>Default recipient:</strong> {notificationData?.default_recipient || auth.user.email}</div>
                <div><strong>AI provider strategy:</strong> {notificationData?.provider_strategy || 'openrouter-first'}</div>
                <div><strong>Recent email logs:</strong> {notificationData?.recent_emails?.length || 0}</div>
                <div><strong>Recent security alerts:</strong> {notificationData?.recent_alerts?.length || 0}</div>
              </div>
            </Card>

            <DataTable
              columns={[
                { key: 'name', label: 'Project' },
                { key: 'scan_mode', label: 'Mode' },
                { key: 'notification_email', label: 'Recipient' },
                { key: 'last_scanned_at', label: 'Last Scan', render: (row) => formatDateTime(row.last_scanned_at) },
                {
                  key: 'send',
                  label: 'Action',
                  render: (row) => (
                    <button
                      type="button"
                      className="secondary-button"
                      onClick={() => sendLatestSummary(row.id)}
                      disabled={sendingProjectId === row.id}
                    >
                      {sendingProjectId === row.id ? 'Sending...' : 'Send Latest Summary'}
                    </button>
                  ),
                },
              ]}
              rows={notificationData?.projects || []}
              emptyText="No projects are available for notifications yet."
            />
          </div>

          <DataTable
            columns={[
              { key: 'project_name', label: 'Project' },
              { key: 'severity', label: 'Severity' },
              { key: 'title', label: 'Latest Cybersecurity Alert' },
              { key: 'category', label: 'Category' },
              { key: 'location', label: 'Location' },
              { key: 'created_at', label: 'When', render: (row) => formatDateTime(row.created_at) },
            ]}
            rows={notificationData?.recent_alerts || []}
            emptyText="No recent alerts have been recorded yet."
          />

          <div className="grid-two report-grid">
            <DataTable
              columns={[
                { key: 'project_name', label: 'Project' },
                { key: 'subject', label: 'Email Subject' },
                { key: 'status', label: 'Status', render: (row) => <StatusBadge status={row.status} /> },
                { key: 'sent_at', label: 'Sent', render: (row) => formatDateTime(row.sent_at || row.created_at) },
                { key: 'error_message', label: 'Error', render: (row) => row.error_message || 'None' },
              ]}
              rows={notificationData?.recent_emails || []}
              emptyText="No notification emails have been logged yet."
            />

            <DataTable
              columns={[
                { key: 'project_name', label: 'Project' },
                { key: 'overall_status', label: 'GitHub Status', render: (row) => <StatusBadge status={row.overall_status} /> },
                { key: 'repo_count', label: 'Repos' },
                { key: 'scanned_file_count', label: 'Files' },
                { key: 'discovered_route_count', label: 'Routes' },
                { key: 'malware_issue_count', label: 'Malware Signals' },
                { key: 'started_at', label: 'Scan Time', render: (row) => formatDateTime(row.started_at) },
              ]}
              rows={notificationData?.github_activity || []}
              emptyText="No GitHub scan activity is available yet."
            />
          </div>
        </>
      )}
    </div>
  );
}
