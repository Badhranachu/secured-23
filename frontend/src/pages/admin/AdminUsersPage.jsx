import { useEffect, useState } from 'react';

import apiClient from '../../api/client';
import { Loader } from '../../components/common/UI';
import { DataTable } from '../../components/tables/DataTable';
import { formatDateTime } from '../../utils/formatters';

export function AdminUsersPage() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient.get('/auth/users/').then((response) => setUsers(response.data.results || response.data)).finally(() => setLoading(false));
  }, []);

  if (loading) return <Loader label="Loading users..." />;

  return <div className="page-grid"><div className="page-header-row"><div><div className="eyebrow">Admin Users</div><h2>User management</h2></div></div><DataTable columns={[{ key: 'name', label: 'Name' }, { key: 'email', label: 'Email' }, { key: 'role', label: 'Role' }, { key: 'is_active', label: 'Active', render: (row) => row.is_active ? 'Yes' : 'No' }, { key: 'last_login', label: 'Last Login', render: (row) => formatDateTime(row.last_login) }, { key: 'created_at', label: 'Created', render: (row) => formatDateTime(row.created_at) }]} rows={users} /></div>;
}
