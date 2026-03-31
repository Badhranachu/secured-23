import { Link } from 'react-router-dom';

import { Badge, Card } from '../common/UI';

export function DataTable({ columns, rows, emptyText = 'No records found.' }) {
  if (!rows.length) {
    return <Card><p>{emptyText}</p></Card>;
  }

  return (
    <div className="table-wrap card">
      <table className="data-table">
        <thead>
          <tr>
            {columns.map((column) => <th key={column.key}>{column.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr key={row.id || rowIndex}>
              {columns.map((column) => {
                const value = typeof column.render === 'function' ? column.render(row) : row[column.key];
                return <td key={column.key}>{value}</td>;
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function SeverityBadge({ severity }) {
  const tone = severity === 'critical' ? 'danger' : severity === 'warning' ? 'warning' : 'neutral';
  return <Badge tone={tone}>{severity}</Badge>;
}

export function StatusBadge({ status }) {
  const normalized = String(status || 'unknown').toLowerCase();
  let tone = 'neutral';
  if (['success', 'found', 'running', 'acceptable'].includes(normalized)) tone = normalized === 'running' ? 'warning' : 'success';
  else if (['failed', 'check_failed', 'danger', 'critical', 'missing'].includes(normalized)) tone = 'danger';
  else if (['partial', 'warning', 'weak'].includes(normalized)) tone = 'warning';
  else if (['not_found', 'not_available', 'pending', 'info', 'unknown'].includes(normalized)) tone = 'neutral';
  return <Badge tone={tone}>{normalized.replace(/_/g, ' ')}</Badge>;
}

export function LinkCell({ to, children }) {
  return <Link className="text-link" to={to}>{children}</Link>;
}
