import { Pie, PieChart, Cell, ResponsiveContainer, Tooltip, LineChart, Line, CartesianGrid, XAxis, YAxis, Legend } from 'recharts';

import { Card } from '../common/UI';

const palette = ['#0f766e', '#f59e0b', '#dc2626', '#2563eb', '#9333ea', '#6b7280'];

export function LineMetricChart({ title, data, dataKey, color }) {
  return (
    <Card title={title}>
      <div className="chart-frame">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="date" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Line type="monotone" dataKey={dataKey} stroke={color} strokeWidth={3} dot={{ strokeWidth: 2, r: 4 }} activeDot={{ r: 6 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}

export function CategoryPieChart({ title, data, nameKey = 'category', valueKey = 'total', onSliceClick }) {
  const clickable = typeof onSliceClick === 'function';

  return (
    <Card title={title}>
      <div className="chart-frame">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Tooltip />
            <Pie
              data={data}
              dataKey={valueKey}
              nameKey={nameKey}
              outerRadius={100}
              label
              onClick={clickable ? (entry) => onSliceClick(entry) : undefined}
              cursor={clickable ? 'pointer' : 'default'}
            >
              {data.map((entry, index) => <Cell key={entry[nameKey] || index} fill={palette[index % palette.length]} />)}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
