export function formatDateTime(value) {
  if (!value) return 'Not available';
  return new Date(value).toLocaleString();
}

export function formatScore(value) {
  return value === null || value === undefined ? 'Not available' : `${value}`;
}

export function formatValue(value, fallback = 'Not available') {
  if (value === null || value === undefined || value === '') return fallback;
  if (Array.isArray(value)) return value.length ? value.join(', ') : fallback;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return `${value}`;
}
