export function Card({ title, action, children, className = '' }) {
  return (
    <section className={`card ${className}`.trim()}>
      {(title || action) && (
        <div className="card-header">
          <h3>{title}</h3>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function StatCard({ label, value, hint }) {
  return (
    <Card className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value ?? 'N/A'}</div>
      {hint ? <div className="stat-hint">{hint}</div> : null}
    </Card>
  );
}

export function Badge({ children, tone = 'neutral' }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function Loader({ label = 'Loading...', progress = null, detail = '' }) {
  const safeProgress = typeof progress === 'number'
    ? Math.max(0, Math.min(100, Math.round(progress)))
    : null;

  return (
    <div className={`loader ${safeProgress !== null ? 'loader-progress card' : ''}`.trim()}>
      <div className="loader-label">{label}</div>
      {detail ? <div className="loader-detail">{detail}</div> : null}
      {safeProgress !== null ? (
        <>
          <div className="progress-track">
            <div className="progress-fill" style={{ width: `${safeProgress}%` }} />
          </div>
          <div className="progress-value">{safeProgress}%</div>
        </>
      ) : null}
    </div>
  );
}

export function EmptyState({ title, description, action }) {
  return (
    <Card className="empty-state">
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </Card>
  );
}
