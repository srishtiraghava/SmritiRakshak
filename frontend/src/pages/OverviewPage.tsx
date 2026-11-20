import React from 'react';
import { Activity, Database, RefreshCw, ShieldAlert, ShieldCheck, Zap } from 'lucide-react';
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { DashboardStatsResponse, HealthResponse } from '../api/types';
import { DecisionBadge } from '../components/StatusBadge';
import { RiskScoreGauge } from '../components/RiskScoreGauge';
import { PageHeader } from '../components/PageHeader';

interface OverviewPageProps {
  stats: DashboardStatsResponse | null;
  health: HealthResponse | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  onNavigateToSimulator: () => void;
  onSelectMemory: (id: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ stats, health, loading, error, onRefresh, onNavigateToSimulator, onSelectMemory }) => {
  const riskChartData = stats
    ? Object.entries(stats.risk_score_distribution || {}).map(([band, count]) => ({ band, count }))
    : [];
  const threatChartData = stats
    ? Object.entries(stats.threat_category_distribution || {}).map(([category, count]) => ({ name: category.replace(/_/g, ' '), value: count }))
    : [];
  const threatColors = ['#a64d44', '#94661c', '#467f81', '#294338'];
  const tooltipStyle = { backgroundColor: '#e2eae2', border: '1px solid #9eafa2', borderRadius: '8px', color: '#263a31', fontSize: '12px' };

  return (
    <section className="page-view" aria-labelledby="overview-title">
      <PageHeader
        titleId="overview-title"
        title="Security overview"
        description="Live memory decisions, threat distribution, and service health."
        actions={(
          <>
            <button type="button" onClick={onRefresh} disabled={loading} className="btn" title="Refresh database metrics">
              <RefreshCw size={15} className={loading ? 'animate-spin' : ''} /> Refresh telemetry
            </button>
            <button type="button" onClick={onNavigateToSimulator} className="btn-primary">
              <Zap size={15} /> Attack simulator
            </button>
          </>
        )}
      />

      {error && !stats ? (
        <div className="notice notice-error" role="alert">
          <Database aria-hidden="true" />
          <div>
            <h2>Database telemetry could not be loaded</h2>
            <p>{error}</p>
            <button type="button" onClick={onRefresh} className="btn mt-3"><RefreshCw size={14} /> Retry connection</button>
          </div>
        </div>
      ) : loading && !stats ? (
        <div className="page-grid">
          <div className="skeleton" aria-label="Loading security metrics" />
          <div className="page-grid page-grid-two"><div className="skeleton" /><div className="skeleton" /></div>
          <div className="loading-state" role="status"><Activity /><p>Connecting to the security service and loading current telemetry…</p></div>
        </div>
      ) : stats ? (
        <>
          <div className="service-summary" aria-label="Current service status">
            <div className="service-summary-item">
              <span className={`health-dot ${health?.status === 'healthy' ? 'is-healthy' : 'is-error'}`} aria-hidden="true" />
              <span>Firewall</span><strong>{health?.status || stats.system_status}</strong>
            </div>
            <div className="service-summary-item">
              <Database size={15} aria-hidden="true" />
              <span>PostgreSQL</span><strong>{health?.database || stats.database_status}</strong>
            </div>
          </div>

          <section aria-label="Memory disposition totals" className="stats-ledger">
            <div className="stat-cell"><span className="stat-label">Total processed</span><strong className="stat-value">{stats.total_processed}</strong><span className="stat-note">Persisted decisions</span></div>
            <div className="stat-cell is-trusted"><span className="stat-label">Trusted</span><strong className="stat-value">{stats.trusted_count}</strong><span className="stat-note">Allowed memories</span></div>
            <div className="stat-cell is-review"><span className="stat-label">Flagged</span><strong className="stat-value">{stats.flagged_count}</strong><span className="stat-note">Pending review</span></div>
            <div className="stat-cell is-danger"><span className="stat-label">Quarantined · blocked</span><strong className="stat-value">{stats.quarantined_count} <span className="stat-divider">/</span> {stats.blocked_count}</strong><span className="stat-note">Isolated · audit only</span></div>
          </section>

          <div className="page-grid page-grid-two chart-grid">
            <section className="panel chart-panel risk-chart-panel" aria-labelledby="risk-distribution-title">
              <div className="panel-heading">
                <div><h2 id="risk-distribution-title" className="panel-title">Risk score distribution</h2><p className="panel-description">Records grouped by their stored risk band.</p></div>
              </div>
              {riskChartData.some((item) => item.count > 0) ? (
                <>
                <div className="chart-area">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={riskChartData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                      <XAxis dataKey="band" stroke="#50675a" fontSize={11} tickLine={false} axisLine={{ stroke: '#cbd7cc' }} />
                      <YAxis stroke="#50675a" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                      <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(117, 208, 176, .08)' }} />
                      <Bar dataKey="count" name="Memories" fill="#294338" maxBarSize={48} radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <dl className="risk-chart-data" aria-label="Risk score counts">
                  {riskChartData.map(({ band, count }) => <div key={band}><dt>{band}</dt><dd>{count}</dd></div>)}
                </dl>
                </>
              ) : <div className="empty-state chart-empty"><Activity aria-hidden="true" /><strong>No risk telemetry yet</strong><p>Stored decisions will appear here when available.</p></div>}
            </section>

            <section className="panel chart-panel" aria-labelledby="threat-distribution-title">
              <div className="panel-heading">
                <div><h2 id="threat-distribution-title" className="panel-title">Threat categories</h2><p className="panel-description">Detector findings recorded across memory decisions.</p></div>
              </div>
              {threatChartData.some((item) => item.value > 0) ? (
                <div className="chart-area">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={threatChartData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius="72%" innerRadius="49%" label={({ name, percent }: any) => `${name} ${(percent * 100).toFixed(0)}%`} labelLine={false} fontSize={10}>
                        {threatChartData.map((item, index) => <Cell key={item.name} fill={threatColors[index % threatColors.length]} />)}
                      </Pie>
                      <Tooltip contentStyle={tooltipStyle} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : <div className="empty-state chart-empty"><ShieldAlert aria-hidden="true" /><strong>No threat categories yet</strong><p>Recorded detector findings will appear here.</p></div>}
            </section>
          </div>

          <section className="panel recent-panel" aria-labelledby="recent-events-title">
            <div className="panel-heading">
              <div><h2 id="recent-events-title" className="panel-title">Recent decisions</h2><p className="panel-description">Select a record to review its evidence.</p></div>
              <span className="inline-message">{stats.recent_events.length} records</span>
            </div>
            {stats.recent_events.length > 0 ? (
              <div className="table-frame recent-table-frame">
                <div className="table-scroll">
                  <table aria-label="Recent security decisions">
                    <thead><tr><th scope="col">Decision</th><th scope="col">Memory</th><th scope="col">Summary</th><th scope="col">Risk</th><th scope="col">Source</th><th scope="col">Time</th><th scope="col">Open</th></tr></thead>
                    <tbody>
                      {stats.recent_events.map((event) => (
                        <tr key={event.id}>
                          <td><DecisionBadge decision={event.decision} size="sm" /></td>
                          <td className="table-link">{event.id}</td>
                          <td><span className="table-clip" title={event.summary}>{event.summary}</span></td>
                          <td><RiskScoreGauge score={event.risk_score} showBar={false} /></td>
                          <td className="table-subtle">{event.source}</td>
                          <td className="table-subtle"><time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleTimeString()}</time></td>
                          <td><button type="button" className="btn-quiet table-open" onClick={() => onSelectMemory(event.id)} aria-label={`Open memory ${event.id}`}>Inspect</button></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="empty-state"><ShieldCheck aria-hidden="true" /><strong>No recent decisions</strong><p>Newly processed memories will appear here.</p></div>
            )}
          </section>
        </>
      ) : null}
    </section>
  );
};
