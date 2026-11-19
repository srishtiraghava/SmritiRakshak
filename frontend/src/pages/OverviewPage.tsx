import React from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  Ban,
  Activity,
  Layers,
  Zap,
  RefreshCw,
  Database,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { DashboardStatsResponse, HealthResponse } from '../api/types';
import { DecisionBadge } from '../components/StatusBadge';
import { RiskScoreGauge } from '../components/RiskScoreGauge';

interface OverviewPageProps {
  stats: DashboardStatsResponse | null;
  health: HealthResponse | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  onNavigateToSimulator: () => void;
  onSelectMemory: (id: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  stats,
  health,
  loading,
  error,
  onRefresh,
  onNavigateToSimulator,
  onSelectMemory,
}) => {
  // Loading state when initial telemetry has not arrived
  if (loading && !stats && !error) {
    return (
      <div className="flex-1 p-16 flex items-center justify-center">
        <div className="text-center space-y-3 font-mono">
          <Activity className="w-8 h-8 text-cyber-accent animate-spin mx-auto" />
          <p className="text-xs text-cyber-muted">Connecting to PostgreSQL and compiling telemetry...</p>
        </div>
      </div>
    );
  }

  // Error state when database or telemetry endpoint failed
  if (error && !stats) {
    return (
      <div className="p-8 max-w-7xl mx-auto space-y-6">
        <div className="p-6 rounded-xl bg-red-950/30 border border-red-900/60 space-y-4">
          <div className="flex items-center gap-2.5 text-red-400 font-mono font-semibold text-sm">
            <XCircle className="w-5 h-5 shrink-0" />
            <span>FAILED TO LOAD DATABASE TELEMETRY</span>
          </div>
          <p className="text-xs text-slate-300 font-mono leading-relaxed">
            {error}
          </p>
          <div className="pt-2">
            <button
              onClick={onRefresh}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-red-900/40 hover:bg-red-800/60 text-red-200 border border-red-700/60 text-xs font-mono font-semibold transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Retry Connection
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Format risk score distribution for Recharts
  const riskChartData = stats
    ? Object.entries(stats.risk_score_distribution || {}).map(([band, count]) => ({
        band,
        count,
      }))
    : [];

  // Format threat categories for Recharts
  const threatChartData = stats
    ? Object.entries(stats.threat_category_distribution || {}).map(([category, count]) => ({
        name: category.replace('_', ' ').toUpperCase(),
        value: count,
      }))
    : [];

  const PIE_COLORS = ['#ef4444', '#f59e0b', '#38bdf8', '#a855f7'];
  const isDbConnected = health?.database === 'connected';

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Top Header / Action Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-cyber-border">
        <div>
          <h2 className="text-xl font-semibold text-slate-100 font-mono tracking-wide">
            SECURITY OVERVIEW
          </h2>
          <p className="text-xs text-cyber-muted mt-0.5">
            Real-time memory firewall telemetry & segregated storage metrics
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyber-card border border-cyber-border text-xs font-mono text-slate-300 hover:text-white transition-colors disabled:opacity-50"
            title="Refresh database metrics"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyber-accent' : ''}`} />
            <span>Sync Telemetry</span>
          </button>

          <button
            onClick={onNavigateToSimulator}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyber-accent/10 border border-cyber-accent/40 text-cyber-accent hover:bg-cyber-accent/20 text-xs font-mono font-medium transition-colors shadow-sm"
          >
            <Zap className="w-4 h-4" />
            ATTACK SIMULATOR
          </button>
        </div>
      </div>

      {/* Independent Database Infrastructure Banner */}
      <div className="p-4 rounded-xl bg-cyber-card border border-cyber-border/80 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyber-bg border border-cyber-border flex items-center justify-center text-cyber-accent shrink-0">
            <Database className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-slate-200 font-semibold">PostgreSQL Storage Engine</span>
              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border ${
                isDbConnected
                  ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/40'
                  : 'bg-red-950/60 text-red-400 border-red-800/40'
              }`}>
                {isDbConnected ? (
                  <>
                    <CheckCircle2 className="w-3 h-3" />
                    CONNECTED
                  </>
                ) : (
                  <>
                    <XCircle className="w-3 h-3" />
                    DISCONNECTED
                  </>
                )}
              </span>
            </div>
            <p className="text-[11px] text-cyber-muted mt-0.5">
              SQLAlchemy 2.0 ORM with psycopg 3 driver • 4 Segregated physical tables
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-cyber-muted text-[11px] border-t md:border-t-0 md:border-l border-cyber-border/60 pt-2 md:pt-0 md:pl-4">
          <div>
            <span className="text-cyber-dim block text-[10px] uppercase">Storage Tiers</span>
            <span className="text-slate-200">4 Segregated Tables</span>
          </div>
          <div>
            <span className="text-cyber-dim block text-[10px] uppercase">Fail-Closed</span>
            <span className="text-emerald-400 font-semibold">ENFORCED</span>
          </div>
          <div>
            <span className="text-cyber-dim block text-[10px] uppercase">Simulator State</span>
            <span className="text-cyber-accent">Zero-Persistence</span>
          </div>
        </div>
      </div>

      {/* Primary KPI Metric Cards (Physical Tiers) */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
        {/* Total Processed */}
        <div className="p-4 rounded-xl bg-cyber-card border border-cyber-border/80 flex flex-col justify-between">
          <div className="flex items-center justify-between text-cyber-muted text-xs font-mono">
            <span>PROCESSED</span>
            <Layers className="w-4 h-4 text-cyber-muted" />
          </div>
          <div className="mt-3">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {stats?.total_processed ?? 0}
            </span>
            <span className="text-[10px] text-cyber-muted block mt-1 leading-tight">
              Sum of 4 physical tiers.<br />Simulator runs excluded.
            </span>
          </div>
        </div>

        {/* ALLOW (Trusted) */}
        <div className="p-4 rounded-xl bg-cyber-card border border-emerald-900/30 flex flex-col justify-between">
          <div className="flex items-center justify-between text-emerald-400 text-xs font-mono">
            <span>TRUSTED</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-3">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              {stats?.trusted_count ?? 0}
            </span>
            <span className="text-[10px] text-cyber-muted block mt-1">
              trusted_memories
            </span>
          </div>
        </div>

        {/* FLAG (Review) */}
        <div className="p-4 rounded-xl bg-cyber-card border border-amber-900/30 flex flex-col justify-between">
          <div className="flex items-center justify-between text-amber-400 text-xs font-mono">
            <span>FLAGGED</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-3">
            <span className="text-2xl font-bold font-mono text-amber-400">
              {stats?.flagged_count ?? 0}
            </span>
            <span className="text-[10px] text-cyber-muted block mt-1">
              pending_review_memories
            </span>
          </div>
        </div>

        {/* QUARANTINE */}
        <div className="p-4 rounded-xl bg-cyber-card border border-orange-900/30 flex flex-col justify-between">
          <div className="flex items-center justify-between text-orange-400 text-xs font-mono">
            <span>QUARANTINED</span>
            <AlertOctagon className="w-4 h-4 text-orange-400" />
          </div>
          <div className="mt-3">
            <span className="text-2xl font-bold font-mono text-orange-400">
              {stats?.quarantined_count ?? 0}
            </span>
            <span className="text-[10px] text-cyber-muted block mt-1">
              quarantined_memories
            </span>
          </div>
        </div>

        {/* BLOCK */}
        <div className="p-4 rounded-xl bg-cyber-card border border-red-900/30 flex flex-col justify-between col-span-2 md:col-span-1">
          <div className="flex items-center justify-between text-red-400 text-xs font-mono">
            <span>BLOCKED</span>
            <Ban className="w-4 h-4 text-red-400" />
          </div>
          <div className="mt-3">
            <span className="text-2xl font-bold font-mono text-red-400">
              {stats?.blocked_count ?? 0}
            </span>
            <span className="text-[10px] text-cyber-muted block mt-1">
              security_audit_events
            </span>
          </div>
        </div>
      </div>

      {/* Visual Telemetry Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Risk Score Distribution */}
        <div className="p-5 rounded-xl bg-cyber-card border border-cyber-border space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-200">
              Risk Score Distribution
            </h3>
            <span className="text-[11px] font-mono text-cyber-muted">Actual DB Scores</span>
          </div>

          <div className="h-56">
            {riskChartData.some((d) => d.count > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={riskChartData}>
                  <XAxis
                    dataKey="band"
                    stroke="#64748b"
                    fontSize={11}
                    tickLine={false}
                    axisLine={{ stroke: '#1e293b' }}
                  />
                  <YAxis
                    stroke="#64748b"
                    fontSize={11}
                    tickLine={false}
                    axisLine={{ stroke: '#1e293b' }}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f141d',
                      border: '1px solid #1f293d',
                      borderRadius: '8px',
                      fontSize: '12px',
                      fontFamily: 'monospace',
                    }}
                  />
                  <Bar dataKey="count" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-cyber-muted font-mono">
                No risk telemetry recorded yet.
              </div>
            )}
          </div>
        </div>

        {/* Threat Category Distribution */}
        <div className="p-5 rounded-xl bg-cyber-card border border-cyber-border space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-200">
              Threat Category Distribution
            </h3>
            <span className="text-[11px] font-mono text-cyber-muted">Detector Class</span>
          </div>

          <div className="h-56">
            {threatChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={threatChartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    innerRadius={50}
                    label={({ name, percent }: any) => `${name} (${(percent * 100).toFixed(0)}%)`}
                    labelLine={false}
                    fontSize={10}
                  >
                    {threatChartData.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f141d',
                      border: '1px solid #1f293d',
                      borderRadius: '8px',
                      fontSize: '12px',
                      fontFamily: 'monospace',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-cyber-muted font-mono">
                No threat categories recorded in database.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Security Events Stream */}
      <div className="p-5 rounded-xl bg-cyber-card border border-cyber-border space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-200">
            Recent Security Activity
          </h3>
          <span className="text-[11px] font-mono text-cyber-muted">Live Database Stream</span>
        </div>

        {stats?.recent_events && stats.recent_events.length > 0 ? (
          <div className="divide-y divide-cyber-border/50">
            {stats.recent_events.map((evt) => (
              <div
                key={evt.id}
                onClick={() => onSelectMemory(evt.id)}
                className="py-3 flex items-center justify-between hover:bg-cyber-surfaceHover/50 px-2 rounded-lg cursor-pointer transition-colors"
              >
                <div className="flex items-center gap-3">
                  <DecisionBadge decision={evt.decision} size="sm" />
                  <div>
                    <span className="font-mono text-xs text-slate-200 block">{evt.id}</span>
                    <span className="text-[11px] text-cyber-muted">{evt.summary}</span>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-right">
                  <RiskScoreGauge score={evt.risk_score} showBar={false} />
                  <span className="text-[11px] font-mono text-cyber-muted hidden sm:block">
                    {new Date(evt.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-8 text-center text-xs font-mono text-cyber-muted">
            No recent activity recorded in PostgreSQL tables.
          </div>
        )}
      </div>
    </div>
  );
};
