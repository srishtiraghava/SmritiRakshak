import React from 'react';
import {
  LayoutDashboard,
  Database,
  ShieldAlert,
  Lock,
  FileText,
  Zap,
} from 'lucide-react';

export type ScreenId = 'overview' | 'explorer' | 'threats' | 'quarantine' | 'audit' | 'simulator';

interface NavigationProps {
  currentScreen: ScreenId;
  onSelectScreen: (screen: ScreenId) => void;
  quarantineCount?: number;
}

export const Navigation: React.FC<NavigationProps> = ({
  currentScreen,
  onSelectScreen,
  quarantineCount = 0,
}) => {
  const items: {
    id: ScreenId;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: number;
  }[] = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'explorer', label: 'Memory Explorer', icon: Database },
    { id: 'threats', label: 'Threat Detection', icon: ShieldAlert },
    { id: 'quarantine', label: 'Quarantine Center', icon: Lock, badge: quarantineCount },
    { id: 'audit', label: 'Audit Trail', icon: FileText },
    { id: 'simulator', label: 'Attack Simulator', icon: Zap },
  ];

  return (
    <aside className="w-64 border-r border-cyber-border bg-cyber-surface/60 flex flex-col shrink-0">
      <div className="p-4 border-b border-cyber-border/60">
        <span className="text-[11px] font-mono tracking-wider uppercase text-cyber-muted font-medium">
          Navigation & Controls
        </span>
      </div>

      <nav className="p-3 space-y-1 flex-1">
        {items.map((item) => {
          const Icon = item.icon;
          const isActive = currentScreen === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onSelectScreen(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-md text-xs font-medium transition-all ${
                isActive
                  ? 'bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-surfaceHover border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyber-accent' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>

              {item.badge !== undefined && item.badge > 0 && (
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-orange-950 text-orange-400 border border-orange-800 font-semibold">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer Info Box */}
      <div className="p-4 border-t border-cyber-border bg-cyber-bg/40 text-[11px] text-cyber-muted space-y-1 font-mono">
        <div className="flex justify-between">
          <span>STORAGE:</span>
          <span className="text-slate-300">4 Tiers</span>
        </div>
        <div className="flex justify-between">
          <span>FAIL-CLOSED:</span>
          <span className="text-emerald-400">ACTIVE</span>
        </div>
      </div>
    </aside>
  );
};
