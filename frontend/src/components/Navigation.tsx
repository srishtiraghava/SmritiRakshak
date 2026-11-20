import React from 'react';
import { Activity, Archive, Database, FileClock, LayoutDashboard, ShieldAlert, Zap } from 'lucide-react';

export type ScreenId = 'overview' | 'explorer' | 'threats' | 'quarantine' | 'audit' | 'simulator';

interface NavigationProps {
  currentScreen: ScreenId;
  onSelectScreen: (screen: ScreenId) => void;
  quarantineCount?: number;
  isOpen: boolean;
}

const items = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'explorer', label: 'Memory explorer', icon: Database },
  { id: 'threats', label: 'Threat detection', icon: ShieldAlert },
  { id: 'quarantine', label: 'Quarantine', icon: Archive },
  { id: 'audit', label: 'Audit trail', icon: FileClock },
  { id: 'simulator', label: 'Attack simulator', icon: Zap },
] as const;

export const Navigation: React.FC<NavigationProps> = ({ currentScreen, onSelectScreen, quarantineCount = 0, isOpen }) => (
  <>
    <button className={`nav-backdrop ${isOpen ? 'is-visible' : ''}`} type="button" aria-label="Close navigation" tabIndex={isOpen ? 0 : -1} onClick={() => onSelectScreen(currentScreen)} />
    <aside className={`sidebar ${isOpen ? 'is-open' : ''}`}>
      <p className="sidebar-label">Workspace</p>
      <nav id="primary-navigation" className="sidebar-nav" aria-label="Primary navigation">
        {items.map(({ id, label, icon: Icon }) => {
          const active = currentScreen === id;
          return (
            <button key={id} type="button" className={`sidebar-item ${active ? 'is-active' : ''}`} aria-current={active ? 'page' : undefined} onClick={() => onSelectScreen(id)}>
              <Icon aria-hidden="true" />
              <span className="sidebar-item-label">{label}</span>
              {id === 'quarantine' && quarantineCount > 0 && <span className="sidebar-count" aria-label={`${quarantineCount} quarantined records`}>{quarantineCount}</span>}
            </button>
          );
        })}
      </nav>
      <div className="sidebar-footer">
        <strong><Activity size={14} aria-hidden="true" /> Security workflows</strong>
        Inspect, investigate, and review memory decisions.
      </div>
    </aside>
  </>
);
