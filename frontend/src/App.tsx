import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Navigation, ScreenId } from './components/Navigation';
import { MemoryDetailModal } from './components/MemoryDetailModal';
import { OverviewPage } from './pages/OverviewPage';
import { ExplorerPage } from './pages/ExplorerPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { QuarantinePage } from './pages/QuarantinePage';
import { AuditTrailPage } from './pages/AuditTrailPage';
import { SimulatorPage } from './pages/SimulatorPage';
import { api } from './api/client';
import { DashboardStatsResponse, HealthResponse, MemoryItemResponse } from './api/types';

export const App: React.FC = () => {
  const [currentScreen, setCurrentScreen] = useState<ScreenId>('overview');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [stats, setStats] = useState<DashboardStatsResponse | null>(null);
  const [statsError, setStatsError] = useState<string | null>(null);
  const [loadingStats, setLoadingStats] = useState<boolean>(false);
  const [activeModalMemory, setActiveModalMemory] = useState<MemoryItemResponse | null>(null);
  const [navigationOpen, setNavigationOpen] = useState<boolean>(false);

  // Fetch telemetry from backend & PostgreSQL
  const fetchTelemetry = async () => {
    setLoadingStats(true);

    // 1. Independent Health Probe
    try {
      const healthData = await api.getHealth();
      setHealth(healthData);
    } catch {
      setHealth({
        status: 'degraded',
        app: 'SmritiRakshak',
        version: '0.1.0',
        database: 'disconnected',
      });
    }

    // 2. Metrics & Telemetry Probe
    try {
      const statsData = await api.getDashboardStats();
      setStats(statsData);
      setStatsError(null);
    } catch (err: any) {
      setStatsError(err.message || 'Failed to query database telemetry');
    } finally {
      setLoadingStats(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
    // Poll telemetry every 30 seconds
    const interval = setInterval(fetchTelemetry, 30000);
    return () => clearInterval(interval);
  }, []);

  // Re-fetch telemetry whenever user returns to Overview
  useEffect(() => {
    if (currentScreen === 'overview') {
      fetchTelemetry();
    }
  }, [currentScreen]);

  useEffect(() => {
    if (!navigationOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setNavigationOpen(false);
    };
    document.addEventListener('keydown', closeOnEscape);
    return () => document.removeEventListener('keydown', closeOnEscape);
  }, [navigationOpen]);

  const handleSelectScreen = (screen: ScreenId) => {
    setCurrentScreen(screen);
    setNavigationOpen(false);
  };

  const handleSelectMemoryById = async (id: string) => {
    try {
      const memory = await api.getMemoryDetail(id);
      setActiveModalMemory(memory);
    } catch (err) {
      console.error('Failed to fetch memory detail:', err);
    }
  };

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <Header
        health={health}
        loading={loadingStats}
        navigationOpen={navigationOpen}
        onToggleNavigation={() => setNavigationOpen((open) => !open)}
        onRefresh={fetchTelemetry}
      />

      <div className="app-workspace">
        <Navigation
          currentScreen={currentScreen}
          onSelectScreen={handleSelectScreen}
          quarantineCount={stats?.quarantined_count ?? 0}
          isOpen={navigationOpen}
        />

        <main id="main-content" className="main-content" tabIndex={-1}>
          {currentScreen === 'overview' && (
            <OverviewPage
              stats={stats}
              health={health}
              loading={loadingStats}
              error={statsError}
              onRefresh={fetchTelemetry}
              onNavigateToSimulator={() => setCurrentScreen('simulator')}
              onSelectMemory={handleSelectMemoryById}
            />
          )}

          {currentScreen === 'explorer' && (
            <ExplorerPage onSelectMemory={setActiveModalMemory} />
          )}

          {currentScreen === 'threats' && <ThreatsPage />}

          {currentScreen === 'quarantine' && (
            <QuarantinePage
              onSelectMemory={setActiveModalMemory}
              onRefreshStats={fetchTelemetry}
            />
          )}

          {currentScreen === 'audit' && <AuditTrailPage />}

          {currentScreen === 'simulator' && <SimulatorPage />}
        </main>
      </div>

      {/* Memory Detail Modal / Drawer */}
      <MemoryDetailModal
        memory={activeModalMemory}
        onClose={() => setActiveModalMemory(null)}
      />
    </div>
  );
};

export default App;
