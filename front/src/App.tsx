import React, { useState } from 'react';
import { Header } from './components/Header';
import { StatsCards } from './components/StatsCards';
import { TabNavigation } from './components/TabNavigation';
import { SecurityAlerts } from './components/SecurityAlerts';
import { NetworkTopology } from './components/NetworkTopology';
import { ThreatIntelligence } from './components/ThreatIntelligence';
import { PreventionSystem } from './components/PreventionSystem';
import { useMonitoring } from './hooks/useMonitoring';

function App() {
  const [activeTab, setActiveTab] = useState('monitoring');
  const {
    alerts,
    systemMetrics,
    threatStats,
    monitoringStatus,
    loading,
    startMonitoring,
    stopMonitoring,
    refreshAlerts,
    // Prevention system props
    preventionActions,
    preventionSettings,
    preventionStatus,
    preventionLoading,
    blockIP,
    unblockIP,
    updatePreventionSettings,
    refreshPreventionActions
  } = useMonitoring();

  const renderTabContent = () => {
    switch (activeTab) {
      case 'monitoring':
        return (
          <div className="px-6 py-4">
            <SecurityAlerts alerts={alerts} lastUpdate={monitoringStatus.lastUpdate} />
          </div>
        );
      case 'topology':
        return (
          <div className="px-6 py-4">
            <NetworkTopology alerts={alerts} />
          </div>
        );
      case 'intelligence':
        return (
          <div className="px-6 py-4">
            <ThreatIntelligence alerts={alerts} />
          </div>
        );
      case 'prevention':
        return (
          <div className="px-6 py-4">
            <PreventionSystem 
              alerts={alerts}
              preventionActions={preventionActions}
              preventionSettings={preventionSettings}
              preventionStatus={preventionStatus}
              loading={preventionLoading}
              onBlockIP={blockIP}
              onUnblockIP={unblockIP}
              onUpdateSettings={updatePreventionSettings}
              onRefresh={refreshPreventionActions}
            />
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen bg-slate-900">
      <Header
        monitoringStatus={monitoringStatus}
        onStartMonitoring={startMonitoring}
        onStopMonitoring={stopMonitoring}
        loading={loading}
      />
      
      <StatsCards
        systemMetrics={systemMetrics}
        threatStats={threatStats}
      />
      
      <TabNavigation
        activeTab={activeTab}
        onTabChange={setActiveTab}
      />
      
      {renderTabContent()}
    </div>
  );
}

export default App;