import React, { useState, useEffect } from 'react';
import { Shield, ShieldCheck, ShieldX, Clock, AlertTriangle, Trash2, Play, Pause, RefreshCw } from 'lucide-react';
import { PreventionAction, PreventionSettings, PreventionStatus, Alert } from '../types';

interface PreventionSystemProps {
  alerts: Alert[];
  preventionActions: PreventionAction[];
  preventionSettings: PreventionSettings;
  preventionStatus: PreventionStatus;
  loading: boolean;
  onBlockIP: (ip: string, duration?: number, reason?: string) => Promise<{ success: boolean; message: string }>;
  onUnblockIP: (ip: string) => Promise<{ success: boolean; message: string }>;
  onUpdateSettings: (settings: PreventionSettings) => Promise<{ success: boolean; message: string }>;
  onRefresh: () => Promise<void>;
}

export const PreventionSystem: React.FC<PreventionSystemProps> = ({
  alerts,
  preventionActions,
  preventionSettings,
  preventionStatus,
  loading,
  onBlockIP,
  onUnblockIP,
  onUpdateSettings,
  onRefresh
}) => {
  const [localSettings, setLocalSettings] = useState<PreventionSettings>(preventionSettings);
  const [manualIPInput, setManualIPInput] = useState('');
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [settingsLoading, setSettingsLoading] = useState(false);

  // Update local settings when props change
  useEffect(() => {
    setLocalSettings(preventionSettings);
  }, [preventionSettings]);

  // Show notification temporarily
  const showNotification = (type: 'success' | 'error', message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 5000);
  };

  const handleRefresh = async () => {
    if (isRefreshing) return;
    
    setIsRefreshing(true);
    try {
      await onRefresh();
      showNotification('success', 'Data refreshed successfully');
    } catch (error) {
      showNotification('error', 'Failed to refresh data');
      console.error('Refresh error:', error);
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleManualBlock = async () => {
    if (!manualIPInput.trim()) {
      showNotification('error', 'Please enter a valid IP address');
      return;
    }

    try {
      const result = await onBlockIP(
        manualIPInput.trim(),
        localSettings.blockDuration,
        'Manual block by administrator'
      );
      
      if (result.success) {
        showNotification('success', `Successfully blocked IP: ${manualIPInput.trim()}`);
        setManualIPInput('');
        // Auto-refresh after blocking
        setTimeout(() => handleRefresh(), 1000);
      } else {
        showNotification('error', result.message);
      }
    } catch (error) {
      showNotification('error', 'Failed to block IP');
    }
  };

  const handleUnblock = async (action: PreventionAction) => {
    try {
      const result = await onUnblockIP(action.ip);
      if (result.success) {
        showNotification('success', `Successfully unblocked IP: ${action.ip}`);
        // Auto-refresh after unblocking
        setTimeout(() => handleRefresh(), 1000);
      } else {
        showNotification('error', result.message);
      }
    } catch (error) {
      showNotification('error', 'Failed to unblock IP');
    }
  };

  const handleSettingsUpdate = async () => {
    if (settingsLoading) return;
    
    setSettingsLoading(true);
    try {
      const result = await onUpdateSettings(localSettings);
      if (result.success) {
        showNotification('success', 'Settings updated successfully');
        // Auto-refresh after settings update
        setTimeout(() => handleRefresh(), 500);
      } else {
        showNotification('error', result.message);
      }
    } catch (error) {
      showNotification('error', 'Failed to update settings');
    } finally {
      setSettingsLoading(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <ShieldCheck className="w-4 h-4 text-red-500" />;
      case 'expired':
        return <ShieldX className="w-4 h-4 text-gray-400" />;
      case 'manual':
        return <Shield className="w-4 h-4 text-orange-500" />;
      default:
        return <Shield className="w-4 h-4 text-gray-400" />;
    }
  };

  const getTimeRemaining = (expiresAt?: string) => {
    if (!expiresAt) return null;
    const remaining = new Date(expiresAt).getTime() - Date.now();
    if (remaining <= 0) return 'Expired';
    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  };

  return (
    <div className="space-y-6">
      {/* Notification */}
      {notification && (
        <div className={`p-4 rounded-lg border ${
          notification.type === 'success' 
            ? 'bg-green-500/20 border-green-500 text-green-400' 
            : 'bg-red-500/20 border-red-500 text-red-400'
        }`}>
          {notification.message}
        </div>
      )}

      {/* Prevention Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Total Actions</p>
              <p className="text-lg font-semibold text-white">{preventionStatus.totalBlocks}</p>
            </div>
            <div className="p-2 rounded-lg bg-blue-500/20">
              <AlertTriangle className="w-6 h-6 text-blue-400" />
            </div>
          </div>
        </div>

        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Auto Prevention</p>
              <p className="text-lg font-semibold text-white">
                {preventionStatus.autoPreventionEnabled ? 'Enabled' : 'Disabled'}
              </p>
            </div>
            <div className={`p-2 rounded-lg ${preventionStatus.autoPreventionEnabled ? 'bg-green-500/20' : 'bg-red-500/20'}`}>
              {preventionStatus.autoPreventionEnabled ? (
                <ShieldCheck className="w-6 h-6 text-green-400" />
              ) : (
                <ShieldX className="w-6 h-6 text-red-400" />
              )}
            </div>
          </div>
        </div>

        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Active Blocks</p>
              <p className="text-lg font-semibold text-white">{preventionStatus.activeBlocks}</p>
            </div>
            <div className="p-2 rounded-lg bg-red-500/20">
              <Shield className="w-6 h-6 text-red-400" />
            </div>
          </div>
        </div>

        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Threat Threshold</p>
              <p className="text-lg font-semibold text-white">{(preventionStatus.threatThreshold * 100).toFixed(0)}%</p>
            </div>
            <div className="p-2 rounded-lg bg-orange-500/20">
              <Clock className="w-6 h-6 text-orange-400" />
            </div>
          </div>
        </div>
      </div>

      {/* Prevention Settings */}
      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
          <Shield className="w-5 h-5 mr-2" />
          Prevention Settings
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Auto Prevention
            </label>
            <button
              onClick={() => setLocalSettings(prev => ({ ...prev, autoPreventionEnabled: !prev.autoPreventionEnabled }))}
              disabled={settingsLoading}
              className={`flex items-center px-4 py-2 rounded-lg transition-colors disabled:opacity-50 ${
                localSettings.autoPreventionEnabled
                  ? 'bg-green-600 hover:bg-green-700 text-white'
                  : 'bg-slate-600 hover:bg-slate-700 text-slate-300'
              }`}
            >
              {localSettings.autoPreventionEnabled ? (
                <>
                  <Play className="w-4 h-4 mr-2" />
                  Enabled
                </>
              ) : (
                <>
                  <Pause className="w-4 h-4 mr-2" />
                  Disabled
                </>
              )}
            </button>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Block Duration (seconds)
            </label>
            <input
              type="number"
              value={localSettings.blockDuration}
              onChange={(e) => setLocalSettings(prev => ({ ...prev, blockDuration: Number(e.target.value) }))}
              disabled={settingsLoading}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
              min="60"
              max="3600"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Threat Threshold
            </label>
            <input
              type="range"
              value={localSettings.threatThreshold}
              onChange={(e) => setLocalSettings(prev => ({ ...prev, threatThreshold: Number(e.target.value) }))}
              disabled={settingsLoading}
              className="w-full disabled:opacity-50"
              min="0.5"
              max="1"
              step="0.05"
            />
            <div className="text-sm text-slate-400 mt-1">
              {(localSettings.threatThreshold * 100).toFixed(0)}% confidence required
            </div>
          </div>
        </div>

        <div className="mt-6 flex justify-end">
          <button
            onClick={handleSettingsUpdate}
            disabled={settingsLoading}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:opacity-50 text-white rounded-lg transition-colors flex items-center"
          >
            {settingsLoading ? (
              <>
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                Updating...
              </>
            ) : (
              'Update Settings'
            )}
          </button>
        </div>
      </div>

      {/* Manual Block Section */}
      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
        <h3 className="text-lg font-semibold text-white mb-4">Manual IP Block</h3>
        <div className="flex gap-4">
          <input
            type="text"
            placeholder="Enter IP address (e.g., 192.168.1.100)"
            value={manualIPInput}
            onChange={(e) => setManualIPInput(e.target.value)}
            className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            onKeyPress={(e) => {
              if (e.key === 'Enter') {
                handleManualBlock();
              }
            }}
          />
          <button
            onClick={handleManualBlock}
            disabled={loading || !manualIPInput.trim()}
            className="px-6 py-2 bg-red-600 hover:bg-red-700 disabled:bg-red-800 disabled:opacity-50 text-white rounded-lg transition-colors flex items-center"
          >
            <Shield className="w-4 h-4 mr-2" />
            Block IP
          </button>
        </div>
      </div>

      {/* Prevention Actions List */}
      <div className="bg-slate-800 rounded-lg border border-slate-700">
        <div className="p-6 border-b border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-white">Prevention Actions</h3>
              <p className="text-sm text-slate-400 mt-1">Recent prevention actions and blocked IPs</p>
            </div>
            <button
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="px-4 py-2 bg-slate-600 hover:bg-slate-700 disabled:bg-slate-800 disabled:opacity-50 text-white rounded-lg transition-colors text-sm flex items-center"
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${isRefreshing ? 'animate-spin' : ''}`} />
              {isRefreshing ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>
        
        <div className="divide-y divide-slate-700">
          {preventionActions.length === 0 ? (
            <div className="p-6 text-center text-slate-400">
              No prevention actions recorded
            </div>
          ) : (
            preventionActions.map((action) => (
              <div key={action.id} className="p-4 hover:bg-slate-700/50 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    {getStatusIcon(action.status)}
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-medium text-white">{action.ip}</span>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                          action.status === 'active' 
                            ? 'bg-red-500/20 text-red-400' 
                            : action.status === 'expired'
                            ? 'bg-gray-500/20 text-gray-400'
                            : 'bg-orange-500/20 text-orange-400'
                        }`}>
                          {action.action.replace('_', ' ')}
                        </span>
                      </div>
                      <p className="text-sm text-slate-400 mt-1">{action.reason}</p>
                      <div className="flex items-center space-x-4 mt-2 text-xs text-slate-500">
                        <span>{new Date(action.timestamp).toLocaleString()}</span>
                        <span>Duration: {action.duration}s</span>
                        {action.status === 'active' && action.expiresAt && (
                          <span className="flex items-center">
                            <Clock className="w-3 h-3 mr-1" />
                            {getTimeRemaining(action.expiresAt)} remaining
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    {action.status === 'active' && (
                      <button
                        onClick={() => handleUnblock(action)}
                        disabled={loading}
                        className="px-3 py-1 bg-green-600 hover:bg-green-700 disabled:bg-green-800 disabled:opacity-50 text-white text-sm rounded transition-colors"
                      >
                        Unblock
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};