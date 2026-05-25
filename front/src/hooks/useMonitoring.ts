import { useState, useEffect, useCallback } from 'react';
import { Alert, SystemMetrics, ThreatStats, MonitoringStatus, PreventionAction, PreventionSettings, PreventionStatus } from '../types';
import { ApiService } from '../services/api';

export const useMonitoring = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics>({
    cpu: 0,
    memory: 0,
    bandwidth: 0,
    temperature: 0
  });
  const [threatStats, setThreatStats] = useState<ThreatStats>({
    threatsDetected: 0,
    packetsAnalyzed: 0,
    connections: 0
  });
  const [monitoringStatus, setMonitoringStatus] = useState<MonitoringStatus>({
    isRunning: false,
    engineStatus: 'Offline'
  });
  const [loading, setLoading] = useState(false);

  // New Prevention System State
  const [preventionActions, setPreventionActions] = useState<PreventionAction[]>([]);
  const [preventionSettings, setPreventionSettings] = useState<PreventionSettings>({
    autoPreventionEnabled: false,
    blockDuration: 600,
    threatThreshold: 0.8
  });
  const [preventionStatus, setPreventionStatus] = useState<PreventionStatus>({
    activeBlocks: 0,
    totalBlocks: 0,
    autoPreventionEnabled: false,
    threatThreshold: 0.8
  });
  const [preventionLoading, setPreventionLoading] = useState(false);

  // Fetch real system metrics from the API
  const fetchSystemMetrics = useCallback(async () => {
    try {
      const response = await fetch('/api/status');
      const data = await response.json();
      
      setSystemMetrics({
        cpu: data.cpu || 0,
        memory: data.memory || 0,
        bandwidth: data.bandwidth || 0,
        temperature: data.temperature || 0
      });
      
      setThreatStats({
        threatsDetected: data.threats || 0,
        packetsAnalyzed: data.packets || 0,
        connections: data.connections || 0
      });
      
      setMonitoringStatus(prev => ({
        ...prev,
        engineStatus: data.engine || 'Offline',
        isRunning: data.engine === 'Online',
        lastUpdate: new Date().toLocaleTimeString()
      }));
    } catch (error) {
      console.error('Error fetching system metrics:', error);
    }
  }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      const alertsData = await ApiService.getAlerts();
      setAlerts(alertsData);
      
      // Update threat stats based on alerts
      const threats = alertsData.filter(alert => alert.prediction === 'ATTACK');
      setThreatStats(prev => ({
        ...prev,
        threatsDetected: threats.length,
        packetsAnalyzed: alertsData.length,
        connections: new Set(alertsData.map(alert => `${alert.src_ip}:${alert.src_port}`)).size
      }));
      
      // Update last update time
      if (alertsData.length > 0) {
        setMonitoringStatus(prev => ({
          ...prev,
          lastUpdate: new Date().toLocaleTimeString()
        }));
      }
    } catch (error) {
      console.error('Error fetching alerts:', error);
    }
  }, []);

  // New Prevention Methods
  const fetchPreventionActions = useCallback(async () => {
    try {
      const actions = await ApiService.getPreventionActions();
      setPreventionActions(actions);
      
      // Update prevention status
      const activeBlocks = actions.filter(action => action.status === 'active').length;
      setPreventionStatus(prev => ({
        ...prev,
        activeBlocks,
        totalBlocks: actions.length
      }));
    } catch (error) {
      console.error('Error fetching prevention actions:', error);
    }
  }, []);

  const fetchPreventionSettings = useCallback(async () => {
    try {
      const settings = await ApiService.getPreventionSettings();
      setPreventionSettings(settings);
      setPreventionStatus(prev => ({
        ...prev,
        autoPreventionEnabled: settings.autoPreventionEnabled,
        threatThreshold: settings.threatThreshold
      }));
    } catch (error) {
      console.error('Error fetching prevention settings:', error);
    }
  }, []);

  const blockIP = useCallback(async (ip: string) => {
    setPreventionLoading(true);
    try {
      const result = await ApiService.blockIP(ip);
      if (result.success) {
        // Refresh prevention actions
        await fetchPreventionActions();
        return { success: true, message: result.message };
      } else {
        return { success: false, message: result.message };
      }
    } catch (error) {
      console.error('Error blocking IP:', error);
      return { success: false, message: 'Failed to block IP' };
    } finally {
      setPreventionLoading(false);
    }
  }, [fetchPreventionActions]);

  const unblockIP = useCallback(async (ip: string) => {
    setPreventionLoading(true);
    try {
      const result = await ApiService.unblockIP(ip);
      if (result.success) {
        // Refresh prevention actions
        await fetchPreventionActions();
        return { success: true, message: result.message };
      } else {
        return { success: false, message: result.message };
      }
    } catch (error) {
      console.error('Error unblocking IP:', error);
      return { success: false, message: 'Failed to unblock IP' };
    } finally {
      setPreventionLoading(false);
    }
  }, [fetchPreventionActions]);

  const updatePreventionSettings = useCallback(async (settings: PreventionSettings) => {
    setPreventionLoading(true);
    try {
      const result = await ApiService.updatePreventionSettings(settings);
      if (result.success) {
        setPreventionSettings(settings);
        setPreventionStatus(prev => ({
          ...prev,
          autoPreventionEnabled: settings.autoPreventionEnabled,
          threatThreshold: settings.threatThreshold
        }));
        return { success: true, message: result.message };
      } else {
        return { success: false, message: result.message };
      }
    } catch (error) {
      console.error('Error updating prevention settings:', error);
      return { success: false, message: 'Failed to update settings' };
    } finally {
      setPreventionLoading(false);
    }
  }, []);

  const startMonitoring = useCallback(async () => {
    setLoading(true);
    try {
      const result = await ApiService.startMonitoring();
      if (result.success) {
        setMonitoringStatus(prev => ({
          ...prev,
          isRunning: true,
          engineStatus: 'Online'
        }));
        // Start polling for alerts, prevention actions, and system metrics
        const interval = setInterval(() => {
          fetchAlerts();
          fetchPreventionActions();
          fetchSystemMetrics();
        }, 2000);
        return () => clearInterval(interval);
      } else {
        console.error('Failed to start monitoring:', result.message);
      }
    } catch (error) {
      console.error('Error starting monitoring:', error);
    } finally {
      setLoading(false);
    }
  }, [fetchAlerts, fetchPreventionActions, fetchSystemMetrics]);

  const stopMonitoring = useCallback(async () => {
    setLoading(true);
    try {
      const result = await ApiService.stopMonitoring();
      if (result.success) {
        setMonitoringStatus(prev => ({
          ...prev,
          isRunning: false,
          engineStatus: 'Offline'
        }));
      } else {
        console.error('Failed to stop monitoring:', result.message);
      }
    } catch (error) {
      console.error('Error stopping monitoring:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  // Fetch real system metrics periodically
  useEffect(() => {
    const interval = setInterval(() => {
      fetchSystemMetrics();
    }, 3000);

    return () => clearInterval(interval);
  }, [fetchSystemMetrics]);

  // Initial fetch
  useEffect(() => {
    fetchAlerts();
    fetchPreventionActions();
    fetchPreventionSettings();
    fetchSystemMetrics();
  }, [fetchAlerts, fetchPreventionActions, fetchPreventionSettings, fetchSystemMetrics]);

  return {
    // Existing monitoring functionality
    alerts,
    systemMetrics,
    threatStats,
    monitoringStatus,
    loading,
    startMonitoring,
    stopMonitoring,
    refreshAlerts: fetchAlerts,
    
    // New prevention functionality
    preventionActions,
    preventionSettings,
    preventionStatus,
    preventionLoading,
    blockIP,
    unblockIP,
    updatePreventionSettings,
    refreshPreventionActions: fetchPreventionActions
  };
};