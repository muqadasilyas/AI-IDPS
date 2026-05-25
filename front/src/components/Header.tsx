import React from 'react';
import { Shield, Activity } from 'lucide-react';
import { MonitoringStatus } from '../types';

interface HeaderProps {
  monitoringStatus: MonitoringStatus;
  onStartMonitoring: () => void;
  onStopMonitoring: () => void;
  loading: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  monitoringStatus,
  onStartMonitoring,
  onStopMonitoring,
  loading
}) => {
  return (
    <header className="bg-slate-900 border-b border-slate-700 px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-600 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">AI-Powered Cyber Threat Dashboard</h1>
            <p className="text-sm text-slate-400">Real-time network security monitoring</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className={`w-2 h-2 rounded-full ${
              monitoringStatus.engineStatus === 'Online' ? 'bg-green-500' : 'bg-red-500'
            }`} />
            <span className="text-sm text-slate-300">
              Engine: {monitoringStatus.engineStatus}
            </span>
          </div>
          
          <div className="flex space-x-2">
            {!monitoringStatus.isRunning ? (
              <button
                onClick={onStartMonitoring}
                disabled={loading}
                className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
              >
                <Activity className="w-4 h-4" />
                <span>{loading ? 'Starting...' : 'Start AI Monitoring'}</span>
              </button>
            ) : (
              <button
                onClick={onStopMonitoring}
                disabled={loading}
                className="flex items-center space-x-2 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
              >
                <div className="w-4 h-4 bg-white rounded-sm" />
                <span>{loading ? 'Stopping...' : 'Stop Engine'}</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};