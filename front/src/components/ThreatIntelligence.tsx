import React from 'react';
import { BarChart3, TrendingUp, Shield, AlertCircle } from 'lucide-react';
import { Alert } from '../types';

interface ThreatIntelligenceProps {
  alerts: Alert[];
}

export const ThreatIntelligence: React.FC<ThreatIntelligenceProps> = ({ alerts }) => {
  // Calculate threat statistics
  const threatStats = {
    totalAlerts: alerts.length,
    attackAlerts: alerts.filter(a => a.prediction === 'ATTACK').length,
    benignAlerts: alerts.filter(a => a.prediction === 'BENIGN').length,
    avgConfidence: alerts.length > 0 ? alerts.reduce((sum, a) => sum + a.confidence, 0) / alerts.length : 0
  };

  // Get top source IPs by threat count
  const topThreats = alerts
    .filter(a => a.prediction === 'ATTACK')
    .reduce((acc, alert) => {
      acc[alert.src_ip] = (acc[alert.src_ip] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

  const topThreatsList = Object.entries(topThreats)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 5);

  // Protocol distribution
  const protocolStats = alerts.reduce((acc, alert) => {
    // Extract protocol from flow_key (simplified)
    const protocol = alert.flow_key.includes('TCP') ? 'TCP' : 'UDP';
    acc[protocol] = (acc[protocol] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // Port analysis
  const portStats = alerts.reduce((acc, alert) => {
    const port = alert.dst_port;
    acc[port] = (acc[port] || 0) + 1;
    return acc;
  }, {} as Record<number, number>);

  const topPorts = Object.entries(portStats)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Total Flows</p>
              <p className="text-2xl font-bold text-white">{threatStats.totalAlerts}</p>
            </div>
            <BarChart3 className="w-8 h-8 text-blue-400" />
          </div>
        </div>
        
        <div className="bg-slate-800 border border-red-500/20 rounded-lg p-4 bg-red-500/5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Attack Flows</p>
              <p className="text-2xl font-bold text-red-400">{threatStats.attackAlerts}</p>
            </div>
            <AlertCircle className="w-8 h-8 text-red-400" />
          </div>
        </div>
        
        <div className="bg-slate-800 border border-green-500/20 rounded-lg p-4 bg-green-500/5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Benign Flows</p>
              <p className="text-2xl font-bold text-green-400">{threatStats.benignAlerts}</p>
            </div>
            <Shield className="w-8 h-8 text-green-400" />
          </div>
        </div>
        
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Avg Confidence</p>
              <p className="text-2xl font-bold text-white">{(threatStats.avgConfidence * 100).toFixed(1)}%</p>
            </div>
            <TrendingUp className="w-8 h-8 text-purple-400" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Threat Sources */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
            <AlertCircle className="w-5 h-5 text-red-400" />
            <span>Top Threat Sources</span>
          </h3>
          
          {topThreatsList.length === 0 ? (
            <p className="text-slate-400 text-center py-8">No threats detected</p>
          ) : (
            <div className="space-y-3">
              {topThreatsList.map(([ip, count], index) => (
                <div key={ip} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-red-500/20 rounded-full flex items-center justify-center">
                      <span className="text-red-400 font-bold text-sm">{index + 1}</span>
                    </div>
                    <span className="text-white font-mono">{ip}</span>
                  </div>
                  <div className="text-red-400 font-semibold">{count} attacks</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Protocol Distribution */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
            <BarChart3 className="w-5 h-5 text-blue-400" />
            <span>Protocol Distribution</span>
          </h3>
          
          <div className="space-y-4">
            {Object.entries(protocolStats).map(([protocol, count]) => {
              const percentage = (count / threatStats.totalAlerts) * 100;
              return (
                <div key={protocol}>
                  <div className="flex justify-between text-sm mb-2">
                    <span className="text-white">{protocol}</span>
                    <span className="text-slate-400">{count} ({percentage.toFixed(1)}%)</span>
                  </div>
                  <div className="w-full bg-slate-700 rounded-full h-2">
                    <div
                      className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top Destination Ports */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
            <Shield className="w-5 h-5 text-green-400" />
            <span>Top Destination Ports</span>
          </h3>
          
          <div className="space-y-3">
            {topPorts.map(([port, count], index) => (
              <div key={port} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 bg-green-500/20 rounded-full flex items-center justify-center">
                    <span className="text-green-400 font-bold text-sm">{index + 1}</span>
                  </div>
                  <span className="text-white font-mono">Port {port}</span>
                </div>
                <div className="text-green-400 font-semibold">{count} connections</div>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Timeline */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
            <TrendingUp className="w-5 h-5 text-purple-400" />
            <span>Recent Activity</span>
          </h3>
          
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {alerts.slice(-10).reverse().map((alert, index) => (
              <div key={index} className="flex items-center justify-between p-2 bg-slate-700 rounded text-sm">
                <div className="flex items-center space-x-2">
                  <div className={`w-2 h-2 rounded-full ${
                    alert.prediction === 'ATTACK' ? 'bg-red-500' : 'bg-green-500'
                  }`} />
                  <span className="text-slate-300">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <span className={`font-semibold ${
                  alert.prediction === 'ATTACK' ? 'text-red-400' : 'text-green-400'
                }`}>
                  {alert.prediction}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};