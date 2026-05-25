import React from 'react';
import { AlertTriangle, Activity, Wifi, Thermometer } from 'lucide-react';
import { SystemMetrics, ThreatStats } from '../types';

interface StatsCardsProps {
  systemMetrics: SystemMetrics;
  threatStats: ThreatStats;
}

export const StatsCards: React.FC<StatsCardsProps> = ({ systemMetrics, threatStats }) => {
  const cards = [
    {
      title: 'Threats Detected',
      value: threatStats.threatsDetected,
      icon: AlertTriangle,
      color: 'text-red-400',
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/20'
    },
    {
      title: 'Packets Analyzed',
      value: threatStats.packetsAnalyzed,
      icon: Activity,
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/20'
    },
    {
      title: 'Connections',
      value: threatStats.connections,
      icon: Wifi,
      color: 'text-green-400',
      bgColor: 'bg-green-500/10',
      borderColor: 'border-green-500/20'
    }
  ];

  const systemCards = [
    {
      title: 'CPU Usage',
      value: `${systemMetrics.cpu.toFixed(1)}%`,
      icon: Activity,
      color: 'text-purple-400',
      bgColor: 'bg-purple-500/10',
      borderColor: 'border-purple-500/20'
    },
    {
      title: 'Memory',
      value: `${systemMetrics.memory.toFixed(1)}%`,
      icon: Activity,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/10',
      borderColor: 'border-cyan-500/20'
    },
    {
      title: 'Bandwidth',
      value: `${systemMetrics.bandwidth.toFixed(1)} Mbps`,
      icon: Wifi,
      color: 'text-indigo-400',
      bgColor: 'bg-indigo-500/10',
      borderColor: 'border-indigo-500/20'
    },
    {
      title: 'Temperature',
      value: `${systemMetrics.temperature.toFixed(1)}°C`,
      icon: Thermometer,
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/10',
      borderColor: 'border-orange-500/20'
    }
  ];

  return (
    <div className="px-6 py-4">
      {/* Threat Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        {cards.map((card, index) => (
          <div
            key={index}
            className={`bg-slate-800 border ${card.borderColor} rounded-lg p-4 ${card.bgColor}`}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400 mb-1">{card.title}</p>
                <p className="text-2xl font-bold text-white">{card.value}</p>
              </div>
              <div className={`p-2 rounded-lg ${card.bgColor}`}>
                <card.icon className={`w-6 h-6 ${card.color}`} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* System Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {systemCards.map((card, index) => (
          <div
            key={index}
            className={`bg-slate-800 border ${card.borderColor} rounded-lg p-4 ${card.bgColor}`}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400 mb-1">{card.title}</p>
                <p className="text-xl font-bold text-white">{card.value}</p>
              </div>
              <div className={`p-2 rounded-lg ${card.bgColor}`}>
                <card.icon className={`w-5 h-5 ${card.color}`} />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};