import React from 'react';
import { Eye, Network, BarChart3, Shield } from 'lucide-react';

interface TabNavigationProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
}

export const TabNavigation: React.FC<TabNavigationProps> = ({ activeTab, onTabChange }) => {
  const tabs = [
    { id: 'monitoring', label: 'Live Threat Monitoring', icon: Eye },
    { id: 'topology', label: 'Network Topology', icon: Network },
    { id: 'intelligence', label: 'Threat Intelligence', icon: BarChart3 },
    { id: 'prevention', label: 'Prevention System', icon: Shield }
  ];

  return (
    <div className="px-6 py-2 border-b border-slate-700">
      <nav className="flex space-x-1">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-slate-700 text-white'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            <span>{tab.label}</span>
          </button>
        ))}
      </nav>
    </div>
  );
};