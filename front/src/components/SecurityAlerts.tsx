import { Shield, Clock, MapPin, AlertTriangle, CheckCircle } from 'lucide-react';
import React from "react";
import { blockIP } from '../services/api';
import { Alert } from '../types';

interface SecurityAlertsProps {
  alerts: Alert[];
  lastUpdate?: string;
}

export const SecurityAlerts: React.FC<SecurityAlertsProps> = ({ alerts, lastUpdate }) => {
  const handleBlock = async (ip: string) => {
    try {
      const res = await blockIP(ip);
      alert(res.message);
    } catch (err: any) {
      alert("Error: " + err.message);
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const formatDuration = (duration: number) => {
    return `${(duration * 1000).toFixed(2)}ms`;
  };

  const getAlertIcon = (prediction: string) => {
    return prediction === 'ATTACK' ? AlertTriangle : CheckCircle;
  };

  const getAlertColor = (prediction: string) => {
    return prediction === 'ATTACK' 
      ? 'text-red-400 bg-red-500/10 border-red-500/20' 
      : 'text-green-400 bg-green-500/10 border-green-500/20';
  };

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold text-white flex items-center space-x-2">
          <Shield className="w-5 h-5 text-blue-400" />
          <span>Security Alerts</span>
        </h2>
        {lastUpdate && (
          <div className="flex items-center space-x-2 text-sm text-slate-400">
            <Clock className="w-4 h-4" />
            <span>Last Update: {lastUpdate}</span>
          </div>
        )}
      </div>

      {alerts.length === 0 ? (
        <div className="text-center py-12">
          <Shield className="w-16 h-16 text-slate-600 mx-auto mb-4" />
          <p className="text-slate-400 text-lg">No security events detected</p>
          <p className="text-slate-500 text-sm mt-2">Your network is secure</p>
        </div>
      ) : (
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {alerts.slice().reverse().map((alert, index) => {
            const AlertIcon = getAlertIcon(alert.prediction);
            const alertColorClass = getAlertColor(alert.prediction);

            return (
              <div
                key={index}
                className={`border rounded-lg p-4 ${alertColorClass}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3">
                    <AlertIcon className="w-5 h-5 mt-0.5" />
                    <div className="flex-1">
                      <div className="flex items-center space-x-2 mb-2">
                        <span className="font-semibold text-white">
                          {alert.prediction}
                        </span>
                        <span className="text-xs px-2 py-1 bg-slate-700 rounded text-slate-300">
                          {(alert.confidence * 100).toFixed(1)}% confidence
                        </span>

                        {alert.prediction === "ATTACK" && (
                          <button
                            onClick={() => handleBlock(alert.src_ip)}
                            className="ml-2 px-2 py-1 bg-red-600 text-white text-xs rounded hover:bg-red-700"
                          >
                            Block IP
                          </button>
                        )}
                      </div>

                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <div className="flex items-center space-x-1 text-slate-300">
                            <MapPin className="w-3 h-3" />
                            <span>Source: {alert.src_ip}:{alert.src_port || "-"}</span>
                          </div>
                          <div className="flex items-center space-x-1 text-slate-300 mt-1">
                            <MapPin className="w-3 h-3" />
                            <span>Destination: {alert.dst_ip}:{alert.dst_port || "-"}</span>
                          </div>
                        </div>
                        <div>
                          {alert.duration && (
                            <div className="text-slate-300">
                              Duration: {formatDuration(alert.duration)}
                            </div>
                          )}
                          {alert.timestamp && (
                            <div className="text-slate-400 text-xs mt-1">
                              {formatTimestamp(alert.timestamp)}
                            </div>
                          )}
                        </div>
                      </div>

                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
