import React, { useEffect, useRef } from 'react';
import { Server, Wifi, Shield, AlertTriangle } from 'lucide-react';
import { Alert } from '../types';


interface NetworkTopologyProps {
  alerts: Alert[];
}

export const NetworkTopology: React.FC<NetworkTopologyProps> = ({ alerts }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Extract unique IPs from alerts
  const getNetworkNodes = () => {
    const nodes = new Map();
    
    alerts.forEach(alert => {
      if (!nodes.has(alert.src_ip)) {
        nodes.set(alert.src_ip, {
          ip: alert.src_ip,
          type: 'source',
          threats: alerts.filter(a => a.src_ip === alert.src_ip && a.prediction === 'ATTACK').length,
          connections: alerts.filter(a => a.src_ip === alert.src_ip).length
        });
      }
      if (!nodes.has(alert.dst_ip)) {
        nodes.set(alert.dst_ip, {
          ip: alert.dst_ip,
          type: 'destination',
          threats: alerts.filter(a => a.dst_ip === alert.dst_ip && a.prediction === 'ATTACK').length,
          connections: alerts.filter(a => a.dst_ip === alert.dst_ip).length
        });
      }
    });
    
    return Array.from(nodes.values());
  };

  const nodes = getNetworkNodes();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const drawNetwork = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Set canvas size
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;

      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;
      const radius = Math.min(canvas.width, canvas.height) * 0.3;

      // Draw connections
      ctx.strokeStyle = '#475569';
      ctx.lineWidth = 1;
      alerts.forEach(alert => {
        const srcIndex = nodes.findIndex(n => n.ip === alert.src_ip);
        const dstIndex = nodes.findIndex(n => n.ip === alert.dst_ip);
        
        if (srcIndex !== -1 && dstIndex !== -1) {
          const srcAngle = (srcIndex / nodes.length) * 2 * Math.PI;
          const dstAngle = (dstIndex / nodes.length) * 2 * Math.PI;
          
          const srcX = centerX + Math.cos(srcAngle) * radius;
          const srcY = centerY + Math.sin(srcAngle) * radius;
          const dstX = centerX + Math.cos(dstAngle) * radius;
          const dstY = centerY + Math.sin(dstAngle) * radius;
          
          ctx.beginPath();
          ctx.moveTo(srcX, srcY);
          ctx.lineTo(dstX, dstY);
          ctx.stroke();
        }
      });

      // Draw nodes
      nodes.forEach((node, index) => {
        const angle = (index / nodes.length) * 2 * Math.PI;
        const x = centerX + Math.cos(angle) * radius;
        const y = centerY + Math.sin(angle) * radius;
        
        // Node circle
        ctx.beginPath();
        ctx.arc(x, y, 20, 0, 2 * Math.PI);
        ctx.fillStyle = node.threats > 0 ? '#ef4444' : '#10b981';
        ctx.fill();
        ctx.strokeStyle = '#1e293b';
        ctx.lineWidth = 2;
        ctx.stroke();
        
        // Node label
        ctx.fillStyle = '#f1f5f9';
        ctx.font = '10px monospace';
        ctx.textAlign = 'center';
        ctx.fillText(node.ip.split('.').slice(-1)[0], x, y - 25);
      });
    };

    drawNetwork();
    
    const handleResize = () => drawNetwork();
    window.addEventListener('resize', handleResize);
    
    return () => window.removeEventListener('resize', handleResize);
  }, [alerts, nodes]);

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold text-white flex items-center space-x-2">
          <Wifi className="w-5 h-5 text-blue-400" />
          <span>Network Topology</span>
        </h2>
        <div className="flex items-center space-x-4 text-sm">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span className="text-slate-400">Secure</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-red-500 rounded-full"></div>
            <span className="text-slate-400">Threat Detected</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <canvas
            ref={canvasRef}
            className="w-full h-80 bg-slate-900 rounded-lg border border-slate-600"
          />
        </div>
        
        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-white mb-4">Network Nodes</h3>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {nodes.map((node, index) => (
              <div
                key={index}
                className="bg-slate-700 rounded-lg p-3 border border-slate-600"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <Server className="w-4 h-4 text-blue-400" />
                    <span className="text-white font-mono text-sm">{node.ip}</span>
                  </div>
                  {node.threats > 0 && (
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                  )}
                </div>
                <div className="text-xs text-slate-400">
                  <div>Connections: {node.connections}</div>
                  {node.threats > 0 && (
                    <div className="text-red-400">Threats: {node.threats}</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};