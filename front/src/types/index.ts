export interface Alert {
  timestamp: string;
  flow_key: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  duration: number;
  prediction: 'BENIGN' | 'ATTACK';
  confidence: number;
  autoBlockEnabled: "Not Blocked" | "Blocked"
}

export interface SystemMetrics {
  cpu: number;
  memory: number;
  bandwidth: number;
  temperature: number;
}
export interface PreventionAction {
  id: string;
  timestamp: string;
  ip: string;
  action: string;
  reason: string;
  duration: number;
  status: 'active' | 'expired' | 'manual';
  expiresAt?: string;
}

export interface PreventionSettings {
  autoPreventionEnabled: boolean;
  blockDuration: number;
  threatThreshold: number;
}

export interface PreventionStatus {
  activeBlocks: number;
  totalBlocks: number;
  autoPreventionEnabled: boolean;
  threatThreshold: number;
}
export interface ThreatStats {
  threatsDetected: number;
  packetsAnalyzed: number;
  connections: number;
}

export interface MonitoringStatus {
  isRunning: boolean;
  engineStatus: 'Online' | 'Offline';
  lastUpdate?: string;
}

export interface ApiStatusResponse {
  engine: 'Online' | 'Offline';
  threats: number;
  packets: number;
  connections: number;
  cpu: number;
  memory: number;
  bandwidth: number;
  temperature: number;
}


