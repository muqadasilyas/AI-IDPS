const API_BASE_URL = 'http://localhost:5000/api';
import axios from "axios";
import { PreventionAction, PreventionSettings } from '../types';

export class ApiService {
  static async getAlerts(): Promise<any[]> {
    try {
      const response = await fetch(`${API_BASE_URL}/alerts`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      return Array.isArray(data) ? data : [];
    } catch (error) {
      console.error('Error fetching alerts:', error);
      return [];
    }
  }

  static async getStatus(): Promise<any> {
    try {
      const response = await fetch(`${API_BASE_URL}/status`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error fetching status:', error);
      return {
        engine: 'Offline',
        threats: 0,
        packets: 0,
        connections: 0,
        cpu: 0,
        memory: 0,
        bandwidth: 0,
        temperature: 0
      };
    }
  }

  static async startMonitoring(): Promise<{ success: boolean; message: string }> {
    try {
      const response = await fetch(`${API_BASE_URL}/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      const data = await response.json();
      return {
        success: response.ok,
        message: data.message || data.error || 'Unknown error'
      };
    } catch (error) {
      console.error('Error starting monitoring:', error);
      return {
        success: false,
        message: 'Failed to connect to backend'
      };
    }
  }

  static async stopMonitoring(): Promise<{ success: boolean; message: string }> {
    try {
      const response = await fetch(`${API_BASE_URL}/stop`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      const data = await response.json();
      return {
        success: response.ok,
        message: data.message || data.error || 'Unknown error'
      };
    } catch (error) {
      console.error('Error stopping monitoring:', error);
      return {
        success: false,
        message: 'Failed to connect to backend'
      };
    }
  }

  // New Prevention API Methods
  static async getPreventionActions(): Promise<PreventionAction[]> {
    try {
      const response = await fetch(`${API_BASE_URL}/prevention/actions`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      return Array.isArray(data) ? data : [];
    } catch (error) {
      console.error('Error fetching prevention actions:', error);
      return [];
    }
  }

  static async blockIP(ip: string, duration: number = 600, reason: string = 'Manual block'): Promise<{ success: boolean; message: string }> {
    try {
      const response = await fetch(`${API_BASE_URL}/prevention/block`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip, duration, reason }),
      });
      
      const data = await response.json();
      return {
        success: response.ok,
        message: data.message || data.error || 'Unknown error'
      };
    } catch (error) {
      console.error('Error blocking IP:', error);
      return {
        success: false,
        message: 'Failed to connect to backend'
      };
    }
  }

  static async unblockIP(ip: string): Promise<{ success: boolean; message: string }> {
    try {
      const response = await fetch(`${API_BASE_URL}/prevention/unblock`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip }),
      });
      
      const data = await response.json();
      return {
        success: response.ok,
        message: data.message || data.error || 'Unknown error'
      };
    } catch (error) {
      console.error('Error unblocking IP:', error);
      return {
        success: false,
        message: 'Failed to connect to backend'
      };
    }
  }

  static async getPreventionSettings(): Promise<PreventionSettings> {
    try {
      const response = await fetch(`${API_BASE_URL}/prevention/settings`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error fetching prevention settings:', error);
      return {
        autoPreventionEnabled: false,
        blockDuration: 600,
        threatThreshold: 0.8
      };
    }
  }

  static async updatePreventionSettings(settings: PreventionSettings): Promise<{ success: boolean; message: string }> {
    try {
      const response = await fetch(`${API_BASE_URL}/prevention/settings`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(settings),
      });
      
      const data = await response.json();
      return {
        success: response.ok,
        message: data.message || data.error || 'Unknown error'
      };
    } catch (error) {
      console.error('Error updating prevention settings:', error);
      return {
        success: false,
        message: 'Failed to connect to backend'
      };
    }
  }
}

export const getAttacks = async () => {
  const res = await axios.get(`http://localhost:5000/api/get_attacks`);
  return res.data;
};

export const blockIP = async (ip: string) => {
  const res = await axios.post(`http://localhost:5000/api/block_ip`, { ip });
  return res.data;
};
