// Packet Types
export interface Packet {
  no: number;
  timestamp: string;
  relativeTime: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  srcPort?: number;
  dstPort?: number;
  raw: any;
  rawBuffer?: Uint8Array;
}

// Network Interface
export interface NetworkInterface {
  name: string;
  description?: string;
  addresses: Array<{ addr: string }>;
}

// Security Alert
export interface SecurityAlert {
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  details: string;
  timestamp: number;
  packet: number;
}

// HTTP Proxy Types
export interface ProxyHistoryItem {
  id: number;
  method: string;
  url: string;
  httpVersion: string;
  headers: Record<string, string>;
  bodyString?: string;
  response?: {
    statusCode: number;
    statusMessage: string;
    headers: Record<string, string>;
    bodyString?: string;
    length: number;
    time: number;
  };
}

export interface InterceptItem {
  id: string;
  method: string;
  url: string;
  httpVersion: string;
  headers: Record<string, string>;
  bodyString?: string;
}

// Electron API
export interface ElectronAPI {
  // Packet Capture
  getInterfaces: () => Promise<{ success: boolean; devices?: NetworkInterface[]; error?: string }>;
  startCapture: (deviceName: string) => Promise<{ success: boolean; error?: string }>;
  stopCapture: () => Promise<{ success: boolean; error?: string }>;
  exportPackets: (packets: Packet[], format: 'json' | 'csv') => Promise<{ success: boolean; error?: string }>;
  onPacketCaptured: (callback: (packet: Packet) => void) => void;
  onCaptureError: (callback: (error: string) => void) => void;
  onSecurityAlert: (callback: (alert: SecurityAlert) => void) => void;

  // HTTP Proxy
  startProxy: (port: number) => Promise<{ success: boolean; port?: number; error?: string }>;
  stopProxy: () => Promise<{ success: boolean; error?: string }>;
  toggleIntercept: (enabled: boolean) => Promise<{ success: boolean; enabled?: boolean; error?: string }>;
  forwardIntercept: (id: string, modifiedRequest: any) => Promise<{ success: boolean; error?: string }>;
  dropIntercept: (id: string) => Promise<{ success: boolean; error?: string }>;
  getProxyHistory: () => Promise<{ success: boolean; history?: ProxyHistoryItem[]; error?: string }>;
  clearProxyHistory: () => Promise<{ success: boolean; error?: string }>;
  repeatRequest: (requestData: any) => Promise<{ success: boolean; result?: any; error?: string }>;
  runIntruder: (requestData: any, positions: any[], payloads: string[], attackType: string) => Promise<{ success: boolean; results?: any[]; error?: string }>;
  onProxyStarted: (callback: (port: number) => void) => void;
  onProxyStopped: (callback: () => void) => void;
  onProxyError: (callback: (error: string) => void) => void;
  onProxyIntercept: (callback: (item: InterceptItem) => void) => void;
  onProxyHistoryUpdate: (callback: (item: ProxyHistoryItem) => void) => void;
  onProxyHistoryCleared: (callback: () => void) => void;
  onIntruderProgress: (callback: (progress: { current: number; total: number }) => void) => void;

  // Window controls
  windowMinimize: () => Promise<void>;
  windowMaximize: () => Promise<boolean>;
  windowClose: () => Promise<void>;
  windowIsMaximized: () => Promise<boolean>;
}

declare global {
  interface Window {
    api: ElectronAPI;
  }
}
