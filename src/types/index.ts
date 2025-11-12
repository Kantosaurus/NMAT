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

// Statistics Types
export interface ProtocolHierarchyItem {
  protocol: string;
  packets: number;
  bytes: number;
  percentage: string;
}

export interface ConversationItem {
  addressA: string;
  addressB: string;
  portA?: number;
  portB?: number;
  packets: number;
  bytes?: number;
  bytesAtoB?: number;
  bytesBtoA?: number;
  packetsAtoB?: number;
  packetsBtoA?: number;
  start: string;
  duration: string;
}

export interface EndpointItem {
  address: string;
  port?: number;
  packets: number;
  bytes: number;
  txPackets: number;
  txBytes: number;
  rxPackets: number;
  rxBytes: number;
}

export interface IOGraphDataPoint {
  time: number;
  packets: number;
  bytes: number;
  avgPacketSize: number;
  protocols: Record<string, number>;
}

export interface TCPStreamInfo {
  stream: string;
  packets: number;
  retransmissions: number;
  outOfOrder: number;
}

export interface ExpertAlert {
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  protocol: string;
  message: string;
  details: string;
  packet: number;
  timestamp: string;
}

export interface SRTStatistic {
  stream: string;
  packets: number;
  avgResponseTime: string;
  minResponseTime: string;
  maxResponseTime: string;
}

export interface FlowGraphItem {
  no: number;
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  info: string;
  length: number;
}

// Configuration Management Types
export interface CustomColumn {
  id: string;
  label: string;
  width: number;
  visible: boolean;
  path?: string;
}

export interface AvailableField {
  id: string;
  label: string;
  type: string;
  path?: string;
}

export interface ColorRule {
  name: string;
  filter: string;
  bgColor: string;
  fgColor: string;
}

export interface DisplayFilter {
  name: string;
  filter: string;
  enabled: boolean;
}

export interface ProfileConfig {
  name: string;
  displayFilters: DisplayFilter[];
  bpfFilter: string;
  customColumns: CustomColumn[];
  colorRules: ColorRule[];
  captureOptions: CaptureOptions;
  uiLayout: {
    packetListHeight: number;
    showHexView: boolean;
    showSecurityAlerts: boolean;
    fontSize: string;
  };
}

// Lua Scripting Types
export interface LuaTemplate {
  id: string;
  name: string;
  description: string;
}

export interface LuaScript {
  id: string;
  hasResults: boolean;
}

export interface LuaScriptAlert {
  scriptId: string;
  severity: string;
  message: string;
  details: string;
  packet: number;
}

export interface LuaScriptLog {
  scriptId: string;
  level: string;
  message: string;
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

// Packet Capture Options
export interface CaptureOptions {
  filter?: string;           // BPF filter syntax
  promiscuous?: boolean;     // Promiscuous mode
  monitor?: boolean;         // Monitor mode for Wi-Fi
  maxPackets?: number;       // Maximum packets to capture (0 = unlimited)
  maxDuration?: number;      // Maximum capture duration in seconds (0 = unlimited)
  ringBuffer?: boolean;      // Enable ring buffer file rotation
  maxFileSize?: number;      // Maximum file size in bytes
  maxFiles?: number;         // Maximum number of ring buffer files
  outputDir?: string | null; // Output directory for ring buffer
}

// Capture Statistics
export interface CaptureStats {
  packetCount: number;
  duration: string;
}

// Electron API
export interface ElectronAPI {
  // Packet Capture
  getInterfaces: () => Promise<{ success: boolean; devices?: NetworkInterface[]; error?: string }>;
  startCapture: (deviceName: string, options?: CaptureOptions) => Promise<{ success: boolean; error?: string }>;
  stopCapture: () => Promise<{ success: boolean; error?: string }>;
  loadPcapFile: () => Promise<{ success: boolean; filepath?: string; packetCount?: number; error?: string }>;
  exportPackets: (packets: Packet[], format: 'json' | 'csv') => Promise<{ success: boolean; error?: string }>;
  onPacketCaptured: (callback: (packet: Packet) => void) => void;
  onCaptureError: (callback: (error: string) => void) => void;
  onCaptureStopped: (callback: (stats: CaptureStats) => void) => void;
  onCaptureFileRotated: (callback: (filepath: string) => void) => void;
  onSecurityAlert: (callback: (alert: SecurityAlert) => void) => void;
  onExpertAlert: (callback: (alert: ExpertAlert) => void) => void;

  // Statistics
  getProtocolHierarchy: () => Promise<{ success: boolean; data?: ProtocolHierarchyItem[]; error?: string }>;
  getConversations: (type: 'ip' | 'tcp' | 'udp') => Promise<{ success: boolean; data?: ConversationItem[]; error?: string }>;
  getEndpoints: (type: 'ip' | 'tcp' | 'udp') => Promise<{ success: boolean; data?: EndpointItem[]; error?: string }>;
  getIOGraph: () => Promise<{ success: boolean; data?: IOGraphDataPoint[]; error?: string }>;
  getTCPStreams: () => Promise<{ success: boolean; data?: TCPStreamInfo[]; error?: string }>;
  getExpertAlerts: () => Promise<{ success: boolean; data?: ExpertAlert[]; error?: string }>;
  getSRTStatistics: () => Promise<{ success: boolean; data?: SRTStatistic[]; error?: string }>;
  getFlowGraph: () => Promise<{ success: boolean; data?: FlowGraphItem[]; error?: string }>;
  resolveHostname: (ip: string) => Promise<{ success: boolean; hostname?: string; error?: string }>;
  resolveMacVendor: (mac: string) => Promise<{ success: boolean; vendor?: string; error?: string }>;
  resolveService: (port: number) => Promise<{ success: boolean; service?: string; error?: string }>;
  exportStatistics: (type: string, format: 'json' | 'csv' | 'xml') => Promise<{ success: boolean; error?: string }>;

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

  // Configuration Management
  configListProfiles: () => Promise<{ success: boolean; profiles?: string[]; error?: string }>;
  configLoadProfile: (profileName: string) => Promise<{ success: boolean; config?: ProfileConfig; error?: string }>;
  configSaveProfile: (profileName: string) => Promise<{ success: boolean; error?: string }>;
  configDeleteProfile: (profileName: string) => Promise<{ success: boolean; error?: string }>;
  configDuplicateProfile: (sourceName: string, newName: string) => Promise<{ success: boolean; error?: string }>;
  configGetCurrent: () => Promise<{ success: boolean; profile?: string; config?: ProfileConfig; error?: string }>;
  configGetCustomColumns: () => Promise<{ success: boolean; columns?: CustomColumn[]; error?: string }>;
  configSetCustomColumns: (columns: CustomColumn[]) => Promise<{ success: boolean; error?: string }>;
  configAddCustomColumn: (field: AvailableField, position?: number) => Promise<{ success: boolean; columns?: CustomColumn[]; error?: string }>;
  configRemoveCustomColumn: (columnId: string) => Promise<{ success: boolean; columns?: CustomColumn[]; error?: string }>;
  configReorderColumns: (fromIndex: number, toIndex: number) => Promise<{ success: boolean; columns?: CustomColumn[]; error?: string }>;
  configGetAvailableFields: () => Promise<{ success: boolean; fields?: AvailableField[]; error?: string }>;
  configGetColorRules: () => Promise<{ success: boolean; rules?: ColorRule[]; error?: string }>;
  configAddColorRule: (rule: ColorRule) => Promise<{ success: boolean; rules?: ColorRule[]; error?: string }>;
  configRemoveColorRule: (ruleName: string) => Promise<{ success: boolean; rules?: ColorRule[]; error?: string }>;

  // Lua Scripting
  luaGetTemplates: () => Promise<{ success: boolean; templates?: LuaTemplate[]; error?: string }>;
  luaGetTemplateCode: (templateId: string) => Promise<{ success: boolean; code?: string; error?: string }>;
  luaLoadScript: (scriptId: string, scriptCode: string) => Promise<{ success: boolean; error?: string }>;
  luaUnloadScript: (scriptId: string) => Promise<{ success: boolean; error?: string }>;
  luaGetLoadedScripts: () => Promise<{ success: boolean; scripts?: LuaScript[]; error?: string }>;
  luaGetResults: (scriptId: string) => Promise<{ success: boolean; results?: any; error?: string }>;
  luaExecuteOnPacket: (scriptId: string, packet: Packet) => Promise<{ success: boolean; error?: string }>;
  luaCompleteScript: (scriptId: string) => Promise<{ success: boolean; results?: any; error?: string }>;
  onLuaScriptAlert: (callback: (alert: LuaScriptAlert) => void) => void;
  onLuaScriptLog: (callback: (log: LuaScriptLog) => void) => void;
}

declare global {
  interface Window {
    api: ElectronAPI;
  }
}
