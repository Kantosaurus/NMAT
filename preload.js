const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  getInterfaces: () => ipcRenderer.invoke('get-interfaces'),
  startCapture: (deviceName, options) => ipcRenderer.invoke('start-capture', deviceName, options),
  stopCapture: () => ipcRenderer.invoke('stop-capture'),
  loadPcapFile: () => ipcRenderer.invoke('load-pcap-file'),
  exportPackets: (packets, format) => ipcRenderer.invoke('export-packets', packets, format),

  // Statistics API
  getProtocolHierarchy: () => ipcRenderer.invoke('get-protocol-hierarchy'),
  getConversations: (type) => ipcRenderer.invoke('get-conversations', type),
  getEndpoints: (type) => ipcRenderer.invoke('get-endpoints', type),
  getIOGraph: () => ipcRenderer.invoke('get-io-graph'),
  getTCPStreams: () => ipcRenderer.invoke('get-tcp-streams'),
  getExpertAlerts: () => ipcRenderer.invoke('get-expert-alerts'),
  getSRTStatistics: () => ipcRenderer.invoke('get-srt-statistics'),
  getFlowGraph: () => ipcRenderer.invoke('get-flow-graph'),
  resolveHostname: (ip) => ipcRenderer.invoke('resolve-hostname', ip),
  resolveMacVendor: (mac) => ipcRenderer.invoke('resolve-mac-vendor', mac),
  resolveService: (port) => ipcRenderer.invoke('resolve-service', port),
  exportStatistics: (type, format) => ipcRenderer.invoke('export-statistics', type, format),

  onPacketCaptured: (callback) => {
    ipcRenderer.on('packet-captured', (event, packet) => callback(packet));
  },

  onExpertAlert: (callback) => {
    ipcRenderer.on('expert-alert', (event, alert) => callback(alert));
  },

  onCaptureError: (callback) => {
    ipcRenderer.on('capture-error', (event, error) => callback(error));
  },

  onCaptureStopped: (callback) => {
    ipcRenderer.on('capture-stopped', (event, stats) => callback(stats));
  },

  onCaptureFileRotated: (callback) => {
    ipcRenderer.on('capture-file-rotated', (event, filepath) => callback(filepath));
  },

  onSecurityAlert: (callback) => {
    ipcRenderer.on('security-alert', (event, alert) => callback(alert));
  },

  // HTTP Proxy controls
  startProxy: (port) => ipcRenderer.invoke('start-proxy', port),
  stopProxy: () => ipcRenderer.invoke('stop-proxy'),
  toggleIntercept: (enabled) => ipcRenderer.invoke('toggle-intercept', enabled),
  forwardIntercept: (id, modifiedRequest) => ipcRenderer.invoke('forward-intercept', id, modifiedRequest),
  dropIntercept: (id) => ipcRenderer.invoke('drop-intercept', id),
  getProxyHistory: () => ipcRenderer.invoke('get-proxy-history'),
  clearProxyHistory: () => ipcRenderer.invoke('clear-proxy-history'),
  repeatRequest: (requestData) => ipcRenderer.invoke('repeat-request', requestData),
  runIntruder: (requestData, positions, payloads, attackType) => ipcRenderer.invoke('run-intruder', requestData, positions, payloads, attackType),

  onProxyStarted: (callback) => {
    ipcRenderer.on('proxy-started', (event, port) => callback(port));
  },

  onProxyStopped: (callback) => {
    ipcRenderer.on('proxy-stopped', () => callback());
  },

  onProxyError: (callback) => {
    ipcRenderer.on('proxy-error', (event, error) => callback(error));
  },

  onProxyIntercept: (callback) => {
    ipcRenderer.on('proxy-intercept', (event, interceptItem) => callback(interceptItem));
  },

  onProxyHistoryUpdate: (callback) => {
    ipcRenderer.on('proxy-history-update', (event, item) => callback(item));
  },

  onProxyHistoryCleared: (callback) => {
    ipcRenderer.on('proxy-history-cleared', () => callback());
  },

  onIntruderProgress: (callback) => {
    ipcRenderer.on('intruder-progress', (event, progress) => callback(progress));
  },

  // Window controls
  windowMinimize: () => ipcRenderer.invoke('window-minimize'),
  windowMaximize: () => ipcRenderer.invoke('window-maximize'),
  windowClose: () => ipcRenderer.invoke('window-close'),
  windowIsMaximized: () => ipcRenderer.invoke('window-is-maximized'),

  // Configuration Management
  configListProfiles: () => ipcRenderer.invoke('config-list-profiles'),
  configLoadProfile: (profileName) => ipcRenderer.invoke('config-load-profile', profileName),
  configSaveProfile: (profileName) => ipcRenderer.invoke('config-save-profile', profileName),
  configDeleteProfile: (profileName) => ipcRenderer.invoke('config-delete-profile', profileName),
  configDuplicateProfile: (sourceName, newName) => ipcRenderer.invoke('config-duplicate-profile', sourceName, newName),
  configGetCurrent: () => ipcRenderer.invoke('config-get-current'),
  configGetCustomColumns: () => ipcRenderer.invoke('config-get-custom-columns'),
  configSetCustomColumns: (columns) => ipcRenderer.invoke('config-set-custom-columns', columns),
  configAddCustomColumn: (field, position) => ipcRenderer.invoke('config-add-custom-column', field, position),
  configRemoveCustomColumn: (columnId) => ipcRenderer.invoke('config-remove-custom-column', columnId),
  configReorderColumns: (fromIndex, toIndex) => ipcRenderer.invoke('config-reorder-columns', fromIndex, toIndex),
  configGetAvailableFields: () => ipcRenderer.invoke('config-get-available-fields'),
  configGetColorRules: () => ipcRenderer.invoke('config-get-color-rules'),
  configAddColorRule: (rule) => ipcRenderer.invoke('config-add-color-rule', rule),
  configRemoveColorRule: (ruleName) => ipcRenderer.invoke('config-remove-color-rule', ruleName),

  // Lua Scripting
  luaGetTemplates: () => ipcRenderer.invoke('lua-get-templates'),
  luaGetTemplateCode: (templateId) => ipcRenderer.invoke('lua-get-template-code', templateId),
  luaLoadScript: (scriptId, scriptCode) => ipcRenderer.invoke('lua-load-script', scriptId, scriptCode),
  luaUnloadScript: (scriptId) => ipcRenderer.invoke('lua-unload-script', scriptId),
  luaGetLoadedScripts: () => ipcRenderer.invoke('lua-get-loaded-scripts'),
  luaGetResults: (scriptId) => ipcRenderer.invoke('lua-get-results', scriptId),
  luaExecuteOnPacket: (scriptId, packet) => ipcRenderer.invoke('lua-execute-on-packet', scriptId, packet),
  luaCompleteScript: (scriptId) => ipcRenderer.invoke('lua-complete-script', scriptId),

  onLuaScriptAlert: (callback) => {
    ipcRenderer.on('lua-script-alert', (event, alert) => callback(alert));
  },

  onLuaScriptLog: (callback) => {
    ipcRenderer.on('lua-script-log', (event, log) => callback(log));
  }
});
