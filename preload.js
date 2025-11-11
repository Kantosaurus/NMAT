const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  getInterfaces: () => ipcRenderer.invoke('get-interfaces'),
  startCapture: (deviceName) => ipcRenderer.invoke('start-capture', deviceName),
  stopCapture: () => ipcRenderer.invoke('stop-capture'),
  exportPackets: (packets, format) => ipcRenderer.invoke('export-packets', packets, format),

  onPacketCaptured: (callback) => {
    ipcRenderer.on('packet-captured', (event, packet) => callback(packet));
  },

  onCaptureError: (callback) => {
    ipcRenderer.on('capture-error', (event, error) => callback(error));
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
  windowIsMaximized: () => ipcRenderer.invoke('window-is-maximized')
});
