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
  startProxy: (port, settings) => ipcRenderer.invoke('start-proxy', port, settings),
  stopProxy: () => ipcRenderer.invoke('stop-proxy'),
  toggleIntercept: (enabled) => ipcRenderer.invoke('toggle-intercept', enabled),
  forwardIntercept: (id, modifiedRequest) => ipcRenderer.invoke('forward-intercept', id, modifiedRequest),
  dropIntercept: (id) => ipcRenderer.invoke('drop-intercept', id),
  getProxyHistory: (filters) => ipcRenderer.invoke('get-proxy-history', filters),
  clearProxyHistory: () => ipcRenderer.invoke('clear-proxy-history'),

  // Certificate Management
  generateCACertificate: () => ipcRenderer.invoke('generate-ca-certificate'),
  exportCACertificate: () => ipcRenderer.invoke('export-ca-certificate'),
  installCACertificate: () => ipcRenderer.invoke('install-ca-certificate'),

  // Repeater
  repeatRequest: (requestData) => ipcRenderer.invoke('repeat-request', requestData),

  // Spider/Crawler
  startSpider: (config, startUrls) => ipcRenderer.invoke('start-spider', config, startUrls),
  stopSpider: () => ipcRenderer.invoke('stop-spider'),
  getDiscoveredEndpoints: () => ipcRenderer.invoke('get-discovered-endpoints'),

  // Scanner
  startScan: (config, urls, policy) => ipcRenderer.invoke('start-scan', config, urls, policy),
  stopScan: () => ipcRenderer.invoke('stop-scan'),
  getVulnerabilities: (filters) => ipcRenderer.invoke('get-vulnerabilities', filters),
  getScanPolicies: () => ipcRenderer.invoke('get-scan-policies'),
  createScanPolicy: (policy) => ipcRenderer.invoke('create-scan-policy', policy),

  // Intruder
  startIntruderAttack: (attack) => ipcRenderer.invoke('start-intruder-attack', attack),
  stopIntruderAttack: () => ipcRenderer.invoke('stop-intruder-attack'),
  getIntruderResults: (attackId) => ipcRenderer.invoke('get-intruder-results', attackId),

  // Sequencer
  analyzeTokens: (tokens) => ipcRenderer.invoke('analyze-tokens', tokens),

  // Decoder/Encoder
  encodeText: (text, method, type) => ipcRenderer.invoke('encode-text', text, method, type),
  decodeText: (text, method) => ipcRenderer.invoke('decode-text', text, method),
  applyTransformationChain: (input, transformations) => ipcRenderer.invoke('apply-transformation-chain', input, transformations),
  detectEncoding: (text) => ipcRenderer.invoke('detect-encoding', text),

  // Comparer
  compareTexts: (text1, text2, mode) => ipcRenderer.invoke('compare-texts', text1, text2, mode),

  // Settings
  getProxySettings: () => ipcRenderer.invoke('get-proxy-settings'),
  updateProxySettings: (settings) => ipcRenderer.invoke('update-proxy-settings', settings),

  // Scope Rules
  getScopeRules: () => ipcRenderer.invoke('get-scope-rules'),
  addScopeRule: (rule) => ipcRenderer.invoke('add-scope-rule', rule),
  deleteScopeRule: (id) => ipcRenderer.invoke('delete-scope-rule', id),

  // Match & Replace Rules
  getMatchReplaceRules: () => ipcRenderer.invoke('get-match-replace-rules'),
  addMatchReplaceRule: (rule) => ipcRenderer.invoke('add-match-replace-rule', rule),
  deleteMatchReplaceRule: (id) => ipcRenderer.invoke('delete-match-replace-rule', id),

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

  onIntruderResult: (callback) => {
    ipcRenderer.on('intruder-result', (event, result) => callback(result));
  },

  onIntruderCompleted: (callback) => {
    ipcRenderer.on('intruder-completed', (event, data) => callback(data));
  },

  // Spider events
  onSpiderStarted: (callback) => {
    ipcRenderer.on('spider-started', () => callback());
  },

  onSpiderProgress: (callback) => {
    ipcRenderer.on('spider-progress', (event, stats) => callback(stats));
  },

  onSpiderEndpointDiscovered: (callback) => {
    ipcRenderer.on('spider-endpoint-discovered', (event, endpoint) => callback(endpoint));
  },

  onSpiderCompleted: (callback) => {
    ipcRenderer.on('spider-completed', (event, stats) => callback(stats));
  },

  onSpiderStopped: (callback) => {
    ipcRenderer.on('spider-stopped', () => callback());
  },

  // Scanner events
  onScanStarted: (callback) => {
    ipcRenderer.on('scan-started', () => callback());
  },

  onScanProgress: (callback) => {
    ipcRenderer.on('scan-progress', (event, progress) => callback(progress));
  },

  onVulnerabilityFound: (callback) => {
    ipcRenderer.on('vulnerability-found', (event, vuln) => callback(vuln));
  },

  onScanCompleted: (callback) => {
    ipcRenderer.on('scan-completed', () => callback());
  },

  onScanStopped: (callback) => {
    ipcRenderer.on('scan-stopped', () => callback());
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
  },

  // Session Handling & Macros
  getSessionRules: () => ipcRenderer.invoke('get-session-rules'),
  addSessionRule: (rule) => ipcRenderer.invoke('add-session-rule', rule),
  updateSessionRule: (id, updates) => ipcRenderer.invoke('update-session-rule', id, updates),
  deleteSessionRule: (id) => ipcRenderer.invoke('delete-session-rule', id),

  getMacros: () => ipcRenderer.invoke('get-macros'),
  createMacro: (macro) => ipcRenderer.invoke('create-macro', macro),
  updateMacro: (id, updates) => ipcRenderer.invoke('update-macro', id, updates),
  deleteMacro: (id) => ipcRenderer.invoke('delete-macro', id),
  executeMacro: (macroId, variables) => ipcRenderer.invoke('execute-macro', macroId, variables),

  cacheToken: (name, value, expiresIn) => ipcRenderer.invoke('cache-token', name, value, expiresIn),
  getCachedToken: (name) => ipcRenderer.invoke('get-cached-token', name),
  clearTokenCache: () => ipcRenderer.invoke('clear-token-cache'),

  onMacroProgress: (callback) => {
    ipcRenderer.on('macro-progress', (event, progress) => callback(progress));
  },

  onMacroCompleted: (callback) => {
    ipcRenderer.on('macro-completed', (event, data) => callback(data));
  },

  onMacroError: (callback) => {
    ipcRenderer.on('macro-error', (event, error) => callback(error));
  },

  onVariableExtracted: (callback) => {
    ipcRenderer.on('variable-extracted', (event, data) => callback(data));
  },

  // Logger Export
  exportHistory: (filters, format) => ipcRenderer.invoke('export-history', filters, format),

  // Extensions Management
  getExtensions: () => ipcRenderer.invoke('get-extensions'),
  loadExtension: (extensionId) => ipcRenderer.invoke('load-extension', extensionId),
  unloadExtension: (extensionId) => ipcRenderer.invoke('unload-extension', extensionId),
  toggleExtension: (extensionId, enabled) => ipcRenderer.invoke('toggle-extension', extensionId, enabled),
  installExtension: (sourcePath) => ipcRenderer.invoke('install-extension', sourcePath),
  uninstallExtension: (extensionId) => ipcRenderer.invoke('uninstall-extension', extensionId),
  runScannerExtensions: (url, requestData) => ipcRenderer.invoke('run-scanner-extensions', url, requestData),

  onExtensionNotification: (callback) => {
    ipcRenderer.on('extension-notification', (event, data) => callback(data));
  },

  // Collaborator (OAST)
  startCollaborator: (config) => ipcRenderer.invoke('start-collaborator', config),
  stopCollaborator: () => ipcRenderer.invoke('stop-collaborator'),
  getCollaboratorStatus: () => ipcRenderer.invoke('get-collaborator-status'),
  generateCollaboratorUrl: (context) => ipcRenderer.invoke('generate-collaborator-url', context),
  generateCollaboratorPayloads: (vulnerabilityType, targetUrl, parameter) =>
    ipcRenderer.invoke('generate-collaborator-payloads', vulnerabilityType, targetUrl, parameter),
  getCollaboratorInteractions: (filters) => ipcRenderer.invoke('get-collaborator-interactions', filters),
  getCollaboratorPayloads: () => ipcRenderer.invoke('get-collaborator-payloads'),
  startCollaboratorPolling: (interval) => ipcRenderer.invoke('start-collaborator-polling', interval),
  stopCollaboratorPolling: () => ipcRenderer.invoke('stop-collaborator-polling'),
  cleanupCollaborator: (olderThan) => ipcRenderer.invoke('cleanup-collaborator', olderThan),

  onCollaboratorInteraction: (callback) => {
    ipcRenderer.on('collaborator-interaction', (event, data) => callback(data));
  },

  onCollaboratorVulnerability: (callback) => {
    ipcRenderer.on('collaborator-vulnerability', (event, data) => callback(data));
  },

  // REST API Server
  startRestApi: (port) => ipcRenderer.invoke('start-rest-api', port),
  stopRestApi: () => ipcRenderer.invoke('stop-rest-api'),
  getRestApiStatus: () => ipcRenderer.invoke('get-rest-api-status'),
  generateApiKey: (name) => ipcRenderer.invoke('generate-api-key', name),
  listApiKeys: () => ipcRenderer.invoke('list-api-keys'),

  // Project Manager
  createProject: (projectData) => ipcRenderer.invoke('create-project', projectData),
  loadProject: (projectId) => ipcRenderer.invoke('load-project', projectId),
  updateProject: (projectId, updates) => ipcRenderer.invoke('update-project', projectId, updates),
  deleteProject: (projectId) => ipcRenderer.invoke('delete-project', projectId),
  listProjects: (filters) => ipcRenderer.invoke('list-projects', filters),
  applyProjectConfig: (projectId) => ipcRenderer.invoke('apply-project-config', projectId),

  // Scheduler
  createSchedule: (scheduleData) => ipcRenderer.invoke('create-schedule', scheduleData),
  updateSchedule: (scheduleId, updates) => ipcRenderer.invoke('update-schedule', scheduleId, updates),
  deleteSchedule: (scheduleId) => ipcRenderer.invoke('delete-schedule', scheduleId),
  getSchedules: (filters) => ipcRenderer.invoke('get-schedules', filters),
  startSchedule: (scheduleId) => ipcRenderer.invoke('start-schedule', scheduleId),
  stopSchedule: (scheduleId) => ipcRenderer.invoke('stop-schedule', scheduleId),
  runScheduleNow: (scheduleId) => ipcRenderer.invoke('run-schedule-now', scheduleId),
  getExecutionHistory: (scheduleId, limit) => ipcRenderer.invoke('get-execution-history', scheduleId, limit),

  onScheduleExecutionStarted: (callback) => {
    ipcRenderer.on('schedule-execution-started', (event, data) => callback(data));
  },

  onScheduleExecutionCompleted: (callback) => {
    ipcRenderer.on('schedule-execution-completed', (event, data) => callback(data));
  },

  onScheduleExecutionFailed: (callback) => {
    ipcRenderer.on('schedule-execution-failed', (event, data) => callback(data));
  },

  // Report Generator
  generateSecurityReport: (config) => ipcRenderer.invoke('generate-security-report', config),
  generateHtmlReport: (config) => ipcRenderer.invoke('generate-html-report', config),
  saveReport: (reportData, format, filepath) => ipcRenderer.invoke('save-report', reportData, format, filepath)
});
