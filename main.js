const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const PacketCapture = require('./packetCapture');
const SecurityDetector = require('./securityDetection');
const HTTPProxy = require('./httpProxy');
const StatisticsAnalyzer = require('./statisticsAnalyzer');
const ConfigurationManager = require('./configurationManager');
const LuaScriptEngine = require('./luaScriptEngine');
const ProxyBackend = require('./backend/proxy-backend');

let mainWindow;
let packetCapture;
let securityDetector;
let httpProxy;
let statisticsAnalyzer;
let configManager;
let luaEngine;
let proxyBackend;

// Development mode check
const isDev = !app.isPackaged;

// Ignore certificate errors for HTTPS interception
app.commandLine.appendSwitch('ignore-certificate-errors');
app.commandLine.appendSwitch('allow-insecure-localhost');
app.commandLine.appendSwitch('disable-features', 'OutOfBlinkCors');

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 700,
    frame: false,
    titleBarStyle: 'hidden',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      webviewTag: true,
    },
    icon: path.join(__dirname, 'assets', 'icon.png')
  });

  // Load from Vite dev server in development, or from built files in production
  if (isDev) {
    mainWindow.loadURL('http://localhost:3000');
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }

  // Handle webview attachment
  mainWindow.webContents.on('will-attach-webview', (event, webPreferences, params) => {
    console.log('Webview attaching, configuring preferences...');
    // Allow any webview content
    webPreferences.nodeIntegration = false;
    webPreferences.contextIsolation = true;
    // Use default session (no partition) so it inherits our certificate bypass
    delete params.partition;
  });

  mainWindow.on('closed', () => {
    if (packetCapture) {
      packetCapture.stop();
    }
    if (httpProxy) {
      httpProxy.stop();
    }
    if (proxyBackend) {
      proxyBackend.close();
    }
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  // Set up certificate verification bypass globally
  const { session } = require('electron');
  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    // Accept all certificates for HTTPS interception
    callback(0);
  });

  // Initialize configuration manager and lua engine
  configManager = new ConfigurationManager();
  luaEngine = new LuaScriptEngine();

  // Set up Lua script event listeners
  luaEngine.on('script-alert', (alert) => {
    if (mainWindow) {
      mainWindow.webContents.send('lua-script-alert', alert);
    }
  });

  luaEngine.on('script-log', (log) => {
    if (mainWindow) {
      mainWindow.webContents.send('lua-script-log', log);
    }
  });

  createWindow();

  // Initialize proxy backend
  proxyBackend = new ProxyBackend(mainWindow);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Handle certificate errors for all webContents (including webviews)
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  // Prevent the default behavior which is to reject the certificate
  event.preventDefault();
  // Accept the certificate (needed for MITM proxy)
  callback(true);
});

// Handle webview creation and set up certificate bypass for each one
app.on('web-contents-created', (event, contents) => {
  // For webviews/guest contents
  if (contents.getType() === 'webview') {
    console.log('Webview created, setting up certificate bypass...');

    // Get the webview's session
    const webviewSession = contents.session;
    if (webviewSession) {
      // Disable certificate verification for this webview's session
      webviewSession.setCertificateVerifyProc((request, callback) => {
        console.log('Certificate verification bypassed for:', request.hostname);
        callback(0); // Accept all certificates
      });
    }

    // Handle certificate errors for this specific webview
    contents.on('certificate-error', (event, url, error, certificate, callback) => {
      console.log('Certificate error caught for webview:', url, error);
      event.preventDefault();
      callback(true);
    });

    // Handle did-fail-load events
    contents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL) => {
      if (errorCode === -3 || errorCode === -321) {
        console.log('Certificate-related load failure:', errorDescription, 'for', validatedURL);
      }
    });
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC Handlers
ipcMain.handle('get-interfaces', async () => {
  try {
    const Cap = require('cap').Cap;
    const devices = Cap.deviceList();
    return { success: true, devices };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('start-capture', async (event, deviceName, options = {}) => {
  try {
    if (packetCapture) {
      packetCapture.stop();
    }

    // Initialize security detector
    securityDetector = new SecurityDetector();

    // Set up security alert listener
    securityDetector.onAlert((alert) => {
      mainWindow.webContents.send('security-alert', alert);
    });

    // Initialize statistics analyzer
    statisticsAnalyzer = new StatisticsAnalyzer();

    packetCapture = new PacketCapture(deviceName, options);

    packetCapture.on('packet', (packet) => {
      mainWindow.webContents.send('packet-captured', packet);

      // Run security detection on each packet
      securityDetector.detectThreats(packet);

      // Add packet to statistics analyzer
      statisticsAnalyzer.addPacket(packet);

      // Send expert alerts if any new ones were generated
      const alerts = statisticsAnalyzer.getExpertAlerts();
      if (alerts.length > 0) {
        mainWindow.webContents.send('expert-alert', alerts[alerts.length - 1]);
      }

      // Execute loaded Lua scripts on packet
      if (luaEngine) {
        const loadedScripts = luaEngine.getLoadedScripts();
        loadedScripts.forEach(script => {
          luaEngine.executeOnPacket(script.id, packet);
        });
      }
    });

    packetCapture.on('error', (error) => {
      mainWindow.webContents.send('capture-error', error.message);
    });

    packetCapture.on('stopped', (stats) => {
      mainWindow.webContents.send('capture-stopped', stats);
    });

    packetCapture.on('file-rotated', (filepath) => {
      mainWindow.webContents.send('capture-file-rotated', filepath);
    });

    packetCapture.start();

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('stop-capture', async () => {
  try {
    if (packetCapture) {
      packetCapture.stop();
      packetCapture = null;
    }
    if (securityDetector) {
      securityDetector = null;
    }
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('load-pcap-file', async () => {
  const { dialog } = require('electron');

  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Load PCAP/PCAPNG File',
      filters: [
        { name: 'Packet Capture Files', extensions: ['pcap', 'pcapng', 'cap'] },
        { name: 'All Files', extensions: ['*'] }
      ],
      properties: ['openFile']
    });

    if (result.canceled || result.filePaths.length === 0) {
      return { success: false, error: 'File selection cancelled' };
    }

    const filepath = result.filePaths[0];

    // Stop current capture if running
    if (packetCapture) {
      packetCapture.stop();
    }

    // Initialize security detector
    securityDetector = new SecurityDetector();

    // Set up security alert listener
    securityDetector.onAlert((alert) => {
      mainWindow.webContents.send('security-alert', alert);
    });

    // Create new PacketCapture instance for offline analysis
    packetCapture = new PacketCapture(null);

    packetCapture.on('packet', (packet) => {
      mainWindow.webContents.send('packet-captured', packet);

      // Run security detection on each packet
      securityDetector.detectThreats(packet);
    });

    packetCapture.on('error', (error) => {
      mainWindow.webContents.send('capture-error', error.message);
    });

    // Load the pcap file
    const pcapResult = await packetCapture.loadPcapFile(filepath);

    return {
      success: true,
      filepath,
      packetCount: pcapResult.packetCount
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// Statistics IPC Handlers
ipcMain.handle('get-protocol-hierarchy', async () => {
  try {
    if (statisticsAnalyzer) {
      return { success: true, data: statisticsAnalyzer.getProtocolHierarchy() };
    }
    return { success: false, error: 'Statistics analyzer not initialized' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-conversations', async (event, type = 'ip') => {
  try {
    if (statisticsAnalyzer) {
      return { success: true, data: statisticsAnalyzer.getConversations(type) };
    }
    return { success: false, error: 'Statistics analyzer not initialized' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-endpoints', async (event, type = 'ip') => {
  try {
    if (statisticsAnalyzer) {
      return { success: true, data: statisticsAnalyzer.getEndpoints(type) };
    }
    return { success: false, error: 'Statistics analyzer not initialized' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-io-graph', async () => {
  try {
    if (statisticsAnalyzer) {
      return { success: true, data: statisticsAnalyzer.getIOGraphData() };
    }
    return { success: false, error: 'Statistics analyzer not initialized' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-tcp-streams', async () => {
  try {
    if (statisticsAnalyzer) {
      return { success: true, data: statisticsAnalyzer.getAllTCPStreams() };
    }
    return { success: false, error: 'Statistics analyzer not initialized' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-expert-alerts', async () => {
  try {
    if (statisticsAnalyzer) {
      return { success: true, data: statisticsAnalyzer.getExpertAlerts() };
    }
    return { success: false, error: 'Statistics analyzer not initialized' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-srt-statistics', async () => {
  try {
    if (statisticsAnalyzer) {
      return { success: true, data: statisticsAnalyzer.getSRTStatistics() };
    }
    return { success: false, error: 'Statistics analyzer not initialized' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-flow-graph', async () => {
  try {
    if (statisticsAnalyzer) {
      return { success: true, data: statisticsAnalyzer.getFlowGraph() };
    }
    return { success: false, error: 'Statistics analyzer not initialized' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('resolve-hostname', async (event, ip) => {
  try {
    if (statisticsAnalyzer) {
      const hostname = await statisticsAnalyzer.resolveHostname(ip);
      return { success: true, hostname };
    }
    return { success: false, error: 'Statistics analyzer not initialized' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('resolve-mac-vendor', async (event, mac) => {
  try {
    if (statisticsAnalyzer) {
      const vendor = statisticsAnalyzer.resolveMacVendor(mac);
      return { success: true, vendor };
    }
    return { success: false, error: 'Statistics analyzer not initialized' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('resolve-service', async (event, port) => {
  try {
    if (statisticsAnalyzer) {
      const service = statisticsAnalyzer.resolveService(port);
      return { success: true, service };
    }
    return { success: false, error: 'Statistics analyzer not initialized' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('export-statistics', async (event, type, format) => {
  const { dialog } = require('electron');
  const fs = require('fs');

  try {
    if (!statisticsAnalyzer) {
      return { success: false, error: 'Statistics analyzer not initialized' };
    }

    let content;
    let extension;

    if (format === 'json') {
      content = statisticsAnalyzer.exportToJSON();
      extension = 'json';
    } else if (format === 'csv') {
      content = statisticsAnalyzer.exportToCSV(type);
      extension = 'csv';
    } else if (format === 'xml') {
      content = statisticsAnalyzer.exportToXML();
      extension = 'xml';
    } else {
      return { success: false, error: 'Unsupported format' };
    }

    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Export Statistics',
      defaultPath: `statistics_${type}_${Date.now()}.${extension}`,
      filters: [
        { name: format.toUpperCase(), extensions: [extension] }
      ]
    });

    if (!result.canceled) {
      fs.writeFileSync(result.filePath, content);
      return { success: true };
    }

    return { success: false, error: 'Export cancelled' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('export-packets', async (event, packets, format) => {
  const { dialog } = require('electron');
  const fs = require('fs');

  try {
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Export Packets',
      defaultPath: `capture_${Date.now()}.${format}`,
      filters: [
        { name: format.toUpperCase(), extensions: [format] }
      ]
    });

    if (!result.canceled) {
      let content;
      if (format === 'json') {
        content = JSON.stringify(packets, null, 2);
      } else if (format === 'csv') {
        const headers = 'No,Time,Source,Destination,Protocol,Length,Info\\n';
        const rows = packets.map(p =>
          `${p.no},${p.timestamp},${p.source},${p.destination},${p.protocol},${p.length},"${p.info}"`
        ).join('\\n');
        content = headers + rows;
      }

      fs.writeFileSync(result.filePath, content);
      return { success: true };
    }
    return { success: false, error: 'Export cancelled' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// Window control handlers
ipcMain.handle('window-minimize', () => {
  mainWindow.minimize();
});

ipcMain.handle('window-maximize', () => {
  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize();
    return false;
  } else {
    mainWindow.maximize();
    return true;
  }
});

ipcMain.handle('window-close', () => {
  mainWindow.close();
});

ipcMain.handle('window-is-maximized', () => {
  return mainWindow.isMaximized();
});

// HTTP Proxy handlers
ipcMain.handle('start-proxy', async (event, port = 8080) => {
  try {
    if (httpProxy) {
      httpProxy.stop();
    }

    httpProxy = new HTTPProxy(port);

    // Set up event listeners
    httpProxy.on('started', (proxyPort) => {
      mainWindow.webContents.send('proxy-started', proxyPort);
    });

    httpProxy.on('stopped', () => {
      mainWindow.webContents.send('proxy-stopped');
    });

    httpProxy.on('error', (error) => {
      mainWindow.webContents.send('proxy-error', error.message);
    });

    httpProxy.on('intercept', (interceptItem) => {
      mainWindow.webContents.send('proxy-intercept', interceptItem);
    });

    httpProxy.on('history-update', (item) => {
      mainWindow.webContents.send('proxy-history-update', item);
    });

    httpProxy.on('history-cleared', () => {
      mainWindow.webContents.send('proxy-history-cleared');
    });

    httpProxy.on('intruder-progress', (progress) => {
      mainWindow.webContents.send('intruder-progress', progress);
    });

    // Handle certificate installation completion
    httpProxy.on('cert-ready', async () => {
      console.log('Certificate ready, reinitializing Electron session...');

      const { session } = require('electron');
      const defaultSession = session.defaultSession;

      // Clear certificate cache to pick up newly installed cert
      await defaultSession.clearCache();
      await defaultSession.clearStorageData();

      // Recreate certificate verification bypass with new cert
      defaultSession.setCertificateVerifyProc((request, callback) => {
        callback(0);
      });

      console.log('Electron session reinitialized with new certificate');
    });

    // Start the proxy (this will auto-install certificate)
    await httpProxy.start();

    // Configure default session to use proxy
    const { session } = require('electron');
    const defaultSession = session.defaultSession;

    await defaultSession.setProxy({
      proxyRules: `http=127.0.0.1:${port};https=127.0.0.1:${port}`,
      proxyBypassRules: '<-loopback>'
    });

    return { success: true, port };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('stop-proxy', async () => {
  try {
    if (httpProxy) {
      await httpProxy.stop();
      httpProxy = null;
    }

    // Clear proxy configuration
    const { session } = require('electron');
    const defaultSession = session.defaultSession;
    await defaultSession.setProxy({
      proxyRules: '',
      proxyBypassRules: ''
    });

    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('toggle-intercept', async (event, enabled) => {
  try {
    if (httpProxy) {
      httpProxy.setIntercept(enabled);
      return { success: true, enabled };
    }
    return { success: false, error: 'Proxy not running' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('forward-intercept', async (event, id, modifiedRequest) => {
  try {
    if (httpProxy) {
      httpProxy.forwardIntercept(id, modifiedRequest);
      return { success: true };
    }
    return { success: false, error: 'Proxy not running' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('drop-intercept', async (event, id) => {
  try {
    if (httpProxy) {
      httpProxy.dropIntercept(id);
      return { success: true };
    }
    return { success: false, error: 'Proxy not running' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-proxy-history', async () => {
  try {
    if (httpProxy) {
      return { success: true, history: httpProxy.getHistory() };
    }
    return { success: false, error: 'Proxy not running' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('clear-proxy-history', async () => {
  try {
    if (httpProxy) {
      httpProxy.clearHistory();
      return { success: true };
    }
    return { success: false, error: 'Proxy not running' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('repeat-request', async (event, requestData) => {
  try {
    if (httpProxy) {
      const result = await httpProxy.repeatRequest(requestData);
      return { success: true, result };
    }
    return { success: false, error: 'Proxy not running' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('run-intruder', async (event, requestData, positions, payloads, attackType) => {
  try {
    if (httpProxy) {
      const results = await httpProxy.intruderAttack(requestData, positions, payloads, attackType);
      return { success: true, results };
    }
    return { success: false, error: 'Proxy not running' };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// Configuration Management IPC Handlers
ipcMain.handle('config-list-profiles', async () => {
  try {
    const profiles = configManager.listProfiles();
    return { success: true, profiles };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-load-profile', async (event, profileName) => {
  try {
    const config = configManager.loadProfile(profileName);
    return { success: true, config };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-save-profile', async (event, profileName) => {
  try {
    configManager.saveProfile(profileName);
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-delete-profile', async (event, profileName) => {
  try {
    const result = configManager.deleteProfile(profileName);
    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-duplicate-profile', async (event, sourceName, newName) => {
  try {
    const result = configManager.duplicateProfile(sourceName, newName);
    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-get-current', async () => {
  try {
    const config = configManager.getCurrentConfig();
    return { success: true, ...config };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-get-custom-columns', async () => {
  try {
    const columns = configManager.getCustomColumns();
    return { success: true, columns };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-set-custom-columns', async (event, columns) => {
  try {
    configManager.setCustomColumns(columns);
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-add-custom-column', async (event, field, position) => {
  try {
    const result = configManager.addCustomColumn(field, position);
    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-remove-custom-column', async (event, columnId) => {
  try {
    const result = configManager.removeCustomColumn(columnId);
    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-reorder-columns', async (event, fromIndex, toIndex) => {
  try {
    const result = configManager.reorderColumns(fromIndex, toIndex);
    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-get-available-fields', async () => {
  try {
    const fields = configManager.getAvailableFields();
    return { success: true, fields };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-get-color-rules', async () => {
  try {
    const rules = configManager.getColorRules();
    return { success: true, rules };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-add-color-rule', async (event, rule) => {
  try {
    const result = configManager.addColorRule(rule);
    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config-remove-color-rule', async (event, ruleName) => {
  try {
    const result = configManager.removeColorRule(ruleName);
    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// Lua Script Engine IPC Handlers
ipcMain.handle('lua-get-templates', async () => {
  try {
    const templates = luaEngine.getTemplates();
    return { success: true, templates };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('lua-get-template-code', async (event, templateId) => {
  try {
    const code = luaEngine.getTemplateCode(templateId);
    return { success: true, code };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('lua-load-script', async (event, scriptId, scriptCode) => {
  try {
    const result = luaEngine.loadScript(scriptId, scriptCode);
    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('lua-unload-script', async (event, scriptId) => {
  try {
    const result = luaEngine.unloadScript(scriptId);
    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('lua-get-loaded-scripts', async () => {
  try {
    const scripts = luaEngine.getLoadedScripts();
    return { success: true, scripts };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('lua-get-results', async (event, scriptId) => {
  try {
    const results = luaEngine.getResults(scriptId);
    return { success: true, results };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('lua-execute-on-packet', async (event, scriptId, packet) => {
  try {
    const result = luaEngine.executeOnPacket(scriptId, packet);
    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('lua-complete-script', async (event, scriptId) => {
  try {
    const result = luaEngine.complete(scriptId);
    return result;
  } catch (error) {
    return { success: false, error: error.message };
  }
});
