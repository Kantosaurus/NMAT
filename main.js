const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const PacketCapture = require('./packetCapture');
const SecurityDetector = require('./securityDetection');
const HTTPProxy = require('./httpProxy');

let mainWindow;
let packetCapture;
let securityDetector;
let httpProxy;

// Development mode check
const isDev = !app.isPackaged;

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

  mainWindow.on('closed', () => {
    if (packetCapture) {
      packetCapture.stop();
    }
    if (httpProxy) {
      httpProxy.stop();
    }
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
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

ipcMain.handle('start-capture', async (event, deviceName) => {
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

    packetCapture = new PacketCapture(deviceName);

    packetCapture.on('packet', (packet) => {
      mainWindow.webContents.send('packet-captured', packet);

      // Run security detection on each packet
      securityDetector.detectThreats(packet);
    });

    packetCapture.on('error', (error) => {
      mainWindow.webContents.send('capture-error', error.message);
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

    httpProxy.start();

    // Configure webview session to use proxy
    const { session } = require('electron');
    const proxySession = session.fromPartition('proxy-session');
    await proxySession.setProxy({
      proxyRules: `http=127.0.0.1:${port};https=127.0.0.1:${port}`,
      proxyBypassRules: '<-loopback>'
    });

    // Disable certificate verification for the proxy session
    proxySession.setCertificateVerifyProc((request, callback) => {
      callback(0); // Accept all certificates
    });

    return { success: true, port };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('stop-proxy', async () => {
  try {
    if (httpProxy) {
      httpProxy.stop();
      httpProxy = null;
    }

    // Clear proxy configuration
    const { session } = require('electron');
    const proxySession = session.fromPartition('proxy-session');
    await proxySession.setProxy({
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
