const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const { app } = require('electron');

/**
 * Extension Manager - Load and manage extensions/plugins
 * Provides API for custom scanners, analyzers, and tools
 */
class ExtensionManager extends EventEmitter {
  constructor(database, mainWindow) {
    super();
    this.db = database;
    this.mainWindow = mainWindow;
    this.extensions = new Map();
    this.extensionsDir = path.join(app.getPath('userData'), 'extensions');

    // Extension API contexts
    this.scannerExtensions = new Map();
    this.analyzerExtensions = new Map();
    this.toolExtensions = new Map();

    // Ensure extensions directory exists
    if (!fs.existsSync(this.extensionsDir)) {
      fs.mkdirSync(this.extensionsDir, { recursive: true });
    }

    this.loadInstalledExtensions();
  }

  /**
   * Load all installed extensions from directory
   */
  loadInstalledExtensions() {
    try {
      const subdirs = fs.readdirSync(this.extensionsDir, { withFileTypes: true })
        .filter(dirent => dirent.isDirectory())
        .map(dirent => dirent.name);

      for (const dirname of subdirs) {
        try {
          this.loadExtension(dirname);
        } catch (error) {
          console.error(`Failed to load extension ${dirname}:`, error);
        }
      }
    } catch (error) {
      console.error('Failed to load extensions:', error);
    }
  }

  /**
   * Load a single extension
   */
  loadExtension(extensionId) {
    const extensionPath = path.join(this.extensionsDir, extensionId);
    const manifestPath = path.join(extensionPath, 'manifest.json');

    if (!fs.existsSync(manifestPath)) {
      throw new Error('Extension manifest not found');
    }

    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));

    // Validate manifest
    if (!manifest.id || !manifest.name || !manifest.version) {
      throw new Error('Invalid extension manifest: missing required fields');
    }

    // Check if already loaded
    if (this.extensions.has(manifest.id)) {
      throw new Error(`Extension ${manifest.id} is already loaded`);
    }

    // Create extension context
    const extension = {
      id: manifest.id,
      name: manifest.name,
      version: manifest.version,
      description: manifest.description || '',
      author: manifest.author || '',
      type: manifest.type || 'tool',
      enabled: true,
      path: extensionPath,
      manifest,
      instance: null
    };

    // Load extension code
    const mainFile = path.join(extensionPath, manifest.main || 'index.js');
    if (fs.existsSync(mainFile)) {
      try {
        const ExtensionClass = require(mainFile);
        const api = this.createExtensionAPI(extension);
        extension.instance = new ExtensionClass(api);

        // Initialize extension
        if (typeof extension.instance.init === 'function') {
          extension.instance.init();
        }
      } catch (error) {
        throw new Error(`Failed to load extension code: ${error.message}`);
      }
    }

    this.extensions.set(extension.id, extension);

    // Register by type
    switch (extension.type) {
      case 'scanner':
        this.scannerExtensions.set(extension.id, extension);
        break;
      case 'analyzer':
        this.analyzerExtensions.set(extension.id, extension);
        break;
      case 'tool':
        this.toolExtensions.set(extension.id, extension);
        break;
    }

    this.emit('extension-loaded', extension);
    console.log(`Loaded extension: ${extension.name} v${extension.version}`);

    return extension;
  }

  /**
   * Unload an extension
   */
  unloadExtension(extensionId) {
    const extension = this.extensions.get(extensionId);
    if (!extension) {
      throw new Error(`Extension ${extensionId} not found`);
    }

    // Call cleanup if available
    if (extension.instance && typeof extension.instance.cleanup === 'function') {
      extension.instance.cleanup();
    }

    // Remove from registries
    this.extensions.delete(extensionId);
    this.scannerExtensions.delete(extensionId);
    this.analyzerExtensions.delete(extensionId);
    this.toolExtensions.delete(extensionId);

    this.emit('extension-unloaded', extensionId);
    console.log(`Unloaded extension: ${extension.name}`);
  }

  /**
   * Enable/disable an extension
   */
  toggleExtension(extensionId, enabled) {
    const extension = this.extensions.get(extensionId);
    if (!extension) {
      throw new Error(`Extension ${extensionId} not found`);
    }

    extension.enabled = enabled;

    if (extension.instance) {
      if (enabled && typeof extension.instance.enable === 'function') {
        extension.instance.enable();
      } else if (!enabled && typeof extension.instance.disable === 'function') {
        extension.instance.disable();
      }
    }

    this.emit('extension-toggled', { extensionId, enabled });
  }

  /**
   * Install an extension from a directory or zip
   */
  async installExtension(sourcePath) {
    // For now, just copy the directory
    // In production, you'd want to validate, sandbox, and handle zips

    const manifestPath = path.join(sourcePath, 'manifest.json');
    if (!fs.existsSync(manifestPath)) {
      throw new Error('Invalid extension: manifest.json not found');
    }

    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    const destPath = path.join(this.extensionsDir, manifest.id);

    if (fs.existsSync(destPath)) {
      throw new Error('Extension already installed');
    }

    // Copy directory
    this.copyDirectory(sourcePath, destPath);

    // Load the extension
    return this.loadExtension(manifest.id);
  }

  /**
   * Uninstall an extension
   */
  uninstallExtension(extensionId) {
    const extension = this.extensions.get(extensionId);
    if (!extension) {
      throw new Error(`Extension ${extensionId} not found`);
    }

    // Unload first
    this.unloadExtension(extensionId);

    // Delete directory
    const extensionPath = path.join(this.extensionsDir, extensionId);
    if (fs.existsSync(extensionPath)) {
      fs.rmSync(extensionPath, { recursive: true, force: true });
    }

    this.emit('extension-uninstalled', extensionId);
  }

  /**
   * Get all extensions
   */
  getExtensions() {
    return Array.from(this.extensions.values()).map(ext => ({
      id: ext.id,
      name: ext.name,
      version: ext.version,
      description: ext.description,
      author: ext.author,
      type: ext.type,
      enabled: ext.enabled
    }));
  }

  /**
   * Get extension by ID
   */
  getExtension(extensionId) {
    return this.extensions.get(extensionId);
  }

  /**
   * Execute scanner extensions on a URL
   */
  async runScannerExtensions(url, requestData) {
    const results = [];

    for (const [id, extension] of this.scannerExtensions) {
      if (!extension.enabled || !extension.instance) continue;

      try {
        if (typeof extension.instance.scan === 'function') {
          const result = await extension.instance.scan(url, requestData);
          if (result && result.findings) {
            results.push({
              extensionId: id,
              extensionName: extension.name,
              findings: result.findings
            });
          }
        }
      } catch (error) {
        console.error(`Error running scanner extension ${id}:`, error);
      }
    }

    return results;
  }

  /**
   * Execute analyzer extensions on data
   */
  async runAnalyzerExtensions(data, type) {
    const results = [];

    for (const [id, extension] of this.analyzerExtensions) {
      if (!extension.enabled || !extension.instance) continue;

      try {
        if (typeof extension.instance.analyze === 'function') {
          const result = await extension.instance.analyze(data, type);
          if (result) {
            results.push({
              extensionId: id,
              extensionName: extension.name,
              result
            });
          }
        }
      } catch (error) {
        console.error(`Error running analyzer extension ${id}:`, error);
      }
    }

    return results;
  }

  /**
   * Create Extension API - Available to extensions
   */
  createExtensionAPI(extension) {
    return {
      // Extension info
      id: extension.id,
      name: extension.name,
      version: extension.version,

      // Logging
      log: (message) => {
        console.log(`[${extension.name}]`, message);
        this.emit('extension-log', { extensionId: extension.id, message });
      },

      warn: (message) => {
        console.warn(`[${extension.name}]`, message);
        this.emit('extension-warn', { extensionId: extension.id, message });
      },

      error: (message) => {
        console.error(`[${extension.name}]`, message);
        this.emit('extension-error', { extensionId: extension.id, message });
      },

      // Database access (read-only for safety)
      database: {
        getHistory: (filters) => this.db.getHistory(filters),
        getEndpoints: () => this.db.getEndpoints(),
        getVulnerabilities: (filters) => this.db.getVulnerabilities(filters)
      },

      // HTTP client
      http: {
        request: async (config) => {
          const axios = require('axios');
          const https = require('https');

          return await axios({
            ...config,
            httpsAgent: new https.Agent({
              rejectUnauthorized: false
            })
          });
        }
      },

      // UI interactions
      ui: {
        notify: (message, type = 'info') => {
          this.mainWindow.webContents.send('extension-notification', {
            extensionId: extension.id,
            extensionName: extension.name,
            message,
            type
          });
        },

        showDialog: async (options) => {
          const { dialog } = require('electron');
          return await dialog.showMessageBox(this.mainWindow, {
            title: extension.name,
            ...options
          });
        }
      },

      // Storage (scoped to extension)
      storage: {
        get: (key) => {
          const data = this.db.getSetting(`ext_${extension.id}_${key}`);
          return data ? JSON.parse(data) : null;
        },

        set: (key, value) => {
          this.db.setSetting(`ext_${extension.id}_${key}`, JSON.stringify(value));
        },

        delete: (key) => {
          this.db.setSetting(`ext_${extension.id}_${key}`, null);
        }
      },

      // Events
      events: {
        on: (event, handler) => {
          this.on(`ext_${extension.id}_${event}`, handler);
        },

        emit: (event, data) => {
          this.emit(`ext_${extension.id}_${event}`, data);
        }
      }
    };
  }

  /**
   * Helper: Copy directory recursively
   */
  copyDirectory(src, dest) {
    if (!fs.existsSync(dest)) {
      fs.mkdirSync(dest, { recursive: true });
    }

    const entries = fs.readdirSync(src, { withFileTypes: true });

    for (const entry of entries) {
      const srcPath = path.join(src, entry.name);
      const destPath = path.join(dest, entry.name);

      if (entry.isDirectory()) {
        this.copyDirectory(srcPath, destPath);
      } else {
        fs.copyFileSync(srcPath, destPath);
      }
    }
  }

  /**
   * Clean up all extensions
   */
  cleanup() {
    for (const [id, extension] of this.extensions) {
      if (extension.instance && typeof extension.instance.cleanup === 'function') {
        try {
          extension.instance.cleanup();
        } catch (error) {
          console.error(`Error cleaning up extension ${id}:`, error);
        }
      }
    }

    this.extensions.clear();
    this.scannerExtensions.clear();
    this.analyzerExtensions.clear();
    this.toolExtensions.clear();
    this.removeAllListeners();
  }
}

module.exports = ExtensionManager;
