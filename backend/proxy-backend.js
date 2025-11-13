const { ipcMain } = require('electron');
const ProxyDatabase = require('./database');
const Repeater = require('./proxy/repeater');
const Spider = require('./spider');
const Scanner = require('./scanner');
const Intruder = require('./intruder');
const Sequencer = require('./sequencer');
const Decoder = require('./decoder');
const SessionHandler = require('./session-handler');
const LoggerExporter = require('./logger/exporter');
const ExtensionManager = require('./extensions');
const Collaborator = require('./collaborator');
const RestApiServer = require('./api/rest-server');
const ProjectManager = require('./project/manager');
const Scheduler = require('./scheduler');
const ReportGenerator = require('./reports/generator');

class ProxyBackend {
  constructor(mainWindow) {
    this.mainWindow = mainWindow;
    this.db = new ProxyDatabase();
    this.repeater = new Repeater();
    this.sequencer = new Sequencer();
    this.decoder = new Decoder();
    this.sessionHandler = new SessionHandler(this.db);
    this.loggerExporter = new LoggerExporter(mainWindow);
    this.extensionManager = new ExtensionManager(this.db, mainWindow);
    this.collaborator = new Collaborator(this.db);
    this.restApiServer = new RestApiServer(this);
    this.projectManager = new ProjectManager(this.db);
    this.scheduler = new Scheduler(this.db, this);
    this.reportGenerator = new ReportGenerator(this.db);
    this.spider = null;
    this.scanner = null;
    this.intruder = null;

    // Set up Collaborator event listeners
    this.collaborator.on('interaction', (data) => {
      mainWindow.webContents.send('collaborator-interaction', data);
    });

    this.collaborator.on('vulnerability-detected', (data) => {
      mainWindow.webContents.send('collaborator-vulnerability', data);
    });

    // Set up Scheduler event listeners
    this.scheduler.on('execution-started', (data) => {
      mainWindow.webContents.send('schedule-execution-started', data);
    });

    this.scheduler.on('execution-completed', (data) => {
      mainWindow.webContents.send('schedule-execution-completed', data);
    });

    this.scheduler.on('execution-failed', (data) => {
      mainWindow.webContents.send('schedule-execution-failed', data);
    });

    this.registerHandlers();
  }

  registerHandlers() {
    // Proxy History
    ipcMain.handle('get-proxy-history', async (event, filters) => {
      try {
        return { success: true, result: this.db.getHistory(filters || {}) };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('clear-proxy-history', async () => {
      try {
        this.db.clearHistory();
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Repeater
    ipcMain.handle('repeat-request', async (event, requestData) => {
      try {
        const response = await this.repeater.sendRequest(requestData);
        return { success: true, result: response };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Spider
    ipcMain.handle('start-spider', async (event, config, startUrls) => {
      try {
        if (this.spider) {
          await this.spider.stop();
        }

        this.spider = new Spider(config, this.db);

        // Set up event listeners
        this.spider.on('started', () => {
          this.mainWindow.webContents.send('spider-started');
        });

        this.spider.on('progress', (stats) => {
          this.mainWindow.webContents.send('spider-progress', stats);
        });

        this.spider.on('endpoint-discovered', (endpoint) => {
          this.mainWindow.webContents.send('spider-endpoint-discovered', endpoint);
        });

        this.spider.on('completed', (stats) => {
          this.mainWindow.webContents.send('spider-completed', stats);
        });

        this.spider.on('stopped', () => {
          this.mainWindow.webContents.send('spider-stopped');
        });

        // Start spider (don't await, let it run in background)
        this.spider.start(startUrls).catch(err => {
          console.error('Spider error:', err);
        });

        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('stop-spider', async () => {
      try {
        if (this.spider) {
          await this.spider.stop();
        }
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-discovered-endpoints', async () => {
      try {
        const endpoints = this.db.getEndpoints();
        return { success: true, result: endpoints };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Scanner
    ipcMain.handle('start-scan', async (event, config, urls, policy) => {
      try {
        if (this.scanner) {
          this.scanner.stop();
        }

        this.scanner = new Scanner(config, this.db);

        // Set up event listeners
        this.scanner.on('started', () => {
          this.mainWindow.webContents.send('scan-started');
        });

        this.scanner.on('progress', (progress) => {
          this.mainWindow.webContents.send('scan-progress', progress);
        });

        this.scanner.on('vulnerability-found', (vuln) => {
          this.mainWindow.webContents.send('vulnerability-found', vuln);
        });

        this.scanner.on('completed', () => {
          this.mainWindow.webContents.send('scan-completed');
        });

        this.scanner.on('stopped', () => {
          this.mainWindow.webContents.send('scan-stopped');
        });

        // Start scan (don't await, let it run in background)
        this.scanner.scan(urls, policy).catch(err => {
          console.error('Scanner error:', err);
        });

        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('stop-scan', async () => {
      try {
        if (this.scanner) {
          this.scanner.stop();
        }
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-vulnerabilities', async (event, filters) => {
      try {
        const vulns = this.db.getVulnerabilities(filters || {});
        return { success: true, result: vulns };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-scan-policies', async () => {
      try {
        // For now, return default policies
        const policies = [
          {
            id: 'default',
            name: 'Default Policy',
            description: 'Balanced scan covering all common vulnerabilities',
            isDefault: true,
            vulnerabilityChecks: {
              sqlInjection: true,
              xssReflected: true,
              xssStored: true,
              xssDom: true,
              csrf: true,
              xxe: true,
              ssrf: true,
              rce: true,
              openRedirect: true,
              insecureCookie: true,
              clickjacking: true,
              pathTraversal: true,
              commandInjection: true,
              ldapInjection: true,
              xmlInjection: true,
              headerInjection: true,
              fileUpload: true,
              authBypass: true,
              authorizationBypass: true,
              informationDisclosure: true,
              securityMisconfiguration: true
            }
          }
        ];
        return { success: true, result: policies };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Intruder
    ipcMain.handle('start-intruder-attack', async (event, attack) => {
      try {
        if (this.intruder) {
          this.intruder.stop();
        }

        this.intruder = new Intruder(this.db);

        // Set up event listeners
        this.intruder.on('started', (attackId) => {
          console.log('Intruder attack started:', attackId);
        });

        this.intruder.on('progress', (progress) => {
          this.mainWindow.webContents.send('intruder-progress', progress);
        });

        this.intruder.on('result', (result) => {
          this.mainWindow.webContents.send('intruder-result', result);
        });

        this.intruder.on('completed', (data) => {
          this.mainWindow.webContents.send('intruder-completed', data);
        });

        this.intruder.on('error', (error) => {
          console.error('Intruder error:', error);
        });

        // Start attack (don't await, let it run in background)
        this.intruder.startAttack(attack).catch(err => {
          console.error('Intruder attack error:', err);
        });

        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('stop-intruder-attack', async () => {
      try {
        if (this.intruder) {
          this.intruder.stop();
        }
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-intruder-results', async (event, attackId) => {
      try {
        const results = this.db.getIntruderResults(attackId);
        return { success: true, result: results };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Sequencer
    ipcMain.handle('analyze-tokens', async (event, tokens) => {
      try {
        const analysis = this.sequencer.analyzeTokens(tokens);
        return { success: true, result: analysis };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Decoder
    ipcMain.handle('encode-text', async (event, text, method, type) => {
      try {
        const result = this.decoder.applyTransformation(text, { type, method });
        return { success: true, result };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('decode-text', async (event, text, method) => {
      try {
        const result = this.decoder.applyTransformation(text, { type: 'decode', method });
        return { success: true, result };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('apply-transformation-chain', async (event, input, transformations) => {
      try {
        const result = this.decoder.applyChain(input, transformations);
        return { success: true, result };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('detect-encoding', async (event, text) => {
      try {
        const detections = this.decoder.detectEncoding(text);
        return { success: true, result: detections };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Comparer
    ipcMain.handle('compare-texts', async (event, text1, text2, mode) => {
      try {
        const result = this.decoder.compare(text1, text2, mode);
        return { success: true, result };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Settings
    ipcMain.handle('get-proxy-settings', async () => {
      try {
        const settings = this.db.getSetting('proxy-settings') || {
          proxyPort: 8080,
          sslInterception: true,
          upstreamProxy: {
            enabled: false,
            host: '',
            port: 8080,
            type: 'http'
          },
          autoForward: false,
          interceptRequests: true,
          interceptResponses: false
        };
        return { success: true, result: settings };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('update-proxy-settings', async (event, settings) => {
      try {
        this.db.setSetting('proxy-settings', settings);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Scope Rules
    ipcMain.handle('get-scope-rules', async () => {
      try {
        const rules = this.db.getScopeRules();
        return { success: true, result: rules };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('add-scope-rule', async (event, rule) => {
      try {
        this.db.addScopeRule(rule);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('delete-scope-rule', async (event, id) => {
      try {
        this.db.deleteScopeRule(id);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Match & Replace Rules
    ipcMain.handle('get-match-replace-rules', async () => {
      try {
        const rules = this.db.getMatchReplaceRules();
        return { success: true, result: rules };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('add-match-replace-rule', async (event, rule) => {
      try {
        this.db.addMatchReplaceRule(rule);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('delete-match-replace-rule', async (event, id) => {
      try {
        this.db.deleteMatchReplaceRule(id);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Session Handling & Macros
    ipcMain.handle('get-session-rules', async () => {
      try {
        const rules = this.sessionHandler.getRules();
        return { success: true, result: rules };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('add-session-rule', async (event, rule) => {
      try {
        const newRule = this.sessionHandler.addRule(rule);
        return { success: true, result: newRule };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('update-session-rule', async (event, id, updates) => {
      try {
        const updatedRule = this.sessionHandler.updateRule(id, updates);
        return { success: true, result: updatedRule };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('delete-session-rule', async (event, id) => {
      try {
        this.sessionHandler.deleteRule(id);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-macros', async () => {
      try {
        const macros = this.sessionHandler.getMacros();
        return { success: true, result: macros };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('create-macro', async (event, macro) => {
      try {
        const newMacro = this.sessionHandler.createMacro(macro);
        return { success: true, result: newMacro };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('update-macro', async (event, id, updates) => {
      try {
        const updatedMacro = this.sessionHandler.updateMacro(id, updates);
        return { success: true, result: updatedMacro };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('delete-macro', async (event, id) => {
      try {
        this.sessionHandler.deleteMacro(id);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('execute-macro', async (event, macroId, variables) => {
      try {
        // Set up event listeners for macro execution
        const progressHandler = (progress) => {
          this.mainWindow.webContents.send('macro-progress', progress);
        };
        const variableHandler = (data) => {
          this.mainWindow.webContents.send('variable-extracted', data);
        };

        this.sessionHandler.on('macro-progress', progressHandler);
        this.sessionHandler.on('variable-extracted', variableHandler);

        const result = await this.sessionHandler.executeMacro(macroId, variables);

        // Clean up listeners
        this.sessionHandler.off('macro-progress', progressHandler);
        this.sessionHandler.off('variable-extracted', variableHandler);

        this.mainWindow.webContents.send('macro-completed', { macroId, ...result });

        return { success: true, result };
      } catch (error) {
        this.mainWindow.webContents.send('macro-error', { macroId, error: error.message });
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('cache-token', async (event, name, value, expiresIn) => {
      try {
        this.sessionHandler.cacheToken(name, value, expiresIn);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-cached-token', async (event, name) => {
      try {
        const value = this.sessionHandler.getCachedToken(name);
        return { success: true, result: value };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('clear-token-cache', async () => {
      try {
        this.sessionHandler.clearTokenCache();
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Logger Export
    ipcMain.handle('export-history', async (event, filters, format) => {
      try {
        const items = this.db.getHistory(filters || {});
        const result = await this.loggerExporter.export(items, format || 'json');
        return result;
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Extensions Management
    ipcMain.handle('get-extensions', async () => {
      try {
        const extensions = this.extensionManager.getExtensions();
        return { success: true, result: extensions };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('load-extension', async (event, extensionId) => {
      try {
        const extension = this.extensionManager.loadExtension(extensionId);
        return { success: true, result: extension };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('unload-extension', async (event, extensionId) => {
      try {
        this.extensionManager.unloadExtension(extensionId);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('toggle-extension', async (event, extensionId, enabled) => {
      try {
        this.extensionManager.toggleExtension(extensionId, enabled);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('install-extension', async (event, sourcePath) => {
      try {
        const extension = await this.extensionManager.installExtension(sourcePath);
        return { success: true, result: extension };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('uninstall-extension', async (event, extensionId) => {
      try {
        this.extensionManager.uninstallExtension(extensionId);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('run-scanner-extensions', async (event, url, requestData) => {
      try {
        const results = await this.extensionManager.runScannerExtensions(url, requestData);
        return { success: true, result: results };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Collaborator (OAST)
    ipcMain.handle('start-collaborator', async (event, config) => {
      try {
        const result = await this.collaborator.start(config);
        return { success: true, result };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('stop-collaborator', async () => {
      try {
        await this.collaborator.stop();
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-collaborator-status', async () => {
      try {
        const status = this.collaborator.getStatus();
        return { success: true, result: status };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('generate-collaborator-url', async (event, context) => {
      try {
        const result = this.collaborator.generateCollaboratorUrl(context);
        return { success: true, result };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('generate-collaborator-payloads', async (event, vulnerabilityType, targetUrl, parameter) => {
      try {
        const result = this.collaborator.generatePayloadsForVulnerability(vulnerabilityType, targetUrl, parameter);
        return { success: true, result };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-collaborator-interactions', async (event, filters) => {
      try {
        const interactions = this.collaborator.getInteractions(filters);
        return { success: true, result: interactions };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-collaborator-payloads', async () => {
      try {
        const payloads = this.collaborator.getPayloads();
        return { success: true, result: payloads };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('start-collaborator-polling', async (event, interval) => {
      try {
        this.collaborator.startPolling(interval);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('stop-collaborator-polling', async () => {
      try {
        this.collaborator.stopPolling();
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('cleanup-collaborator', async (event, olderThan) => {
      try {
        this.collaborator.cleanup(olderThan);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // REST API Server
    ipcMain.handle('start-rest-api', async (event, port) => {
      try {
        const result = await this.restApiServer.start(port);
        return { success: true, result };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('stop-rest-api', async () => {
      try {
        await this.restApiServer.stop();
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-rest-api-status', async () => {
      try {
        const status = this.restApiServer.getStatus();
        return { success: true, result: status };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('generate-api-key', async (event, name) => {
      try {
        const apiKey = this.restApiServer.generateApiKey(name);
        return { success: true, result: apiKey };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('list-api-keys', async () => {
      try {
        const keys = this.restApiServer.listApiKeys();
        return { success: true, result: keys };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Project Manager
    ipcMain.handle('create-project', async (event, projectData) => {
      try {
        const project = this.projectManager.createProject(projectData);
        return { success: true, result: project };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('load-project', async (event, projectId) => {
      try {
        const project = this.projectManager.loadProject(projectId);
        return { success: true, result: project };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('update-project', async (event, projectId, updates) => {
      try {
        const project = this.projectManager.updateProject(projectId, updates);
        return { success: true, result: project };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('delete-project', async (event, projectId) => {
      try {
        this.projectManager.deleteProject(projectId);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('list-projects', async (event, filters) => {
      try {
        const projects = this.projectManager.listProjects(filters);
        return { success: true, result: projects };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('apply-project-config', async (event, projectId) => {
      try {
        const project = this.projectManager.applyProjectConfig(projectId, this);
        return { success: true, result: project };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Scheduler
    ipcMain.handle('create-schedule', async (event, scheduleData) => {
      try {
        const schedule = this.scheduler.createSchedule(scheduleData);
        return { success: true, result: schedule };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('update-schedule', async (event, scheduleId, updates) => {
      try {
        const schedule = this.scheduler.updateSchedule(scheduleId, updates);
        return { success: true, result: schedule };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('delete-schedule', async (event, scheduleId) => {
      try {
        this.scheduler.deleteSchedule(scheduleId);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-schedules', async (event, filters) => {
      try {
        const schedules = this.scheduler.getSchedules(filters);
        return { success: true, result: schedules };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('start-schedule', async (event, scheduleId) => {
      try {
        this.scheduler.startSchedule(scheduleId);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('stop-schedule', async (event, scheduleId) => {
      try {
        this.scheduler.stopSchedule(scheduleId);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('run-schedule-now', async (event, scheduleId) => {
      try {
        await this.scheduler.runNow(scheduleId);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('get-execution-history', async (event, scheduleId, limit) => {
      try {
        const history = this.scheduler.getExecutionHistory(scheduleId, limit);
        return { success: true, result: history };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Report Generator
    ipcMain.handle('generate-security-report', async (event, config) => {
      try {
        const report = this.reportGenerator.generateReport(config);
        return { success: true, result: report };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('generate-html-report', async (event, config) => {
      try {
        const reportData = this.reportGenerator.generateReport(config);
        const html = this.reportGenerator.generateHTML(reportData);
        return { success: true, result: html };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    ipcMain.handle('save-report', async (event, reportData, format, filepath) => {
      try {
        const path = await this.reportGenerator.saveReport(reportData, format, filepath);
        return { success: true, result: path };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });
  }

  // Add history item (called by proxy when capturing traffic)
  addHistoryItem(item) {
    this.db.addHistoryItem(item);
    this.mainWindow.webContents.send('proxy-history-update', item);
  }

  close() {
    if (this.spider) this.spider.stop();
    if (this.scanner) this.scanner.stop();
    if (this.intruder) this.intruder.stop();
    if (this.sessionHandler) this.sessionHandler.cleanup();
    if (this.extensionManager) this.extensionManager.cleanup();
    if (this.collaborator) this.collaborator.stop();
    if (this.restApiServer) this.restApiServer.stop();
    if (this.scheduler) this.scheduler.cleanup();
    this.db.close();
  }
}

module.exports = ProxyBackend;
