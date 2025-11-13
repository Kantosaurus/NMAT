const express = require('express');
const bodyParser = require('body-parser');
const EventEmitter = require('events');

/**
 * REST API Server for NMAT Automation
 * Provides programmatic access to all NMAT features for CI/CD integration
 */
class RestApiServer extends EventEmitter {
  constructor(proxyBackend) {
    super();
    this.proxyBackend = proxyBackend;
    this.app = express();
    this.server = null;
    this.port = 0;
    this.apiKeys = new Map(); // API key authentication

    this.setupMiddleware();
    this.setupRoutes();
  }

  /**
   * Setup Express middleware
   */
  setupMiddleware() {
    this.app.use(bodyParser.json({ limit: '10mb' }));
    this.app.use(bodyParser.urlencoded({ extended: true }));

    // CORS headers
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, X-API-Key');

      if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
      }
      next();
    });

    // API Key authentication middleware
    this.app.use((req, res, next) => {
      // Skip auth for health check
      if (req.path === '/api/health') {
        return next();
      }

      const apiKey = req.headers['x-api-key'];
      if (!apiKey || !this.apiKeys.has(apiKey)) {
        return res.status(401).json({
          success: false,
          error: 'Unauthorized: Invalid or missing API key'
        });
      }

      req.apiKeyData = this.apiKeys.get(apiKey);
      next();
    });

    // Error handling
    this.app.use((err, req, res, next) => {
      console.error('API Error:', err);
      res.status(500).json({
        success: false,
        error: err.message
      });
    });
  }

  /**
   * Setup API routes
   */
  setupRoutes() {
    // Health check
    this.app.get('/api/health', (req, res) => {
      res.json({
        success: true,
        status: 'running',
        version: '1.0.0',
        timestamp: Date.now()
      });
    });

    // Scanner routes
    this.app.post('/api/scan/start', async (req, res) => {
      try {
        const { config, urls, policy } = req.body;
        await this.proxyBackend.scanner?.scan(urls, policy);
        res.json({ success: true, message: 'Scan started' });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/scan/stop', async (req, res) => {
      try {
        this.proxyBackend.scanner?.stop();
        res.json({ success: true, message: 'Scan stopped' });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/scan/vulnerabilities', async (req, res) => {
      try {
        const filters = req.query;
        const vulnerabilities = this.proxyBackend.db.getVulnerabilities(filters);
        res.json({ success: true, result: vulnerabilities });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/scan/status', async (req, res) => {
      try {
        const status = {
          running: !!this.proxyBackend.scanner,
          progress: this.proxyBackend.scanner?.progress || null
        };
        res.json({ success: true, result: status });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Spider routes
    this.app.post('/api/spider/start', async (req, res) => {
      try {
        const { config, startUrls } = req.body;
        await this.proxyBackend.spider?.start(startUrls);
        res.json({ success: true, message: 'Spider started' });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/spider/endpoints', async (req, res) => {
      try {
        const endpoints = this.proxyBackend.db.getEndpoints();
        res.json({ success: true, result: endpoints });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Intruder routes
    this.app.post('/api/intruder/attack', async (req, res) => {
      try {
        const attack = req.body;
        await this.proxyBackend.intruder?.startAttack(attack);
        res.json({ success: true, message: 'Intruder attack started' });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/intruder/results/:attackId', async (req, res) => {
      try {
        const results = this.proxyBackend.db.getIntruderResults(req.params.attackId);
        res.json({ success: true, result: results });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Proxy history routes
    this.app.get('/api/proxy/history', async (req, res) => {
      try {
        const filters = req.query;
        const history = this.proxyBackend.db.getHistory(filters);
        res.json({ success: true, result: history });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Repeater route
    this.app.post('/api/repeater/send', async (req, res) => {
      try {
        const requestData = req.body;
        const response = await this.proxyBackend.repeater.sendRequest(requestData);
        res.json({ success: true, result: response });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Macro routes
    this.app.get('/api/macros', async (req, res) => {
      try {
        const macros = this.proxyBackend.sessionHandler.getMacros();
        res.json({ success: true, result: macros });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/macros/:macroId/execute', async (req, res) => {
      try {
        const { macroId } = req.params;
        const variables = req.body.variables || {};
        const result = await this.proxyBackend.sessionHandler.executeMacro(macroId, variables);
        res.json({ success: true, result });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Report generation routes
    this.app.post('/api/reports/generate', async (req, res) => {
      try {
        const { format, filters } = req.body;
        const items = this.proxyBackend.db.getHistory(filters || {});

        let content;
        switch (format) {
          case 'json':
            content = this.proxyBackend.loggerExporter.exportToJSON(items);
            break;
          case 'csv':
            content = this.proxyBackend.loggerExporter.exportToCSV(items);
            break;
          case 'xml':
            content = this.proxyBackend.loggerExporter.exportToXML(items);
            break;
          case 'har':
            content = this.proxyBackend.loggerExporter.exportToHAR(items);
            break;
          default:
            throw new Error('Unsupported format');
        }

        res.set('Content-Type', `application/${format}`);
        res.send(content);
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/reports/vulnerabilities', async (req, res) => {
      try {
        const filters = req.query;
        const vulnerabilities = this.proxyBackend.db.getVulnerabilities(filters);

        const report = {
          generatedAt: new Date().toISOString(),
          totalVulnerabilities: vulnerabilities.length,
          bySeverity: this.groupBySeverity(vulnerabilities),
          byType: this.groupByType(vulnerabilities),
          vulnerabilities
        };

        res.json({ success: true, result: report });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Project/Configuration routes
    this.app.post('/api/project/save', async (req, res) => {
      try {
        const { name, config } = req.body;
        this.proxyBackend.db.setSetting(`project_${name}`, JSON.stringify(config));
        res.json({ success: true, message: 'Project saved' });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/project/load/:name', async (req, res) => {
      try {
        const config = this.proxyBackend.db.getSetting(`project_${req.params.name}`);
        if (!config) {
          return res.status(404).json({ success: false, error: 'Project not found' });
        }
        res.json({ success: true, result: JSON.parse(config) });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Collaborator routes
    this.app.post('/api/collaborator/start', async (req, res) => {
      try {
        const config = req.body;
        const result = await this.proxyBackend.collaborator.start(config);
        res.json({ success: true, result });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/collaborator/interactions', async (req, res) => {
      try {
        const filters = req.query;
        const interactions = this.proxyBackend.collaborator.getInteractions(filters);
        res.json({ success: true, result: interactions });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/collaborator/payloads/generate', async (req, res) => {
      try {
        const { vulnerabilityType, targetUrl, parameter } = req.body;
        const result = this.proxyBackend.collaborator.generatePayloadsForVulnerability(
          vulnerabilityType,
          targetUrl,
          parameter
        );
        res.json({ success: true, result });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Extension routes
    this.app.get('/api/extensions', async (req, res) => {
      try {
        const extensions = this.proxyBackend.extensionManager.getExtensions();
        res.json({ success: true, result: extensions });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/extensions/:extensionId/toggle', async (req, res) => {
      try {
        const { extensionId } = req.params;
        const { enabled } = req.body;
        this.proxyBackend.extensionManager.toggleExtension(extensionId, enabled);
        res.json({ success: true, message: 'Extension toggled' });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });
  }

  /**
   * Start the REST API server
   */
  async start(port = 0) {
    return new Promise((resolve, reject) => {
      this.server = this.app.listen(port, () => {
        this.port = this.server.address().port;
        console.log(`REST API server started on port ${this.port}`);
        this.emit('started', { port: this.port });
        resolve({ port: this.port });
      });

      this.server.on('error', reject);
    });
  }

  /**
   * Stop the REST API server
   */
  async stop() {
    if (this.server) {
      return new Promise((resolve) => {
        this.server.close(() => {
          this.server = null;
          console.log('REST API server stopped');
          this.emit('stopped');
          resolve();
        });
      });
    }
  }

  /**
   * Generate an API key
   */
  generateApiKey(name = 'default') {
    const crypto = require('crypto');
    const apiKey = crypto.randomBytes(32).toString('hex');

    this.apiKeys.set(apiKey, {
      name,
      createdAt: Date.now(),
      lastUsed: null
    });

    return apiKey;
  }

  /**
   * Revoke an API key
   */
  revokeApiKey(apiKey) {
    return this.apiKeys.delete(apiKey);
  }

  /**
   * List all API keys
   */
  listApiKeys() {
    return Array.from(this.apiKeys.entries()).map(([key, data]) => ({
      key: key.substring(0, 8) + '...',
      fullKey: key,
      name: data.name,
      createdAt: data.createdAt,
      lastUsed: data.lastUsed
    }));
  }

  /**
   * Helper: Group vulnerabilities by severity
   */
  groupBySeverity(vulnerabilities) {
    const groups = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    vulnerabilities.forEach(vuln => {
      groups[vuln.severity] = (groups[vuln.severity] || 0) + 1;
    });
    return groups;
  }

  /**
   * Helper: Group vulnerabilities by type
   */
  groupByType(vulnerabilities) {
    const groups = {};
    vulnerabilities.forEach(vuln => {
      groups[vuln.vulnerabilityType] = (groups[vuln.vulnerabilityType] || 0) + 1;
    });
    return groups;
  }

  /**
   * Get server status
   */
  getStatus() {
    return {
      running: !!this.server,
      port: this.port,
      apiKeyCount: this.apiKeys.size
    };
  }
}

module.exports = RestApiServer;
