const EventEmitter = require('events');
const axios = require('axios');
const https = require('https');

/**
 * Session Handler - Manages session handling rules, macros, and token extraction
 * Provides automated login, token refresh, and state management capabilities
 */
class SessionHandler extends EventEmitter {
  constructor(database) {
    super();
    this.db = database;
    this.sessions = new Map(); // Active sessions
    this.macros = new Map(); // Loaded macros
    this.rules = new Map(); // Session handling rules
    this.tokenCache = new Map(); // Cached tokens

    this.httpsAgent = new https.Agent({
      rejectUnauthorized: false
    });

    // Load saved rules and macros from database
    this.loadRules();
    this.loadMacros();
  }

  /**
   * Load session handling rules from database
   */
  loadRules() {
    const rules = this.db.getSessionRules();
    rules.forEach(rule => {
      this.rules.set(rule.id, rule);
    });
  }

  /**
   * Load macros from database
   */
  loadMacros() {
    const macros = this.db.getMacros();
    macros.forEach(macro => {
      this.macros.set(macro.id, macro);
    });
  }

  /**
   * Add a new session handling rule
   */
  addRule(rule) {
    const ruleData = {
      id: rule.id || this.generateId(),
      name: rule.name,
      enabled: rule.enabled !== false,
      scope: rule.scope || [],
      conditions: rule.conditions || [],
      actions: rule.actions || [],
      priority: rule.priority || 0,
      description: rule.description || '',
      createdAt: Date.now()
    };

    this.db.addSessionRule(ruleData);
    this.rules.set(ruleData.id, ruleData);
    this.emit('rule-added', ruleData);

    return ruleData;
  }

  /**
   * Update an existing session handling rule
   */
  updateRule(id, updates) {
    const rule = this.rules.get(id);
    if (!rule) {
      throw new Error(`Rule ${id} not found`);
    }

    const updatedRule = { ...rule, ...updates };
    this.db.updateSessionRule(id, updatedRule);
    this.rules.set(id, updatedRule);
    this.emit('rule-updated', updatedRule);

    return updatedRule;
  }

  /**
   * Delete a session handling rule
   */
  deleteRule(id) {
    this.db.deleteSessionRule(id);
    this.rules.delete(id);
    this.emit('rule-deleted', id);
  }

  /**
   * Get all session handling rules
   */
  getRules() {
    return Array.from(this.rules.values()).sort((a, b) => b.priority - a.priority);
  }

  /**
   * Create a new macro
   */
  createMacro(macro) {
    const macroData = {
      id: macro.id || this.generateId(),
      name: macro.name,
      description: macro.description || '',
      requests: macro.requests || [],
      variables: macro.variables || {},
      correlationRules: macro.correlationRules || [],
      createdAt: Date.now()
    };

    this.db.addMacro(macroData);
    this.macros.set(macroData.id, macroData);
    this.emit('macro-created', macroData);

    return macroData;
  }

  /**
   * Update an existing macro
   */
  updateMacro(id, updates) {
    const macro = this.macros.get(id);
    if (!macro) {
      throw new Error(`Macro ${id} not found`);
    }

    const updatedMacro = { ...macro, ...updates };
    this.db.updateMacro(id, updatedMacro);
    this.macros.set(id, updatedMacro);
    this.emit('macro-updated', updatedMacro);

    return updatedMacro;
  }

  /**
   * Delete a macro
   */
  deleteMacro(id) {
    this.db.deleteMacro(id);
    this.macros.delete(id);
    this.emit('macro-deleted', id);
  }

  /**
   * Get all macros
   */
  getMacros() {
    return Array.from(this.macros.values());
  }

  /**
   * Execute a macro - run sequence of requests with variable extraction
   */
  async executeMacro(macroId, initialVariables = {}) {
    const macro = this.macros.get(macroId);
    if (!macro) {
      throw new Error(`Macro ${macroId} not found`);
    }

    this.emit('macro-started', { macroId, name: macro.name });

    const results = [];
    const variables = { ...macro.variables, ...initialVariables };

    try {
      for (let i = 0; i < macro.requests.length; i++) {
        const requestTemplate = macro.requests[i];

        // Replace variables in request
        const request = this.replaceVariables(requestTemplate, variables);

        this.emit('macro-progress', {
          macroId,
          step: i + 1,
          total: macro.requests.length,
          request: request.name || `Request ${i + 1}`
        });

        // Execute request
        const response = await this.executeRequest(request);

        results.push({
          request,
          response,
          timestamp: Date.now()
        });

        // Extract variables using correlation rules
        if (macro.correlationRules && macro.correlationRules.length > 0) {
          for (const rule of macro.correlationRules) {
            if (rule.sourceRequest === i) {
              const extractedValue = this.extractValue(response, rule);
              if (extractedValue) {
                variables[rule.variableName] = extractedValue;
                this.emit('variable-extracted', {
                  macroId,
                  variableName: rule.variableName,
                  value: extractedValue
                });
              }
            }
          }
        }
      }

      this.emit('macro-completed', { macroId, results, variables });
      return { success: true, results, variables };
    } catch (error) {
      this.emit('macro-error', { macroId, error: error.message });
      throw error;
    }
  }

  /**
   * Replace variables in request template
   */
  replaceVariables(template, variables) {
    const replaced = JSON.parse(JSON.stringify(template));

    const replace = (str) => {
      if (typeof str !== 'string') return str;
      return str.replace(/\{\{(\w+)\}\}/g, (match, varName) => {
        return variables[varName] !== undefined ? variables[varName] : match;
      });
    };

    replaced.url = replace(replaced.url);
    replaced.bodyString = replace(replaced.bodyString);

    if (replaced.headers) {
      Object.keys(replaced.headers).forEach(key => {
        replaced.headers[key] = replace(replaced.headers[key]);
      });
    }

    return replaced;
  }

  /**
   * Execute a single HTTP request
   */
  async executeRequest(request) {
    const startTime = Date.now();

    try {
      const config = {
        method: request.method.toLowerCase(),
        url: request.url,
        headers: request.headers || {},
        data: request.bodyString || undefined,
        maxRedirects: 5,
        validateStatus: () => true,
        httpsAgent: this.httpsAgent,
        timeout: 30000
      };

      const response = await axios(config);
      const duration = Date.now() - startTime;

      return {
        statusCode: response.status,
        statusMessage: response.statusText,
        headers: response.headers,
        bodyString: typeof response.data === 'string' ? response.data : JSON.stringify(response.data),
        time: duration,
        length: response.headers['content-length'] || 0
      };
    } catch (error) {
      throw new Error(`Request failed: ${error.message}`);
    }
  }

  /**
   * Extract value from response using correlation rule
   */
  extractValue(response, rule) {
    const source = rule.extractFrom === 'header'
      ? JSON.stringify(response.headers)
      : response.bodyString;

    if (rule.extractionType === 'regex') {
      const regex = new RegExp(rule.pattern);
      const match = source.match(regex);
      return match ? (match[1] || match[0]) : null;
    } else if (rule.extractionType === 'json') {
      try {
        const json = JSON.parse(response.bodyString);
        return this.getNestedProperty(json, rule.jsonPath);
      } catch (e) {
        return null;
      }
    } else if (rule.extractionType === 'xpath') {
      // Simple XPath-like extraction for common cases
      const match = source.match(new RegExp(`<${rule.xpath}>(.*?)<\/${rule.xpath}>`));
      return match ? match[1] : null;
    }

    return null;
  }

  /**
   * Get nested property from object using dot notation
   */
  getNestedProperty(obj, path) {
    return path.split('.').reduce((current, prop) => current?.[prop], obj);
  }

  /**
   * Process request through session handling rules
   */
  async processRequest(request) {
    const applicableRules = this.getApplicableRules(request);

    for (const rule of applicableRules) {
      if (!rule.enabled) continue;

      // Check conditions
      const conditionsMet = this.checkConditions(request, rule.conditions);

      if (conditionsMet) {
        // Execute actions
        request = await this.executeActions(request, rule.actions);
      }
    }

    return request;
  }

  /**
   * Get rules applicable to a request
   */
  getApplicableRules(request) {
    return this.getRules().filter(rule => {
      if (!rule.scope || rule.scope.length === 0) return true;

      return rule.scope.some(scopePattern => {
        const regex = new RegExp(scopePattern.replace(/\*/g, '.*'));
        return regex.test(request.url);
      });
    });
  }

  /**
   * Check if conditions are met
   */
  checkConditions(request, conditions) {
    if (!conditions || conditions.length === 0) return true;

    return conditions.every(condition => {
      switch (condition.type) {
        case 'url-matches':
          return new RegExp(condition.pattern).test(request.url);
        case 'header-exists':
          return request.headers && request.headers[condition.headerName];
        case 'header-missing':
          return !request.headers || !request.headers[condition.headerName];
        case 'cookie-exists':
          const cookieHeader = request.headers?.['Cookie'] || request.headers?.['cookie'] || '';
          return cookieHeader.includes(condition.cookieName);
        default:
          return false;
      }
    });
  }

  /**
   * Execute actions on request
   */
  async executeActions(request, actions) {
    let modifiedRequest = { ...request };

    for (const action of actions) {
      switch (action.type) {
        case 'add-header':
          modifiedRequest.headers = modifiedRequest.headers || {};
          modifiedRequest.headers[action.headerName] = action.headerValue;
          break;

        case 'replace-header':
          if (modifiedRequest.headers) {
            modifiedRequest.headers[action.headerName] = action.headerValue;
          }
          break;

        case 'add-cookie':
          modifiedRequest.headers = modifiedRequest.headers || {};
          const existingCookies = modifiedRequest.headers['Cookie'] || modifiedRequest.headers['cookie'] || '';
          const newCookie = `${action.cookieName}=${action.cookieValue}`;
          modifiedRequest.headers['Cookie'] = existingCookies
            ? `${existingCookies}; ${newCookie}`
            : newCookie;
          break;

        case 'run-macro':
          const macroResult = await this.executeMacro(action.macroId);
          // Store extracted variables for use in subsequent requests
          if (macroResult.variables) {
            Object.assign(this.tokenCache, macroResult.variables);
          }
          break;

        case 'use-cached-token':
          const cachedToken = this.tokenCache.get(action.tokenName);
          if (cachedToken) {
            if (action.location === 'header') {
              modifiedRequest.headers = modifiedRequest.headers || {};
              modifiedRequest.headers[action.headerName] = cachedToken;
            } else if (action.location === 'cookie') {
              modifiedRequest.headers = modifiedRequest.headers || {};
              const cookies = modifiedRequest.headers['Cookie'] || '';
              modifiedRequest.headers['Cookie'] = cookies
                ? `${cookies}; ${action.cookieName}=${cachedToken}`
                : `${action.cookieName}=${cachedToken}`;
            }
          }
          break;
      }
    }

    return modifiedRequest;
  }

  /**
   * Store a token in cache
   */
  cacheToken(name, value, expiresIn = null) {
    const token = {
      value,
      cachedAt: Date.now(),
      expiresAt: expiresIn ? Date.now() + expiresIn : null
    };

    this.tokenCache.set(name, token);
    this.emit('token-cached', { name, value });

    // Auto-cleanup expired tokens
    if (expiresIn) {
      setTimeout(() => {
        if (this.tokenCache.get(name) === token) {
          this.tokenCache.delete(name);
          this.emit('token-expired', { name });
        }
      }, expiresIn);
    }
  }

  /**
   * Get a cached token
   */
  getCachedToken(name) {
    const token = this.tokenCache.get(name);
    if (!token) return null;

    // Check if expired
    if (token.expiresAt && Date.now() > token.expiresAt) {
      this.tokenCache.delete(name);
      this.emit('token-expired', { name });
      return null;
    }

    return token.value;
  }

  /**
   * Clear cached tokens
   */
  clearTokenCache() {
    this.tokenCache.clear();
    this.emit('token-cache-cleared');
  }

  /**
   * Generate unique ID
   */
  generateId() {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Clean up resources
   */
  cleanup() {
    this.sessions.clear();
    this.tokenCache.clear();
    this.removeAllListeners();
  }
}

module.exports = SessionHandler;
