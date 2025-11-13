const Database = require('better-sqlite3');
const path = require('path');
const { app } = require('electron');

class ProxyDatabase {
  constructor() {
    const userDataPath = app.getPath('userData');
    const dbPath = path.join(userDataPath, 'nmat-proxy.db');
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.initializeTables();
  }

  initializeTables() {
    // Proxy history table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS proxy_history (
        id TEXT PRIMARY KEY,
        timestamp INTEGER NOT NULL,
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        request_headers TEXT,
        request_body TEXT,
        response_status INTEGER,
        response_status_message TEXT,
        response_headers TEXT,
        response_body TEXT,
        response_time INTEGER,
        response_length INTEGER,
        source TEXT DEFAULT 'proxy'
      );

      CREATE INDEX IF NOT EXISTS idx_history_timestamp ON proxy_history(timestamp);
      CREATE INDEX IF NOT EXISTS idx_history_url ON proxy_history(url);
      CREATE INDEX IF NOT EXISTS idx_history_method ON proxy_history(method);
    `);

    // Intercept queue table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS intercept_queue (
        id TEXT PRIMARY KEY,
        timestamp INTEGER NOT NULL,
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        headers TEXT,
        body TEXT,
        status TEXT DEFAULT 'pending'
      );
    `);

    // Site map / discovered endpoints
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS discovered_endpoints (
        id TEXT PRIMARY KEY,
        url TEXT UNIQUE NOT NULL,
        host TEXT,
        path TEXT,
        method TEXT,
        discovered_at INTEGER,
        status_code INTEGER,
        content_type TEXT,
        parameters TEXT,
        forms TEXT,
        links TEXT,
        response_time INTEGER,
        response_size INTEGER
      );

      CREATE INDEX IF NOT EXISTS idx_endpoints_host ON discovered_endpoints(host);
      CREATE INDEX IF NOT EXISTS idx_endpoints_url ON discovered_endpoints(url);
    `);

    // Crawl queue
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS crawl_queue (
        id TEXT PRIMARY KEY,
        url TEXT NOT NULL,
        depth INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending',
        parent_url TEXT,
        created_at INTEGER
      );

      CREATE INDEX IF NOT EXISTS idx_crawl_status ON crawl_queue(status);
    `);

    // Vulnerability issues
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vulnerability_issues (
        id TEXT PRIMARY KEY,
        url TEXT NOT NULL,
        vulnerability_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        cvss_score REAL,
        cwe_id TEXT,
        owasp_category TEXT,
        description TEXT,
        proof_of_concept TEXT,
        remediation TEXT,
        discovered_at INTEGER,
        scan_type TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerability_issues(severity);
      CREATE INDEX IF NOT EXISTS idx_vuln_type ON vulnerability_issues(vulnerability_type);
    `);

    // Intruder results
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS intruder_results (
        id TEXT PRIMARY KEY,
        attack_id TEXT NOT NULL,
        request_number INTEGER,
        payload TEXT,
        status_code INTEGER,
        response_length INTEGER,
        response_time INTEGER,
        matched_rules TEXT,
        extracted_data TEXT,
        request TEXT,
        response TEXT,
        error TEXT,
        created_at INTEGER
      );

      CREATE INDEX IF NOT EXISTS idx_intruder_attack ON intruder_results(attack_id);
    `);

    // Settings
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      );
    `);

    // Scope rules
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scope_rules (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        protocol TEXT,
        host TEXT,
        port TEXT,
        path TEXT,
        enabled INTEGER DEFAULT 1
      );
    `);

    // Match & Replace rules
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS match_replace_rules (
        id TEXT PRIMARY KEY,
        name TEXT,
        type TEXT NOT NULL,
        match_type TEXT NOT NULL,
        match_pattern TEXT,
        replace_with TEXT,
        enabled INTEGER DEFAULT 1
      );
    `);

    // Form configs for spider
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS form_configs (
        id TEXT PRIMARY KEY,
        url_pattern TEXT,
        field_name TEXT,
        field_value TEXT,
        enabled INTEGER DEFAULT 1
      );
    `);

    // Scan policies
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scan_policies (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        description TEXT,
        is_default INTEGER DEFAULT 0,
        vulnerability_checks TEXT,
        scan_speed TEXT,
        max_requests_per_second INTEGER,
        follow_redirects INTEGER DEFAULT 1,
        detect_custom_errors INTEGER DEFAULT 1,
        custom_error_patterns TEXT
      );
    `);

    // Session handling rules
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS session_rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        scope TEXT,
        conditions TEXT,
        actions TEXT,
        priority INTEGER DEFAULT 0,
        description TEXT,
        created_at INTEGER
      );

      CREATE INDEX IF NOT EXISTS idx_session_rules_priority ON session_rules(priority DESC);
    `);

    // Macros
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS macros (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        requests TEXT,
        variables TEXT,
        correlation_rules TEXT,
        created_at INTEGER
      );
    `);

    console.log('Database tables initialized successfully');
  }

  // Proxy History Methods
  addHistoryItem(item) {
    const stmt = this.db.prepare(`
      INSERT INTO proxy_history (
        id, timestamp, method, url, request_headers, request_body,
        response_status, response_status_message, response_headers,
        response_body, response_time, response_length, source
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    return stmt.run(
      item.id,
      item.timestamp,
      item.method,
      item.url,
      JSON.stringify(item.headers || {}),
      item.bodyString || '',
      item.response?.statusCode || null,
      item.response?.statusMessage || null,
      JSON.stringify(item.response?.headers || {}),
      item.response?.bodyString || '',
      item.response?.time || null,
      item.response?.length || null,
      item.source || 'proxy'
    );
  }

  getHistory(filters = {}) {
    let query = 'SELECT * FROM proxy_history WHERE 1=1';
    const params = [];

    if (filters.method) {
      query += ' AND method = ?';
      params.push(filters.method);
    }

    if (filters.urlPattern) {
      query += ' AND url LIKE ?';
      params.push(`%${filters.urlPattern}%`);
    }

    if (filters.statusCode) {
      query += ' AND response_status = ?';
      params.push(filters.statusCode);
    }

    query += ' ORDER BY timestamp DESC';

    if (filters.limit) {
      query += ' LIMIT ?';
      params.push(filters.limit);
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params);

    return rows.map(row => ({
      id: row.id,
      timestamp: row.timestamp,
      method: row.method,
      url: row.url,
      headers: JSON.parse(row.request_headers || '{}'),
      bodyString: row.request_body,
      response: row.response_status ? {
        statusCode: row.response_status,
        statusMessage: row.response_status_message,
        headers: JSON.parse(row.response_headers || '{}'),
        bodyString: row.response_body,
        time: row.response_time,
        length: row.response_length
      } : null,
      source: row.source
    }));
  }

  clearHistory() {
    return this.db.prepare('DELETE FROM proxy_history').run();
  }

  // Discovered Endpoints Methods
  addEndpoint(endpoint) {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO discovered_endpoints (
        id, url, host, path, method, discovered_at, status_code,
        content_type, parameters, forms, links, response_time, response_size
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    return stmt.run(
      endpoint.id,
      endpoint.url,
      endpoint.host,
      endpoint.path,
      endpoint.method,
      endpoint.discovered_at || Date.now(),
      endpoint.statusCode,
      endpoint.contentType,
      JSON.stringify(endpoint.parameters || []),
      JSON.stringify(endpoint.forms || []),
      JSON.stringify(endpoint.links || []),
      endpoint.responseTime,
      endpoint.responseSize
    );
  }

  getEndpoints() {
    const rows = this.db.prepare('SELECT * FROM discovered_endpoints ORDER BY discovered_at DESC').all();
    return rows.map(row => ({
      id: row.id,
      url: row.url,
      host: row.host,
      path: row.path,
      method: row.method,
      discovered_at: row.discovered_at,
      statusCode: row.status_code,
      contentType: row.content_type,
      parameters: JSON.parse(row.parameters || '[]'),
      forms: JSON.parse(row.forms || '[]'),
      links: JSON.parse(row.links || '[]'),
      responseTime: row.response_time,
      responseSize: row.response_size
    }));
  }

  // Vulnerability Issues Methods
  addVulnerability(vuln) {
    const stmt = this.db.prepare(`
      INSERT INTO vulnerability_issues (
        id, url, vulnerability_type, severity, confidence, cvss_score,
        cwe_id, owasp_category, description, proof_of_concept,
        remediation, discovered_at, scan_type
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    return stmt.run(
      vuln.id,
      vuln.url,
      vuln.vulnerabilityType,
      vuln.severity,
      vuln.confidence,
      vuln.cvssScore || null,
      vuln.cweId || null,
      vuln.owaspCategory || null,
      vuln.description,
      JSON.stringify(vuln.proofOfConcept || {}),
      vuln.remediation || '',
      vuln.discoveredAt || Date.now(),
      vuln.scanType
    );
  }

  getVulnerabilities(filters = {}) {
    let query = 'SELECT * FROM vulnerability_issues WHERE 1=1';
    const params = [];

    if (filters.severity && filters.severity.length > 0) {
      query += ` AND severity IN (${filters.severity.map(() => '?').join(',')})`;
      params.push(...filters.severity);
    }

    if (filters.type && filters.type.length > 0) {
      query += ` AND vulnerability_type IN (${filters.type.map(() => '?').join(',')})`;
      params.push(...filters.type);
    }

    query += ' ORDER BY discovered_at DESC';

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params);

    return rows.map(row => ({
      id: row.id,
      url: row.url,
      vulnerabilityType: row.vulnerability_type,
      severity: row.severity,
      confidence: row.confidence,
      cvssScore: row.cvss_score,
      cweId: row.cwe_id,
      owaspCategory: row.owasp_category,
      description: row.description,
      proofOfConcept: JSON.parse(row.proof_of_concept || '{}'),
      remediation: row.remediation,
      discoveredAt: row.discovered_at,
      scanType: row.scan_type
    }));
  }

  // Intruder Results Methods
  addIntruderResult(result) {
    const stmt = this.db.prepare(`
      INSERT INTO intruder_results (
        id, attack_id, request_number, payload, status_code,
        response_length, response_time, matched_rules, extracted_data,
        request, response, error, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    return stmt.run(
      result.id,
      result.attackId,
      result.requestNumber,
      JSON.stringify(result.payload),
      result.statusCode,
      result.length,
      result.time,
      JSON.stringify(result.matches || {}),
      JSON.stringify(result.extractions || {}),
      result.request,
      result.response || '',
      result.error || null,
      Date.now()
    );
  }

  getIntruderResults(attackId) {
    const stmt = this.db.prepare('SELECT * FROM intruder_results WHERE attack_id = ? ORDER BY request_number');
    const rows = stmt.all(attackId);

    return rows.map(row => ({
      id: row.id,
      attackId: row.attack_id,
      requestNumber: row.request_number,
      payload: JSON.parse(row.payload),
      statusCode: row.status_code,
      length: row.response_length,
      time: row.response_time,
      matches: JSON.parse(row.matched_rules || '{}'),
      extractions: JSON.parse(row.extracted_data || '{}'),
      request: row.request,
      response: row.response,
      error: row.error
    }));
  }

  // Settings Methods
  getSetting(key) {
    const row = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
    return row ? JSON.parse(row.value) : null;
  }

  setSetting(key, value) {
    const stmt = this.db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
    return stmt.run(key, JSON.stringify(value));
  }

  // Scope Rules Methods
  addScopeRule(rule) {
    const stmt = this.db.prepare(`
      INSERT INTO scope_rules (id, type, protocol, host, port, path, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    return stmt.run(
      rule.id,
      rule.type,
      rule.protocol || '',
      rule.host || '',
      rule.port || '',
      rule.path || '',
      rule.enabled ? 1 : 0
    );
  }

  getScopeRules() {
    const rows = this.db.prepare('SELECT * FROM scope_rules').all();
    return rows.map(row => ({
      id: row.id,
      type: row.type,
      protocol: row.protocol,
      host: row.host,
      port: row.port,
      path: row.path,
      enabled: Boolean(row.enabled)
    }));
  }

  deleteScopeRule(id) {
    return this.db.prepare('DELETE FROM scope_rules WHERE id = ?').run(id);
  }

  // Match & Replace Rules Methods
  addMatchReplaceRule(rule) {
    const stmt = this.db.prepare(`
      INSERT INTO match_replace_rules (id, name, type, match_type, match_pattern, replace_with, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    return stmt.run(
      rule.id,
      rule.name,
      rule.type,
      rule.matchType,
      rule.matchPattern,
      rule.replaceWith,
      rule.enabled ? 1 : 0
    );
  }

  getMatchReplaceRules() {
    const rows = this.db.prepare('SELECT * FROM match_replace_rules').all();
    return rows.map(row => ({
      id: row.id,
      name: row.name,
      type: row.type,
      matchType: row.match_type,
      matchPattern: row.match_pattern,
      replaceWith: row.replace_with,
      enabled: Boolean(row.enabled)
    }));
  }

  deleteMatchReplaceRule(id) {
    return this.db.prepare('DELETE FROM match_replace_rules WHERE id = ?').run(id);
  }

  // Session Handling Rules Methods
  addSessionRule(rule) {
    const stmt = this.db.prepare(`
      INSERT INTO session_rules (
        id, name, enabled, scope, conditions, actions, priority, description, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    return stmt.run(
      rule.id,
      rule.name,
      rule.enabled ? 1 : 0,
      JSON.stringify(rule.scope || []),
      JSON.stringify(rule.conditions || []),
      JSON.stringify(rule.actions || []),
      rule.priority || 0,
      rule.description || '',
      rule.createdAt || Date.now()
    );
  }

  getSessionRules() {
    const rows = this.db.prepare('SELECT * FROM session_rules ORDER BY priority DESC').all();
    return rows.map(row => ({
      id: row.id,
      name: row.name,
      enabled: Boolean(row.enabled),
      scope: JSON.parse(row.scope || '[]'),
      conditions: JSON.parse(row.conditions || '[]'),
      actions: JSON.parse(row.actions || '[]'),
      priority: row.priority,
      description: row.description,
      createdAt: row.created_at
    }));
  }

  updateSessionRule(id, rule) {
    const stmt = this.db.prepare(`
      UPDATE session_rules
      SET name = ?, enabled = ?, scope = ?, conditions = ?, actions = ?,
          priority = ?, description = ?
      WHERE id = ?
    `);

    return stmt.run(
      rule.name,
      rule.enabled ? 1 : 0,
      JSON.stringify(rule.scope || []),
      JSON.stringify(rule.conditions || []),
      JSON.stringify(rule.actions || []),
      rule.priority || 0,
      rule.description || '',
      id
    );
  }

  deleteSessionRule(id) {
    return this.db.prepare('DELETE FROM session_rules WHERE id = ?').run(id);
  }

  // Macros Methods
  addMacro(macro) {
    const stmt = this.db.prepare(`
      INSERT INTO macros (
        id, name, description, requests, variables, correlation_rules, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    return stmt.run(
      macro.id,
      macro.name,
      macro.description || '',
      JSON.stringify(macro.requests || []),
      JSON.stringify(macro.variables || {}),
      JSON.stringify(macro.correlationRules || []),
      macro.createdAt || Date.now()
    );
  }

  getMacros() {
    const rows = this.db.prepare('SELECT * FROM macros').all();
    return rows.map(row => ({
      id: row.id,
      name: row.name,
      description: row.description,
      requests: JSON.parse(row.requests || '[]'),
      variables: JSON.parse(row.variables || '{}'),
      correlationRules: JSON.parse(row.correlation_rules || '[]'),
      createdAt: row.created_at
    }));
  }

  updateMacro(id, macro) {
    const stmt = this.db.prepare(`
      UPDATE macros
      SET name = ?, description = ?, requests = ?, variables = ?, correlation_rules = ?
      WHERE id = ?
    `);

    return stmt.run(
      macro.name,
      macro.description || '',
      JSON.stringify(macro.requests || []),
      JSON.stringify(macro.variables || {}),
      JSON.stringify(macro.correlationRules || []),
      id
    );
  }

  deleteMacro(id) {
    return this.db.prepare('DELETE FROM macros WHERE id = ?').run(id);
  }

  close() {
    this.db.close();
  }
}

module.exports = ProxyDatabase;
