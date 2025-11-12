const EventEmitter = require('events');

/**
 * LuaScriptEngine - Execute Lua scripts on packet data
 *
 * Note: This implementation uses JavaScript to simulate Lua scripting.
 * For production, integrate fengari or lua.vm.js for actual Lua execution.
 */
class LuaScriptEngine extends EventEmitter {
  constructor() {
    super();
    this.scripts = new Map();
    this.scriptResults = new Map();

    // Built-in script templates
    this.templates = {
      'port-scanner-detector': {
        name: 'Port Scanner Detector',
        description: 'Detects potential port scanning activity',
        code: `
-- Port Scanner Detector
local port_counts = {}

function on_packet(packet)
  if packet.protocol == "TCP" then
    local src = packet.source

    if not port_counts[src] then
      port_counts[src] = {}
    end

    port_counts[src][packet.dstPort] = true

    local unique_ports = 0
    for _ in pairs(port_counts[src]) do
      unique_ports = unique_ports + 1
    end

    if unique_ports > 20 then
      alert("critical", "Port Scan Detected",
            src .. " has connected to " .. unique_ports .. " different ports")
      port_counts[src] = {} -- Reset to avoid spam
    end
  end
end
`
      },
      'http-extractor': {
        name: 'HTTP Data Extractor',
        description: 'Extracts HTTP requests and responses',
        code: `
-- HTTP Data Extractor
local http_requests = {}

function on_packet(packet)
  if packet.protocol == "HTTP" then
    if packet.info:match("GET") or packet.info:match("POST") then
      log("info", "HTTP Request: " .. packet.info)
      table.insert(http_requests, {
        time = packet.timestamp,
        src = packet.source,
        dst = packet.destination,
        info = packet.info
      })
    end
  end
end

function on_complete()
  log("info", "Total HTTP requests captured: " .. #http_requests)
  return http_requests
end
`
      },
      'bandwidth-monitor': {
        name: 'Bandwidth Monitor',
        description: 'Monitors bandwidth usage by host',
        code: `
-- Bandwidth Monitor
local bandwidth = {}

function on_packet(packet)
  local src = packet.source
  local dst = packet.destination

  if not bandwidth[src] then
    bandwidth[src] = { tx = 0, rx = 0 }
  end
  if not bandwidth[dst] then
    bandwidth[dst] = { tx = 0, rx = 0 }
  end

  bandwidth[src].tx = bandwidth[src].tx + packet.length
  bandwidth[dst].rx = bandwidth[dst].rx + packet.length
end

function on_complete()
  for host, stats in pairs(bandwidth) do
    log("info", string.format("%s - TX: %d bytes, RX: %d bytes",
        host, stats.tx, stats.rx))
  end
  return bandwidth
end
`
      },
      'dns-query-logger': {
        name: 'DNS Query Logger',
        description: 'Logs all DNS queries',
        code: `
-- DNS Query Logger
local dns_queries = {}

function on_packet(packet)
  if packet.protocol == "DNS" and packet.dstPort == 53 then
    log("info", "DNS Query from " .. packet.source)
    table.insert(dns_queries, {
      time = packet.timestamp,
      source = packet.source,
      info = packet.info
    })
  end
end

function on_complete()
  log("info", "Total DNS queries: " .. #dns_queries)
  return dns_queries
end
`
      },
      'tcp-connection-tracker': {
        name: 'TCP Connection Tracker',
        description: 'Tracks TCP connection states',
        code: `
-- TCP Connection Tracker
local connections = {}

function on_packet(packet)
  if packet.protocol == "TCP" then
    local key = packet.source .. ":" .. packet.srcPort .. " -> " ..
                packet.destination .. ":" .. packet.dstPort

    if packet.info:match("SYN") and not packet.info:match("ACK") then
      connections[key] = "SYN_SENT"
      log("info", "Connection initiated: " .. key)
    elseif packet.info:match("SYN") and packet.info:match("ACK") then
      connections[key] = "SYN_RECEIVED"
    elseif packet.info:match("FIN") then
      connections[key] = "CLOSING"
      log("info", "Connection closing: " .. key)
    elseif packet.info:match("RST") then
      connections[key] = "RESET"
      log("warn", "Connection reset: " .. key)
    end
  end
end

function on_complete()
  local active = 0
  for _, state in pairs(connections) do
    if state ~= "CLOSING" and state ~= "RESET" then
      active = active + 1
    end
  end
  log("info", "Active connections: " .. active)
  return connections
end
`
      }
    };
  }

  // Load a script
  loadScript(scriptId, scriptCode) {
    try {
      // Parse the Lua-like script into a JavaScript function
      // This is a simplified implementation - in production use actual Lua VM
      const jsCode = this.translateLuaToJS(scriptCode);

      this.scripts.set(scriptId, {
        code: scriptCode,
        jsCode: jsCode,
        state: {},
        results: []
      });

      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Translate Lua-like syntax to JavaScript (simplified)
  translateLuaToJS(luaCode) {
    // This is a basic translation - in production, use fengari or lua.vm.js
    let jsCode = luaCode;

    // Replace Lua syntax with JS equivalents
    jsCode = jsCode.replace(/function\s+(\w+)\s*\((.*?)\)/g, 'const $1 = ($2) => {');
    jsCode = jsCode.replace(/\bend\b/g, '}');
    jsCode = jsCode.replace(/local\s+/g, 'let ');
    jsCode = jsCode.replace(/\~=/g, '!==');
    jsCode = jsCode.replace(/\.\./g, '+');
    jsCode = jsCode.replace(/:/g, '.');
    jsCode = jsCode.replace(/then/g, '{');
    jsCode = jsCode.replace(/elseif/g, '} else if');
    jsCode = jsCode.replace(/\belse\b/g, '} else {');
    jsCode = jsCode.replace(/pairs\((.*?)\)/g, 'Object.entries($1)');
    jsCode = jsCode.replace(/#(\w+)/g, '$1.length');
    jsCode = jsCode.replace(/table\.insert\((.*?),\s*(.*?)\)/g, '$1.push($2)');
    jsCode = jsCode.replace(/string\.format/g, 'sprintf');

    return jsCode;
  }

  // Execute script on a packet
  executeOnPacket(scriptId, packet) {
    const script = this.scripts.get(scriptId);
    if (!script) {
      return { success: false, error: 'Script not found' };
    }

    try {
      // Create script execution context
      const context = {
        packet: packet,
        state: script.state,
        alert: (severity, message, details) => {
          this.emit('script-alert', {
            scriptId,
            severity,
            message,
            details,
            packet: packet.no
          });
        },
        log: (level, message) => {
          this.emit('script-log', {
            scriptId,
            level,
            message,
            packet: packet.no
          });
        }
      };

      // Execute the on_packet function
      this.executeScriptFunction(script, 'on_packet', [packet], context);

      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Execute a script function
  executeScriptFunction(script, functionName, args, context) {
    // In a real implementation, this would use a Lua VM
    // For now, we'll implement the built-in scripts in JavaScript

    const scriptCode = script.code;

    // Check which template is being used and execute accordingly
    if (scriptCode.includes('Port Scanner Detector')) {
      this.executePortScannerDetector(args[0], script.state, context);
    } else if (scriptCode.includes('HTTP Data Extractor')) {
      this.executeHTTPExtractor(args[0], script.state, context);
    } else if (scriptCode.includes('Bandwidth Monitor')) {
      this.executeBandwidthMonitor(args[0], script.state, context);
    } else if (scriptCode.includes('DNS Query Logger')) {
      this.executeDNSLogger(args[0], script.state, context);
    } else if (scriptCode.includes('TCP Connection Tracker')) {
      this.executeTCPTracker(args[0], script.state, context);
    }
  }

  // Built-in script implementations
  executePortScannerDetector(packet, state, context) {
    if (packet.protocol === 'TCP') {
      if (!state.port_counts) state.port_counts = {};

      const src = packet.source;
      if (!state.port_counts[src]) {
        state.port_counts[src] = new Set();
      }

      state.port_counts[src].add(packet.dstPort);

      if (state.port_counts[src].size > 20) {
        context.alert('critical', 'Port Scan Detected',
          `${src} has connected to ${state.port_counts[src].size} different ports`);
        state.port_counts[src] = new Set(); // Reset
      }
    }
  }

  executeHTTPExtractor(packet, state, context) {
    if (packet.protocol === 'HTTP' ||
        (packet.protocol === 'TCP' && (packet.dstPort === 80 || packet.srcPort === 80))) {
      if (packet.info.match(/GET|POST|PUT|DELETE/)) {
        if (!state.http_requests) state.http_requests = [];

        context.log('info', `HTTP Request: ${packet.info}`);
        state.http_requests.push({
          time: packet.timestamp,
          src: packet.source,
          dst: packet.destination,
          info: packet.info
        });
      }
    }
  }

  executeBandwidthMonitor(packet, state, context) {
    if (!state.bandwidth) state.bandwidth = {};

    const src = packet.source;
    const dst = packet.destination;

    if (!state.bandwidth[src]) {
      state.bandwidth[src] = { tx: 0, rx: 0 };
    }
    if (!state.bandwidth[dst]) {
      state.bandwidth[dst] = { tx: 0, rx: 0 };
    }

    state.bandwidth[src].tx += packet.length;
    state.bandwidth[dst].rx += packet.length;
  }

  executeDNSLogger(packet, state, context) {
    if (packet.protocol === 'DNS' ||
        (packet.protocol === 'UDP' && packet.dstPort === 53)) {
      if (!state.dns_queries) state.dns_queries = [];

      context.log('info', `DNS Query from ${packet.source}`);
      state.dns_queries.push({
        time: packet.timestamp,
        source: packet.source,
        info: packet.info
      });
    }
  }

  executeTCPTracker(packet, state, context) {
    if (packet.protocol === 'TCP') {
      if (!state.connections) state.connections = {};

      const key = `${packet.source}:${packet.srcPort} -> ${packet.destination}:${packet.dstPort}`;

      if (packet.info.match(/SYN/) && !packet.info.match(/ACK/)) {
        state.connections[key] = 'SYN_SENT';
        context.log('info', `Connection initiated: ${key}`);
      } else if (packet.info.match(/SYN/) && packet.info.match(/ACK/)) {
        state.connections[key] = 'SYN_RECEIVED';
      } else if (packet.info.match(/FIN/)) {
        state.connections[key] = 'CLOSING';
        context.log('info', `Connection closing: ${key}`);
      } else if (packet.info.match(/RST/)) {
        state.connections[key] = 'RESET';
        context.log('warn', `Connection reset: ${key}`);
      }
    }
  }

  // Complete script execution
  complete(scriptId) {
    const script = this.scripts.get(scriptId);
    if (!script) {
      return { success: false, error: 'Script not found' };
    }

    try {
      // Execute on_complete function if it exists
      const results = this.executeCompleteFunction(script);

      this.scriptResults.set(scriptId, results);

      return { success: true, results };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  executeCompleteFunction(script) {
    const state = script.state;
    const scriptCode = script.code;

    if (scriptCode.includes('Bandwidth Monitor') && state.bandwidth) {
      const results = [];
      for (const [host, stats] of Object.entries(state.bandwidth)) {
        results.push({
          host,
          tx: stats.tx,
          rx: stats.rx,
          total: stats.tx + stats.rx
        });
      }
      return results.sort((a, b) => b.total - a.total);
    } else if (scriptCode.includes('DNS Query Logger') && state.dns_queries) {
      return state.dns_queries;
    } else if (scriptCode.includes('HTTP Data Extractor') && state.http_requests) {
      return state.http_requests;
    } else if (scriptCode.includes('TCP Connection Tracker') && state.connections) {
      const results = [];
      let active = 0;
      for (const [conn, state_val] of Object.entries(state.connections)) {
        results.push({ connection: conn, state: state_val });
        if (state_val !== 'CLOSING' && state_val !== 'RESET') {
          active++;
        }
      }
      return { connections: results, active };
    }

    return {};
  }

  // Get script results
  getResults(scriptId) {
    return this.scriptResults.get(scriptId) || {};
  }

  // Unload a script
  unloadScript(scriptId) {
    this.scripts.delete(scriptId);
    this.scriptResults.delete(scriptId);
    return { success: true };
  }

  // Get all loaded scripts
  getLoadedScripts() {
    const scripts = [];
    for (const [id, script] of this.scripts.entries()) {
      scripts.push({
        id,
        hasResults: this.scriptResults.has(id)
      });
    }
    return scripts;
  }

  // Get available script templates
  getTemplates() {
    return Object.entries(this.templates).map(([id, template]) => ({
      id,
      name: template.name,
      description: template.description
    }));
  }

  // Get template code
  getTemplateCode(templateId) {
    const template = this.templates[templateId];
    return template ? template.code : null;
  }

  // Clear all scripts
  clearAll() {
    this.scripts.clear();
    this.scriptResults.clear();
    return { success: true };
  }
}

module.exports = LuaScriptEngine;
