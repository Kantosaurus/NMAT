#!/usr/bin/env node

const { Command } = require('commander');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

/**
 * NMAT CLI - Command-line interface for headless scanning
 * Allows integration with CI/CD pipelines and automation workflows
 */
class NMATCli {
  constructor() {
    this.program = new Command();
    this.apiUrl = null;
    this.apiKey = null;
    this.configFile = path.join(process.env.HOME || process.env.USERPROFILE, '.nmat', 'config.json');

    this.loadConfig();
    this.setupCommands();
  }

  /**
   * Load configuration from file
   */
  loadConfig() {
    try {
      if (fs.existsSync(this.configFile)) {
        const config = JSON.parse(fs.readFileSync(this.configFile, 'utf-8'));
        this.apiUrl = config.apiUrl;
        this.apiKey = config.apiKey;
      }
    } catch (error) {
      // Config file doesn't exist yet
    }
  }

  /**
   * Save configuration to file
   */
  saveConfig() {
    const configDir = path.dirname(this.configFile);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    fs.writeFileSync(this.configFile, JSON.stringify({
      apiUrl: this.apiUrl,
      apiKey: this.apiKey
    }, null, 2));

    console.log(`Configuration saved to ${this.configFile}`);
  }

  /**
   * Make API request
   */
  async apiRequest(method, endpoint, data = null) {
    if (!this.apiUrl || !this.apiKey) {
      console.error('Error: API not configured. Run "nmat configure" first.');
      process.exit(1);
    }

    try {
      const response = await axios({
        method,
        url: `${this.apiUrl}${endpoint}`,
        headers: {
          'X-API-Key': this.apiKey,
          'Content-Type': 'application/json'
        },
        data
      });

      return response.data;
    } catch (error) {
      if (error.response) {
        console.error(`API Error: ${error.response.data.error || error.response.statusText}`);
      } else {
        console.error(`Error: ${error.message}`);
      }
      process.exit(1);
    }
  }

  /**
   * Setup CLI commands
   */
  setupCommands() {
    this.program
      .name('nmat')
      .description('NMAT CLI - Network Monitor Analysis Tool Command Line Interface')
      .version('1.0.0');

    // Configure command
    this.program
      .command('configure')
      .description('Configure NMAT CLI with API URL and key')
      .option('-u, --url <url>', 'API URL (e.g., http://localhost:8080)')
      .option('-k, --key <key>', 'API key')
      .action((options) => {
        if (options.url) this.apiUrl = options.url;
        if (options.key) this.apiKey = options.key;

        if (!this.apiUrl) {
          const readline = require('readline');
          const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
          });

          rl.question('API URL: ', (url) => {
            this.apiUrl = url;
            rl.question('API Key: ', (key) => {
              this.apiKey = key;
              this.saveConfig();
              rl.close();
            });
          });
        } else {
          this.saveConfig();
        }
      });

    // Scan commands
    const scan = this.program.command('scan').description('Scanning operations');

    scan
      .command('start')
      .description('Start a vulnerability scan')
      .requiredOption('-t, --target <urls...>', 'Target URLs to scan')
      .option('-p, --policy <policy>', 'Scan policy', 'default')
      .option('--active', 'Enable active scanning', true)
      .option('--passive', 'Enable passive scanning', true)
      .action(async (options) => {
        console.log(`Starting scan on ${options.target.join(', ')}...`);

        const result = await this.apiRequest('POST', '/api/scan/start', {
          config: {
            activeScanning: options.active,
            passiveScanning: options.passive
          },
          urls: options.target,
          policy: { vulnerabilityChecks: {} }
        });

        console.log(result.message);
      });

    scan
      .command('status')
      .description('Get scan status')
      .action(async () => {
        const result = await this.apiRequest('GET', '/api/scan/status');
        console.log(JSON.stringify(result.result, null, 2));
      });

    scan
      .command('stop')
      .description('Stop running scan')
      .action(async () => {
        const result = await this.apiRequest('POST', '/api/scan/stop');
        console.log(result.message);
      });

    scan
      .command('results')
      .description('Get scan results')
      .option('-s, --severity <severity>', 'Filter by severity')
      .option('-o, --output <file>', 'Save results to file')
      .action(async (options) => {
        const filters = options.severity ? { severity: options.severity } : {};
        const result = await this.apiRequest('GET', '/api/scan/vulnerabilities', filters);

        const output = JSON.stringify(result.result, null, 2);

        if (options.output) {
          fs.writeFileSync(options.output, output);
          console.log(`Results saved to ${options.output}`);
        } else {
          console.log(output);
        }
      });

    // Spider commands
    const spider = this.program.command('spider').description('Spidering operations');

    spider
      .command('start')
      .description('Start web spider')
      .requiredOption('-t, --target <urls...>', 'Starting URLs')
      .option('-d, --depth <depth>', 'Maximum crawl depth', '3')
      .option('-m, --max <max>', 'Maximum requests', '100')
      .action(async (options) => {
        console.log(`Starting spider on ${options.target.join(', ')}...`);

        const result = await this.apiRequest('POST', '/api/spider/start', {
          config: {
            maxDepth: parseInt(options.depth),
            maxRequests: parseInt(options.max)
          },
          startUrls: options.target
        });

        console.log(result.message);
      });

    spider
      .command('endpoints')
      .description('List discovered endpoints')
      .option('-o, --output <file>', 'Save endpoints to file')
      .action(async (options) => {
        const result = await this.apiRequest('GET', '/api/spider/endpoints');

        const output = JSON.stringify(result.result, null, 2);

        if (options.output) {
          fs.writeFileSync(options.output, output);
          console.log(`Endpoints saved to ${options.output}`);
        } else {
          console.log(output);
        }
      });

    // Report commands
    const report = this.program.command('report').description('Report generation');

    report
      .command('generate')
      .description('Generate vulnerability report')
      .option('-f, --format <format>', 'Report format (json, xml, html)', 'json')
      .option('-o, --output <file>', 'Output file')
      .action(async (options) => {
        const result = await this.apiRequest('GET', '/api/reports/vulnerabilities');

        let output;
        if (options.format === 'json') {
          output = JSON.stringify(result.result, null, 2);
        } else if (options.format === 'xml') {
          output = this.generateXMLReport(result.result);
        } else if (options.format === 'html') {
          output = this.generateHTMLReport(result.result);
        }

        if (options.output) {
          fs.writeFileSync(options.output, output);
          console.log(`Report saved to ${options.output}`);
        } else {
          console.log(output);
        }
      });

    report
      .command('export')
      .description('Export proxy history')
      .option('-f, --format <format>', 'Export format (json, csv, xml, har)', 'json')
      .option('-o, --output <file>', 'Output file', `export-${Date.now()}.json`)
      .action(async (options) => {
        const response = await axios({
          method: 'POST',
          url: `${this.apiUrl}/api/reports/generate`,
          headers: {
            'X-API-Key': this.apiKey
          },
          data: {
            format: options.format,
            filters: {}
          }
        });

        fs.writeFileSync(options.output, response.data);
        console.log(`Export saved to ${options.output}`);
      });

    // Project commands
    const project = this.program.command('project').description('Project management');

    project
      .command('save')
      .description('Save project configuration')
      .requiredOption('-n, --name <name>', 'Project name')
      .requiredOption('-c, --config <file>', 'Configuration file')
      .action(async (options) => {
        const config = JSON.parse(fs.readFileSync(options.config, 'utf-8'));

        await this.apiRequest('POST', '/api/project/save', {
          name: options.name,
          config
        });

        console.log(`Project "${options.name}" saved`);
      });

    project
      .command('load')
      .description('Load project configuration')
      .requiredOption('-n, --name <name>', 'Project name')
      .option('-o, --output <file>', 'Output file')
      .action(async (options) => {
        const result = await this.apiRequest('GET', `/api/project/load/${options.name}`);

        const output = JSON.stringify(result.result, null, 2);

        if (options.output) {
          fs.writeFileSync(options.output, output);
          console.log(`Project configuration saved to ${options.output}`);
        } else {
          console.log(output);
        }
      });

    // Macro commands
    const macro = this.program.command('macro').description('Macro execution');

    macro
      .command('execute')
      .description('Execute a macro')
      .requiredOption('-i, --id <macroId>', 'Macro ID')
      .option('-v, --variables <json>', 'Variables as JSON string')
      .action(async (options) => {
        const variables = options.variables ? JSON.parse(options.variables) : {};

        console.log(`Executing macro ${options.id}...`);

        const result = await this.apiRequest('POST', `/api/macros/${options.id}/execute`, {
          variables
        });

        console.log('Macro execution completed');
        console.log(JSON.stringify(result.result, null, 2));
      });

    macro
      .command('list')
      .description('List all macros')
      .action(async () => {
        const result = await this.apiRequest('GET', '/api/macros');
        console.log(JSON.stringify(result.result, null, 2));
      });

    // CI/CD helper command
    this.program
      .command('ci-scan')
      .description('Run a complete CI/CD scan workflow')
      .requiredOption('-t, --target <urls...>', 'Target URLs')
      .option('-o, --output <file>', 'Output report file', 'nmat-report.json')
      .option('--fail-on-high', 'Exit with error code if high severity issues found')
      .option('--timeout <seconds>', 'Scan timeout in seconds', '300')
      .action(async (options) => {
        console.log('Starting CI/CD scan workflow...');

        // Start scan
        await this.apiRequest('POST', '/api/scan/start', {
          config: { activeScanning: true, passiveScanning: true },
          urls: options.target,
          policy: {}
        });

        // Wait for scan to complete or timeout
        const startTime = Date.now();
        const timeout = parseInt(options.timeout) * 1000;

        while (Date.now() - startTime < timeout) {
          const status = await this.apiRequest('GET', '/api/scan/status');

          if (!status.result.running) {
            break;
          }

          await new Promise(resolve => setTimeout(resolve, 5000));
        }

        // Get results
        const result = await this.apiRequest('GET', '/api/reports/vulnerabilities');

        // Save report
        fs.writeFileSync(options.output, JSON.stringify(result.result, null, 2));
        console.log(`Report saved to ${options.output}`);

        // Print summary
        const summary = result.result;
        console.log('\nScan Summary:');
        console.log(`Total vulnerabilities: ${summary.totalVulnerabilities}`);
        console.log(`Critical: ${summary.bySeverity.critical || 0}`);
        console.log(`High: ${summary.bySeverity.high || 0}`);
        console.log(`Medium: ${summary.bySeverity.medium || 0}`);
        console.log(`Low: ${summary.bySeverity.low || 0}`);

        // Fail if high severity issues found
        if (options.failOnHigh && (summary.bySeverity.high > 0 || summary.bySeverity.critical > 0)) {
          console.error('\nFailing: High or critical severity vulnerabilities found');
          process.exit(1);
        }
      });
  }

  /**
   * Generate XML report
   */
  generateXMLReport(data) {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<vulnerabilityReport>\n';
    xml += `  <generatedAt>${data.generatedAt}</generatedAt>\n`;
    xml += `  <totalVulnerabilities>${data.totalVulnerabilities}</totalVulnerabilities>\n`;
    xml += '  <vulnerabilities>\n';

    data.vulnerabilities.forEach(vuln => {
      xml += '    <vulnerability>\n';
      xml += `      <type>${this.escapeXml(vuln.vulnerabilityType)}</type>\n`;
      xml += `      <severity>${vuln.severity}</severity>\n`;
      xml += `      <url>${this.escapeXml(vuln.url)}</url>\n`;
      xml += `      <description>${this.escapeXml(vuln.description)}</description>\n`;
      xml += '    </vulnerability>\n';
    });

    xml += '  </vulnerabilities>\n';
    xml += '</vulnerabilityReport>';

    return xml;
  }

  /**
   * Generate HTML report
   */
  generateHTMLReport(data) {
    let html = `<!DOCTYPE html>
<html>
<head>
  <title>NMAT Vulnerability Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #333; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #4CAF50; color: white; }
    .critical { background-color: #f44336; color: white; }
    .high { background-color: #ff9800; }
    .medium { background-color: #ffeb3b; }
    .low { background-color: #8bc34a; }
  </style>
</head>
<body>
  <h1>NMAT Vulnerability Report</h1>
  <p>Generated: ${data.generatedAt}</p>
  <p>Total Vulnerabilities: ${data.totalVulnerabilities}</p>

  <h2>Summary by Severity</h2>
  <table>
    <tr>
      <th>Severity</th>
      <th>Count</th>
    </tr>
    <tr class="critical"><td>Critical</td><td>${data.bySeverity.critical || 0}</td></tr>
    <tr class="high"><td>High</td><td>${data.bySeverity.high || 0}</td></tr>
    <tr class="medium"><td>Medium</td><td>${data.bySeverity.medium || 0}</td></tr>
    <tr class="low"><td>Low</td><td>${data.bySeverity.low || 0}</td></tr>
  </table>

  <h2>Vulnerabilities</h2>
  <table>
    <tr>
      <th>Type</th>
      <th>Severity</th>
      <th>URL</th>
      <th>Description</th>
    </tr>`;

    data.vulnerabilities.forEach(vuln => {
      html += `
    <tr class="${vuln.severity}">
      <td>${this.escapeHtml(vuln.vulnerabilityType)}</td>
      <td>${vuln.severity}</td>
      <td>${this.escapeHtml(vuln.url)}</td>
      <td>${this.escapeHtml(vuln.description)}</td>
    </tr>`;
    });

    html += `
  </table>
</body>
</html>`;

    return html;
  }

  /**
   * Escape XML
   */
  escapeXml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  /**
   * Escape HTML
   */
  escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /**
   * Run CLI
   */
  run() {
    this.program.parse(process.argv);
  }
}

// Run CLI
const cli = new NMATCli();
cli.run();
