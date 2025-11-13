const fs = require('fs');
const path = require('path');

/**
 * Report Generator - Generate comprehensive security reports
 * Supports multiple formats: HTML, PDF, JSON, XML, Markdown
 */
class ReportGenerator {
  constructor(database) {
    this.db = database;
  }

  /**
   * Generate complete security report
   */
  generateReport(config = {}) {
    const data = this.aggregateData(config);
    const report = {
      metadata: {
        generatedAt: new Date().toISOString(),
        reportType: config.reportType || 'full',
        projectName: config.projectName || 'NMAT Security Assessment',
        dateRange: config.dateRange || { start: null, end: Date.now() }
      },
      executive_summary: this.generateExecutiveSummary(data),
      vulnerability_summary: this.generateVulnerabilitySummary(data.vulnerabilities),
      detailed_findings: data.vulnerabilities,
      scan_coverage: this.generateScanCoverage(data),
      compliance: config.compliance ? this.generateComplianceReport(data, config.compliance) : null,
      recommendations: this.generateRecommendations(data),
      appendix: {
        methodology: this.getMethodology(),
        riskRatings: this.getRiskRatings()
      }
    };

    return report;
  }

  /**
   * Aggregate data from database
   */
  aggregateData(config) {
    const vulnerabilities = this.db.getVulnerabilities(config.filters || {});
    const endpoints = this.db.getEndpoints();
    const history = this.db.getHistory({ limit: 1000 });

    return {
      vulnerabilities,
      endpoints,
      history,
      scanCount: history.length,
      endpointCount: endpoints.length
    };
  }

  /**
   * Generate executive summary
   */
  generateExecutiveSummary(data) {
    const severityCounts = this.groupBySeverity(data.vulnerabilities);
    const totalVulnerabilities = data.vulnerabilities.length;

    const riskScore = this.calculateRiskScore(severityCounts);
    const riskLevel = this.getRiskLevel(riskScore);

    return {
      totalVulnerabilities,
      severityBreakdown: severityCounts,
      riskScore,
      riskLevel,
      criticalFindings: data.vulnerabilities.filter(v => v.severity === 'critical').length,
      highFindings: data.vulnerabilities.filter(v => v.severity === 'high').length,
      endpointsTested: data.endpointCount,
      requestsMade: data.scanCount,
      keyFindings: this.getTopVulnerabilities(data.vulnerabilities, 5)
    };
  }

  /**
   * Generate vulnerability summary
   */
  generateVulnerabilitySummary(vulnerabilities) {
    return {
      total: vulnerabilities.length,
      bySeverity: this.groupBySeverity(vulnerabilities),
      byType: this.groupByType(vulnerabilities),
      byConfidence: this.groupByConfidence(vulnerabilities),
      byCWE: this.groupByCWE(vulnerabilities),
      byOWASP: this.groupByOWASP(vulnerabilities)
    };
  }

  /**
   * Generate scan coverage report
   */
  generateScanCoverage(data) {
    const uniqueHosts = new Set(data.endpoints.map(e => e.host)).size;
    const uniquePaths = new Set(data.endpoints.map(e => e.path)).size;

    return {
      uniqueHosts,
      uniquePaths,
      totalEndpoints: data.endpointCount,
      scanDepth: Math.max(...data.endpoints.map(e => (e.path || '').split('/').length)),
      coverage: {
        forms: data.endpoints.filter(e => e.forms && e.forms.length > 0).length,
        parameters: data.endpoints.filter(e => e.parameters && e.parameters.length > 0).length,
        apis: data.endpoints.filter(e => e.path && e.path.includes('/api/')).length
      }
    };
  }

  /**
   * Generate compliance report
   */
  generateComplianceReport(data, complianceStandards) {
    const results = {};

    if (complianceStandards.includes('OWASP_TOP_10')) {
      results.OWASP_TOP_10 = this.checkOWASPTop10Compliance(data.vulnerabilities);
    }

    if (complianceStandards.includes('PCI_DSS')) {
      results.PCI_DSS = this.checkPCIDSSCompliance(data.vulnerabilities);
    }

    if (complianceStandards.includes('GDPR')) {
      results.GDPR = this.checkGDPRCompliance(data.vulnerabilities);
    }

    return results;
  }

  /**
   * Check OWASP Top 10 compliance
   */
  checkOWASPTop10Compliance(vulnerabilities) {
    const owaspCategories = {
      'A01:2021 - Broken Access Control': [],
      'A02:2021 - Cryptographic Failures': [],
      'A03:2021 - Injection': [],
      'A04:2021 - Insecure Design': [],
      'A05:2021 - Security Misconfiguration': [],
      'A06:2021 - Vulnerable Components': [],
      'A07:2021 - Identification Failures': [],
      'A08:2021 - Software Integrity Failures': [],
      'A09:2021 - Logging Failures': [],
      'A10:2021 - SSRF': []
    };

    vulnerabilities.forEach(vuln => {
      const category = this.mapToOWASPCategory(vuln.vulnerabilityType);
      if (category && owaspCategories[category]) {
        owaspCategories[category].push(vuln);
      }
    });

    const compliance = Object.entries(owaspCategories).map(([category, vulns]) => ({
      category,
      issueCount: vulns.length,
      status: vulns.length === 0 ? 'PASS' : 'FAIL',
      severity: vulns.length > 0 ? Math.max(...vulns.map(v => this.severityToNumber(v.severity))) : 0
    }));

    return {
      overallStatus: compliance.every(c => c.status === 'PASS') ? 'COMPLIANT' : 'NON_COMPLIANT',
      categories: compliance
    };
  }

  /**
   * Check PCI DSS compliance
   */
  checkPCIDSSCompliance(vulnerabilities) {
    const requirements = {
      'Requirement 6.5.1 - Injection': vulnerabilities.filter(v =>
        ['SQL Injection', 'Command Injection', 'LDAP Injection'].includes(v.vulnerabilityType)
      ).length === 0,
      'Requirement 6.5.7 - XSS': vulnerabilities.filter(v =>
        v.vulnerabilityType.includes('XSS')
      ).length === 0,
      'Requirement 6.5.8 - Access Control': vulnerabilities.filter(v =>
        ['Authorization Bypass', 'Authentication Bypass'].includes(v.vulnerabilityType)
      ).length === 0,
      'Requirement 6.5.9 - CSRF': vulnerabilities.filter(v =>
        v.vulnerabilityType === 'CSRF'
      ).length === 0,
      'Requirement 6.5.10 - Authentication': vulnerabilities.filter(v =>
        v.vulnerabilityType.includes('Authentication')
      ).length === 0
    };

    return {
      overallStatus: Object.values(requirements).every(v => v === true) ? 'COMPLIANT' : 'NON_COMPLIANT',
      requirements: Object.entries(requirements).map(([req, status]) => ({
        requirement: req,
        status: status ? 'PASS' : 'FAIL'
      }))
    };
  }

  /**
   * Check GDPR compliance
   */
  checkGDPRCompliance(vulnerabilities) {
    const dataProtectionIssues = vulnerabilities.filter(v =>
      ['Information Disclosure', 'Insecure Cookie', 'Sensitive Data Exposure'].includes(v.vulnerabilityType)
    );

    return {
      overallStatus: dataProtectionIssues.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT',
      dataProtectionIssues: dataProtectionIssues.length,
      findings: dataProtectionIssues.map(v => ({
        type: v.vulnerabilityType,
        url: v.url,
        severity: v.severity
      }))
    };
  }

  /**
   * Generate recommendations
   */
  generateRecommendations(data) {
    const recommendations = [];

    // Priority recommendations based on critical/high vulnerabilities
    const critical = data.vulnerabilities.filter(v => v.severity === 'critical');
    if (critical.length > 0) {
      recommendations.push({
        priority: 'CRITICAL',
        title: 'Address Critical Vulnerabilities Immediately',
        description: `${critical.length} critical vulnerabilities were identified that require immediate remediation.`,
        actions: critical.slice(0, 5).map(v => `Fix ${v.vulnerabilityType} at ${v.url}`)
      });
    }

    // Common vulnerability patterns
    const sqlInjection = data.vulnerabilities.filter(v => v.vulnerabilityType === 'SQL Injection');
    if (sqlInjection.length > 0) {
      recommendations.push({
        priority: 'HIGH',
        title: 'Implement Parameterized Queries',
        description: 'Multiple SQL injection vulnerabilities detected. Use prepared statements and parameterized queries.',
        actions: ['Review all database queries', 'Implement ORM or query builders', 'Add input validation']
      });
    }

    // Security headers
    const securityMisconfig = data.vulnerabilities.filter(v => v.vulnerabilityType === 'Security Misconfiguration');
    if (securityMisconfig.length > 0) {
      recommendations.push({
        priority: 'MEDIUM',
        title: 'Configure Security Headers',
        description: 'Missing security headers detected. Implement comprehensive security headers.',
        actions: [
          'Add Content-Security-Policy header',
          'Add X-Frame-Options header',
          'Add Strict-Transport-Security header',
          'Add X-Content-Type-Options header'
        ]
      });
    }

    return recommendations;
  }

  /**
   * Generate HTML report
   */
  generateHTML(reportData) {
    const summary = reportData.executive_summary;
    const vulnSummary = reportData.vulnerability_summary;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${reportData.metadata.projectName} - Security Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; text-align: center; margin-bottom: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    h1 { font-size: 2.5em; margin-bottom: 10px; }
    .report-meta { font-size: 0.9em; opacity: 0.9; }
    .section { background: white; padding: 30px; margin-bottom: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h2 { color: #667eea; margin-bottom: 20px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
    .risk-score { display: inline-block; padding: 10px 20px; border-radius: 5px; font-weight: bold; font-size: 1.2em; margin: 10px 0; }
    .risk-critical { background: #f44336; color: white; }
    .risk-high { background: #ff9800; color: white; }
    .risk-medium { background: #ffeb3b; color: #333; }
    .risk-low { background: #8bc34a; color: white; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
    .stat-card { background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); padding: 20px; border-radius: 8px; text-align: center; }
    .stat-number { font-size: 2.5em; font-weight: bold; color: #667eea; }
    .stat-label { color: #666; margin-top: 5px; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background: #667eea; color: white; font-weight: 600; }
    tr:hover { background: #f5f5f5; }
    .severity-critical { background: #ffebee; }
    .severity-high { background: #fff3e0; }
    .severity-medium { background: #fffde7; }
    .severity-low { background: #f1f8e9; }
    .chart { margin: 20px 0; }
    .bar { height: 30px; background: #667eea; margin: 5px 0; position: relative; border-radius: 3px; }
    .bar-label { position: absolute; left: 10px; line-height: 30px; color: white; font-weight: bold; }
    .recommendation { background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin: 10px 0; border-radius: 4px; }
    .recommendation-priority { display: inline-block; padding: 3px 10px; border-radius: 3px; font-size: 0.85em; font-weight: bold; margin-bottom: 10px; }
    .priority-critical { background: #f44336; color: white; }
    .priority-high { background: #ff9800; color: white; }
    .priority-medium { background: #ffeb3b; color: #333; }
    footer { text-align: center; padding: 20px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>${reportData.metadata.projectName}</h1>
      <div class="report-meta">
        Security Assessment Report | Generated: ${reportData.metadata.generatedAt}
      </div>
    </header>

    <div class="section">
      <h2>Executive Summary</h2>
      <div class="risk-score risk-${summary.riskLevel.toLowerCase()}">${summary.riskLevel} RISK (Score: ${summary.riskScore}/100)</div>
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-number">${summary.totalVulnerabilities}</div>
          <div class="stat-label">Total Vulnerabilities</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">${summary.criticalFindings}</div>
          <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">${summary.highFindings}</div>
          <div class="stat-label">High</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">${summary.endpointsTested}</div>
          <div class="stat-label">Endpoints Tested</div>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Vulnerability Summary</h2>
      <h3>By Severity</h3>
      <div class="chart">
        ${this.renderBar('Critical', vulnSummary.bySeverity.critical || 0, summary.totalVulnerabilities, '#f44336')}
        ${this.renderBar('High', vulnSummary.bySeverity.high || 0, summary.totalVulnerabilities, '#ff9800')}
        ${this.renderBar('Medium', vulnSummary.bySeverity.medium || 0, summary.totalVulnerabilities, '#ffeb3b')}
        ${this.renderBar('Low', vulnSummary.bySeverity.low || 0, summary.totalVulnerabilities, '#8bc34a')}
      </div>

      <h3>By Type</h3>
      <table>
        <tr><th>Vulnerability Type</th><th>Count</th></tr>
        ${Object.entries(vulnSummary.byType).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([type, count]) => `
          <tr><td>${type}</td><td>${count}</td></tr>
        `).join('')}
      </table>
    </div>

    <div class="section">
      <h2>Detailed Findings</h2>
      <table>
        <tr>
          <th>Severity</th>
          <th>Type</th>
          <th>URL</th>
          <th>Confidence</th>
        </tr>
        ${reportData.detailed_findings.slice(0, 50).map(vuln => `
          <tr class="severity-${vuln.severity}">
            <td>${vuln.severity.toUpperCase()}</td>
            <td>${vuln.vulnerabilityType}</td>
            <td>${this.truncate(vuln.url, 60)}</td>
            <td>${vuln.confidence}</td>
          </tr>
        `).join('')}
      </table>
      ${reportData.detailed_findings.length > 50 ? `<p><em>Showing first 50 of ${reportData.detailed_findings.length} findings. See full report for complete list.</em></p>` : ''}
    </div>

    ${reportData.recommendations.length > 0 ? `
    <div class="section">
      <h2>Recommendations</h2>
      ${reportData.recommendations.map(rec => `
        <div class="recommendation">
          <div class="recommendation-priority priority-${rec.priority.toLowerCase()}">${rec.priority}</div>
          <h3>${rec.title}</h3>
          <p>${rec.description}</p>
          <ul>
            ${rec.actions.map(action => `<li>${action}</li>`).join('')}
          </ul>
        </div>
      `).join('')}
    </div>
    ` : ''}

    <footer>
      <p>Generated by NMAT - Network Monitor Analysis Tool</p>
      <p>This report contains confidential security information</p>
    </footer>
  </div>
</body>
</html>`;
  }

  /**
   * Render progress bar
   */
  renderBar(label, value, total, color) {
    const percent = total > 0 ? Math.round((value / total) * 100) : 0;
    return `<div class="bar" style="width: ${percent}%; background: ${color};">
      <span class="bar-label">${label}: ${value} (${percent}%)</span>
    </div>`;
  }

  /**
   * Helper methods
   */
  groupBySeverity(vulnerabilities) {
    const groups = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    vulnerabilities.forEach(v => {
      groups[v.severity] = (groups[v.severity] || 0) + 1;
    });
    return groups;
  }

  groupByType(vulnerabilities) {
    const groups = {};
    vulnerabilities.forEach(v => {
      groups[v.vulnerabilityType] = (groups[v.vulnerabilityType] || 0) + 1;
    });
    return groups;
  }

  groupByConfidence(vulnerabilities) {
    const groups = { certain: 0, firm: 0, tentative: 0 };
    vulnerabilities.forEach(v => {
      groups[v.confidence] = (groups[v.confidence] || 0) + 1;
    });
    return groups;
  }

  groupByCWE(vulnerabilities) {
    const groups = {};
    vulnerabilities.forEach(v => {
      if (v.cweId) {
        groups[v.cweId] = (groups[v.cweId] || 0) + 1;
      }
    });
    return groups;
  }

  groupByOWASP(vulnerabilities) {
    const groups = {};
    vulnerabilities.forEach(v => {
      if (v.owaspCategory) {
        groups[v.owaspCategory] = (groups[v.owaspCategory] || 0) + 1;
      }
    });
    return groups;
  }

  calculateRiskScore(severityCounts) {
    return Math.min(100,
      (severityCounts.critical || 0) * 25 +
      (severityCounts.high || 0) * 10 +
      (severityCounts.medium || 0) * 3 +
      (severityCounts.low || 0) * 1
    );
  }

  getRiskLevel(score) {
    if (score >= 75) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 25) return 'MEDIUM';
    return 'LOW';
  }

  getTopVulnerabilities(vulnerabilities, count) {
    return vulnerabilities
      .sort((a, b) => this.severityToNumber(b.severity) - this.severityToNumber(a.severity))
      .slice(0, count)
      .map(v => ({
        type: v.vulnerabilityType,
        severity: v.severity,
        url: v.url
      }));
  }

  severityToNumber(severity) {
    const map = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return map[severity] || 0;
  }

  mapToOWASPCategory(vulnerabilityType) {
    const mapping = {
      'SQL Injection': 'A03:2021 - Injection',
      'Command Injection': 'A03:2021 - Injection',
      'LDAP Injection': 'A03:2021 - Injection',
      'XSS Reflected': 'A03:2021 - Injection',
      'XSS Stored': 'A03:2021 - Injection',
      'Authorization Bypass': 'A01:2021 - Broken Access Control',
      'Authentication Bypass': 'A07:2021 - Identification Failures',
      'Security Misconfiguration': 'A05:2021 - Security Misconfiguration',
      'SSRF': 'A10:2021 - SSRF'
    };
    return mapping[vulnerabilityType] || null;
  }

  truncate(str, length) {
    return str.length > length ? str.substring(0, length) + '...' : str;
  }

  getMethodology() {
    return 'Automated vulnerability scanning using NMAT with active and passive detection techniques.';
  }

  getRiskRatings() {
    return {
      critical: 'CVSS 9.0-10.0',
      high: 'CVSS 7.0-8.9',
      medium: 'CVSS 4.0-6.9',
      low: 'CVSS 0.1-3.9'
    };
  }

  /**
   * Save report to file
   */
  async saveReport(reportData, format, filepath) {
    let content;

    switch (format) {
      case 'html':
        content = this.generateHTML(reportData);
        break;
      case 'json':
        content = JSON.stringify(reportData, null, 2);
        break;
      case 'xml':
        content = this.generateXML(reportData);
        break;
      default:
        throw new Error('Unsupported format');
    }

    fs.writeFileSync(filepath, content);
    return filepath;
  }

  /**
   * Generate XML report
   */
  generateXML(reportData) {
    return `<?xml version="1.0" encoding="UTF-8"?>
<securityReport>
  <metadata>
    <generatedAt>${reportData.metadata.generatedAt}</generatedAt>
    <projectName>${reportData.metadata.projectName}</projectName>
  </metadata>
  <executiveSummary>
    <totalVulnerabilities>${reportData.executive_summary.totalVulnerabilities}</totalVulnerabilities>
    <riskScore>${reportData.executive_summary.riskScore}</riskScore>
    <riskLevel>${reportData.executive_summary.riskLevel}</riskLevel>
  </executiveSummary>
</securityReport>`;
  }
}

module.exports = ReportGenerator;
