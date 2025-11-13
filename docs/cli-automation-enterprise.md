# NMAT CLI, Automation & Enterprise Features

Complete guide to NMAT's professional automation, CLI tools, and enterprise features for CI/CD integration and scalable security testing.

## Table of Contents

1. [REST API Server](#rest-api-server)
2. [CLI Tool](#cli-tool)
3. [Project Management](#project-management)
4. [Scheduling System](#scheduling-system)
5. [Report Generation](#report-generation)
6. [CI/CD Integration](#cicd-integration)
7. [Enterprise Features](#enterprise-features)

---

## REST API Server

The REST API provides programmatic access to all NMAT features for automation and integration.

### Starting the API Server

```javascript
// From NMAT UI
const result = await window.api.startRestApi(8080);
console.log('API server running on port:', result.result.port);

// Generate API key
const apiKey = await window.api.generateApiKey('my-automation');
console.log('API Key:', apiKey.result);
```

### API Key Management

```javascript
// List all API keys
const keys = await window.api.listApiKeys();

// Each key shows:
// - key: First 8 characters (for display)
// - fullKey: Complete key (for use)
// - name: Key identifier
// - createdAt: Creation timestamp
```

### Available Endpoints

#### Health Check
```bash
GET /api/health
```

#### Scanner Operations
```bash
POST /api/scan/start
POST /api/scan/stop
GET /api/scan/vulnerabilities
GET /api/scan/status
```

#### Spider Operations
```bash
POST /api/spider/start
GET /api/spider/endpoints
```

#### Intruder Operations
```bash
POST /api/intruder/attack
GET /api/intruder/results/:attackId
```

#### Report Generation
```bash
POST /api/reports/generate
GET /api/reports/vulnerabilities
```

#### Project Management
```bash
POST /api/project/save
GET /api/project/load/:name
```

### Example API Usage

```bash
# Health check
curl http://localhost:8080/api/health

# Start scan (requires API key)
curl -X POST http://localhost:8080/api/scan/start \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {"activeScanning": true},
    "urls": ["https://example.com"],
    "policy": {}
  }'

# Get vulnerabilities
curl http://localhost:8080/api/scan/vulnerabilities \
  -H "X-API-Key: your-api-key-here"

# Generate report
curl -X POST http://localhost:8080/api/reports/generate \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"format": "json", "filters": {}}'
```

---

## CLI Tool

The NMAT CLI (`nmat`) provides command-line access for headless scanning and CI/CD integration.

### Installation

```bash
npm install -g nmat-cli
# OR if installed locally
npm link
```

### Configuration

```bash
# Interactive configuration
nmat configure

# Or with flags
nmat configure \
  --url http://localhost:8080 \
  --key your-api-key
```

Configuration is saved to `~/.nmat/config.json`

### Scanning Commands

```bash
# Start a scan
nmat scan start \
  --target https://example.com \
  --policy default \
  --active \
  --passive

# Check scan status
nmat scan status

# Stop scan
nmat scan stop

# Get results
nmat scan results --severity high --output results.json
```

### Spider Commands

```bash
# Start spider
nmat spider start \
  --target https://example.com \
  --depth 3 \
  --max 100

# List discovered endpoints
nmat spider endpoints --output endpoints.json
```

### Report Commands

```bash
# Generate vulnerability report
nmat report generate \
  --format html \
  --output security-report.html

# Export history
nmat report export \
  --format har \
  --output traffic.har
```

### Project Commands

```bash
# Save project
nmat project save \
  --name my-project \
  --config project-config.json

# Load project
nmat project load \
  --name my-project \
  --output loaded-config.json
```

### Macro Commands

```bash
# Execute a macro
nmat macro execute \
  --id macro-123 \
  --variables '{"username":"test","password":"pass"}'

# List macros
nmat macro list
```

### CI/CD Scan Command

Complete automated scan workflow for CI/CD pipelines:

```bash
nmat ci-scan \
  --target https://staging.example.com \
  --output nmat-report.json \
  --fail-on-high \
  --timeout 600
```

**Features:**
- Starts scan automatically
- Waits for completion
- Generates JSON report
- Prints summary to console
- Exits with error code if critical/high issues found
- Perfect for CI/CD gates

**Output Example:**
```
Starting CI/CD scan workflow...
Report saved to nmat-report.json

Scan Summary:
Total vulnerabilities: 12
Critical: 0
High: 2
Medium: 5
Low: 5

Failing: High or critical severity vulnerabilities found
```

---

## Project Management

Organize scans with reusable project configurations.

### Creating Projects

```javascript
const project = await window.api.createProject({
  name: 'E-Commerce App Security',
  description: 'Security testing for online store',
  owner: 'security-team',
  team: ['alice@example.com', 'bob@example.com'],
  scope: [
    { type: 'include', protocol: 'https', host: 'store.example.com' }
  ],
  scanPolicies: [
    { id: 'default', enabled: true }
  ],
  sessionRules: [...],
  macros: [...],
  tags: ['production', 'ecommerce'],
  priority: 'high',
  compliance: ['PCI-DSS', 'OWASP']
});
```

### Loading Projects

```javascript
// Load project configuration
const project = await window.api.loadProject('proj_123');

// Apply project config to current session
await window.api.applyProjectConfig('proj_123');
```

### Listing Projects

```javascript
// All projects
const projects = await window.api.listProjects();

// Filtered
const myProjects = await window.api.listProjects({
  owner: 'security-team',
  tag: 'production'
});
```

### Project Structure

```json
{
  "id": "proj_1234567890_abc123",
  "name": "E-Commerce App",
  "description": "Security testing",
  "owner": "security-team",
  "team": ["alice@example.com"],
  "config": {
    "scope": [...],
    "scanPolicies": [...],
    "sessionRules": [...],
    "macros": [...],
    "collaboratorConfig": {...},
    "proxySettings": {...},
    "spiderConfig": {...},
    "scannerConfig": {...}
  },
  "metadata": {
    "tags": ["production"],
    "priority": "high",
    "compliance": ["PCI-DSS"]
  },
  "scanHistory": [...]
}
```

---

## Scheduling System

Automate regular security scans with cron-based scheduling.

### Creating Schedules

```javascript
const schedule = await window.api.createSchedule({
  name: 'Daily Production Scan',
  description: 'Automated security scan of production environment',
  cronExpression: '0 2 * * *', // 2 AM daily
  type: 'scan', // or 'spider', 'macro'
  config: {
    urls: ['https://app.example.com'],
    policy: { vulnerabilityChecks: {...} }
  },
  projectId: 'proj_123',
  notifications: {
    onStart: false,
    onComplete: true,
    onError: true,
    email: 'security@example.com',
    webhook: 'https://hooks.slack.com/services/...'
  }
});
```

### Cron Expression Examples

```
0 2 * * *      # Daily at 2 AM
0 */6 * * *    # Every 6 hours
0 9 * * 1      # Every Monday at 9 AM
0 0 1 * *      # First day of month at midnight
*/30 * * * *   # Every 30 minutes
```

### Managing Schedules

```javascript
// Start schedule
await window.api.startSchedule(scheduleId);

// Stop schedule
await window.api.stopSchedule(scheduleId);

// Run immediately (manual trigger)
await window.api.runScheduleNow(scheduleId);

// Get execution history
const history = await window.api.getExecutionHistory(scheduleId, 50);
```

### Schedule Events

```javascript
// Listen for execution events
window.api.onScheduleExecutionStarted((data) => {
  console.log('Schedule started:', data.scheduleName);
});

window.api.onScheduleExecutionCompleted((data) => {
  console.log('Schedule completed:', data.results);
});

window.api.onScheduleExecutionFailed((data) => {
  console.error('Schedule failed:', data.error);
});
```

### Execution History

```javascript
const history = await window.api.getExecutionHistory(scheduleId);

// Each execution contains:
// - id: Execution ID
// - scheduleId: Parent schedule
// - startTime: When started
// - endTime: When finished
// - status: 'running', 'completed', 'failed'
// - results: Scan results
// - error: Error message if failed
```

---

## Report Generation

Generate comprehensive security reports in multiple formats.

### Generating Reports

```javascript
// Generate full security report
const report = await window.api.generateSecurityReport({
  reportType: 'full',
  projectName: 'E-Commerce Security Assessment',
  filters: { severity: 'high' },
  compliance: ['OWASP_TOP_10', 'PCI_DSS', 'GDPR']
});
```

### Report Structure

```json
{
  "metadata": {
    "generatedAt": "2025-01-15T10:30:00Z",
    "projectName": "Security Assessment",
    "reportType": "full"
  },
  "executive_summary": {
    "totalVulnerabilities": 42,
    "riskScore": 65,
    "riskLevel": "HIGH",
    "criticalFindings": 2,
    "highFindings": 8,
    "keyFindings": [...]
  },
  "vulnerability_summary": {
    "bySeverity": {...},
    "byType": {...},
    "byConfidence": {...},
    "byCWE": {...},
    "byOWASP": {...}
  },
  "detailed_findings": [...],
  "scan_coverage": {...},
  "compliance": {
    "OWASP_TOP_10": {...},
    "PCI_DSS": {...},
    "GDPR": {...}
  },
  "recommendations": [...]
}
```

### HTML Report Generation

```javascript
// Generate beautiful HTML report
const html = await window.api.generateHtmlReport({
  projectName: 'Production Security Scan',
  compliance: ['OWASP_TOP_10']
});

// Save to file
await window.api.saveReport(reportData, 'html', 'security-report.html');
```

### Compliance Reporting

**OWASP Top 10 2021:**
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Identification Failures
- A08: Software Integrity Failures
- A09: Logging Failures
- A10: SSRF

**PCI DSS:**
- Requirement 6.5.1 - Injection
- Requirement 6.5.7 - XSS
- Requirement 6.5.8 - Access Control
- Requirement 6.5.9 - CSRF
- Requirement 6.5.10 - Authentication

**GDPR:**
- Data protection issues
- Sensitive data exposure
- Privacy violations

### Report Formats

| Format | Use Case | Size | Features |
|--------|----------|------|----------|
| HTML | Presentation | Medium | Interactive, styled, charts |
| JSON | Automation | Small | Machine-readable, complete data |
| XML | Integration | Large | Structured, schemas |

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/nmat-scan.yml
name: NMAT Security Scan

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 2 * * *'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm install -g nmat-cli
      - run: nmat configure --url ${{ secrets.NMAT_API_URL }} --key ${{ secrets.NMAT_API_KEY }}
      - run: nmat ci-scan --target ${{ secrets.TARGET_URL }} --fail-on-high
      - uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: nmat-report.json
```

### GitLab CI

```yaml
# .gitlab-ci.yml
nmat_security_scan:
  stage: security
  image: node:18
  script:
    - npm install -g nmat-cli
    - nmat configure --url $NMAT_API_URL --key $NMAT_API_KEY
    - nmat ci-scan --target $TARGET_URL --fail-on-high
  artifacts:
    paths:
      - nmat-report.json
  only:
    - merge_requests
    - main
```

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'npm install -g nmat-cli'
                sh 'nmat configure --url ${NMAT_API_URL} --key ${NMAT_API_KEY}'
                sh 'nmat ci-scan --target ${TARGET_URL} --fail-on-high'
            }
        }
    }
    post {
        always {
            archiveArtifacts 'nmat-report.json'
        }
    }
}
```

### Docker Integration

```dockerfile
FROM node:18-alpine

RUN npm install -g nmat-cli

COPY ci-cd/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]
```

**Usage:**
```bash
docker build -t nmat-scanner .
docker run -e NMAT_API_URL=... -e NMAT_API_KEY=... \
  nmat-scanner ci-scan --target https://example.com
```

### Setup Script

Quick CI/CD integration setup:

```bash
./ci-cd/setup-integration.sh all
```

**Features:**
- Detects CI/CD platform automatically
- Installs NMAT CLI
- Generates sample configuration
- Creates platform-specific workflow files
- Sets up Docker image

---

## Enterprise Features

### Multi-Tenant Project Support

```javascript
// Create project for different teams
const projectA = await window.api.createProject({
  name: 'Team A - Web App',
  owner: 'team-a',
  team: ['alice@example.com', 'bob@example.com']
});

const projectB = await window.api.createProject({
  name: 'Team B - API',
  owner: 'team-b',
  team: ['charlie@example.com']
});

// List projects by team
const teamAProjects = await window.api.listProjects({ owner: 'team-a' });
```

### Role-Based Access Control (via API Keys)

```javascript
// Generate API keys for different purposes
const cicdKey = await window.api.generateApiKey('ci-cd-automation');
const reportingKey = await window.api.generateApiKey('reporting-only');
const devKey = await window.api.generateApiKey('dev-team');

// Each key can be revoked independently
```

### Centralized Results Aggregation

```javascript
// Get all vulnerabilities across projects
const allVulns = await window.api.getVulnerabilities({});

// Group by project
const byProject = {};
allVulns.forEach(vuln => {
  const project = vuln.projectId || 'unassigned';
  if (!byProject[project]) byProject[project] = [];
  byProject[project].push(vuln);
});
```

### Automated Scheduling

```javascript
// Schedule regular scans for compliance
const schedules = [
  {
    name: 'PCI-DSS Weekly Scan',
    cronExpression: '0 0 * * 0', // Weekly
    config: { urls: ['https://payment.example.com'] }
  },
  {
    name: 'GDPR Monthly Audit',
    cronExpression: '0 0 1 * *', // Monthly
    config: { urls: ['https://userdata.example.com'] }
  }
];

for (const schedule of schedules) {
  await window.api.createSchedule(schedule);
}
```

### Credential Storage

Projects store authentication credentials securely:

```javascript
const project = await window.api.createProject({
  name: 'Authenticated App Scan',
  sessionRules: [
    {
      name: 'Login Flow',
      actions: [
        {
          type: 'run-macro',
          macroId: 'login-macro'
        }
      ]
    }
  ],
  macros: [
    {
      id: 'login-macro',
      name: 'Login',
      requests: [
        {
          method: 'POST',
          url: 'https://app.example.com/login',
          bodyString: JSON.stringify({
            username: '{{username}}',
            password: '{{password}}'
          })
        }
      ],
      variables: {
        username: 'test-user',
        password: 'encrypted-password'
      }
    }
  ]
});
```

### Compliance Dashboards

```javascript
// Generate compliance report
const report = await window.api.generateSecurityReport({
  compliance: ['OWASP_TOP_10', 'PCI_DSS', 'GDPR']
});

// Check compliance status
console.log('OWASP Compliance:', report.compliance.OWASP_TOP_10.overallStatus);
console.log('PCI DSS Compliance:', report.compliance.PCI_DSS.overallStatus);
console.log('GDPR Compliance:', report.compliance.GDPR.overallStatus);
```

---

## Best Practices

### API Security

1. **Always use HTTPS** for API server in production
2. **Rotate API keys regularly**
3. **Use different keys** for different environments
4. **Never commit API keys** to version control
5. **Store keys in CI/CD secrets**

### Scheduling

1. **Avoid overlapping scans** - space out schedules
2. **Set appropriate timeouts** based on application size
3. **Monitor execution history** for failures
4. **Configure notifications** for critical failures
5. **Use webhooks** for real-time alerts

### Project Management

1. **Use descriptive names** for easy identification
2. **Tag projects** by environment (dev, staging, prod)
3. **Set compliance requirements** at project level
4. **Assign teams** for access control
5. **Review scan history** regularly

### CI/CD Integration

1. **Run scans on feature branches** early
2. **Use `--fail-on-high`** to enforce quality gates
3. **Archive reports** as build artifacts
4. **Send notifications** on failures
5. **Trend analysis** - track vulnerabilities over time

### Reporting

1. **Generate HTML reports** for stakeholders
2. **Use JSON reports** for automation
3. **Include compliance** sections for audits
4. **Schedule regular reports** via automation
5. **Customize report** filters for relevance

---

## Troubleshooting

### CLI Issues

**Problem:** `nmat: command not found`
**Solution:** Install globally with `npm install -g nmat-cli` or use `npx nmat`

**Problem:** API connection refused
**Solution:** Ensure REST API server is running and URL is correct

### API Server Issues

**Problem:** 401 Unauthorized
**Solution:** Check API key is valid and included in `X-API-Key` header

**Problem:** Port already in use
**Solution:** Use different port or stop conflicting service

### Scheduling Issues

**Problem:** Schedule not running
**Solution:** Verify cron expression is valid and schedule is enabled

**Problem:** Executions failing
**Solution:** Check execution history for error messages

### CI/CD Issues

**Problem:** Scan timeout in CI/CD
**Solution:** Increase `--timeout` parameter or reduce scan scope

**Problem:** Build fails unexpectedly
**Solution:** Remove `--fail-on-high` or fix vulnerabilities first

---

## Quick Reference

### CLI Commands

```bash
nmat configure                 # Configure CLI
nmat scan start --target URL   # Start scan
nmat scan results             # Get results
nmat report generate          # Generate report
nmat ci-scan --target URL     # CI/CD scan
```

### API Endpoints

```
GET  /api/health
POST /api/scan/start
GET  /api/scan/vulnerabilities
POST /api/reports/generate
```

### Cron Patterns

```
*/15 * * * *   # Every 15 minutes
0 */2 * * *    # Every 2 hours
0 9 * * *      # Daily at 9 AM
0 0 * * 0      # Weekly on Sunday
0 0 1 * *      # Monthly on 1st
```

---

## Support

For issues or questions:
- Check logs in REST API server console
- Review execution history for failed schedules
- Verify API key permissions
- Check CI/CD pipeline logs
- Consult example configurations in `ci-cd/` directory

---

**Documentation Version**: 1.0
**Last Updated**: 2025-11-13
**Features Status**: Production Ready
