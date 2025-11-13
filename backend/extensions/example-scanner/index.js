/**
 * Example Scanner Extension
 *
 * This demonstrates how to create a custom scanner extension for NMAT.
 * Scanner extensions receive URLs and request data, and return security findings.
 */
class ExampleScanner {
  constructor(api) {
    this.api = api;
    this.enabled = true;
  }

  /**
   * Called when extension is loaded
   */
  init() {
    this.api.log('Example Scanner extension initialized');
  }

  /**
   * Called when extension is enabled
   */
  enable() {
    this.enabled = true;
    this.api.log('Example Scanner enabled');
  }

  /**
   * Called when extension is disabled
   */
  disable() {
    this.enabled = false;
    this.api.log('Example Scanner disabled');
  }

  /**
   * Main scan function - called for each URL
   * @param {string} url - The URL to scan
   * @param {object} requestData - Request data including method, headers, body
   * @returns {object} - Scan results with findings array
   */
  async scan(url, requestData) {
    if (!this.enabled) return { findings: [] };

    const findings = [];

    try {
      // Example check 1: Detect debug parameters
      if (url.includes('debug=') || url.includes('test=')) {
        findings.push({
          type: 'Information Disclosure',
          severity: 'low',
          confidence: 'certain',
          title: 'Debug Parameter Detected',
          description: 'The URL contains a debug or test parameter which may leak sensitive information',
          url: url,
          evidence: this.extractDebugParams(url),
          remediation: 'Remove debug parameters from production URLs'
        });
      }

      // Example check 2: Detect API keys in URL
      const apiKeyPattern = /[?&](api_key|apikey|key)=([^&]+)/i;
      const apiKeyMatch = url.match(apiKeyPattern);
      if (apiKeyMatch) {
        findings.push({
          type: 'Sensitive Data Exposure',
          severity: 'high',
          confidence: 'firm',
          title: 'API Key in URL',
          description: 'API key detected in URL query parameters, which may be logged or cached',
          url: url,
          evidence: `Found API key parameter: ${apiKeyMatch[1]}`,
          remediation: 'Use HTTP headers (e.g., Authorization) instead of URL parameters for API keys'
        });
      }

      // Example check 3: Make additional HTTP request to check headers
      try {
        const response = await this.api.http.request({
          method: 'GET',
          url: url,
          timeout: 5000
        });

        // Check for missing security headers
        const securityHeaders = [
          'X-Content-Type-Options',
          'X-Frame-Options',
          'Strict-Transport-Security',
          'Content-Security-Policy'
        ];

        const missingHeaders = securityHeaders.filter(
          header => !response.headers[header.toLowerCase()]
        );

        if (missingHeaders.length > 0) {
          findings.push({
            type: 'Security Misconfiguration',
            severity: 'medium',
            confidence: 'certain',
            title: 'Missing Security Headers',
            description: `The following security headers are missing: ${missingHeaders.join(', ')}`,
            url: url,
            evidence: `Missing headers: ${missingHeaders.join(', ')}`,
            remediation: 'Add recommended security headers to HTTP responses'
          });
        }
      } catch (error) {
        // Request failed, skip this check
        this.api.warn(`Failed to check security headers for ${url}: ${error.message}`);
      }

      // Store scan results in extension storage
      const previousScans = this.api.storage.get('scan_count') || 0;
      this.api.storage.set('scan_count', previousScans + 1);

      if (findings.length > 0) {
        this.api.ui.notify(`Found ${findings.length} issue(s) in ${url}`, 'warning');
      }

    } catch (error) {
      this.api.error(`Scan error: ${error.message}`);
    }

    return { findings };
  }

  /**
   * Helper: Extract debug parameters
   */
  extractDebugParams(url) {
    const debugParams = [];
    const urlObj = new URL(url);

    for (const [key, value] of urlObj.searchParams) {
      if (key.toLowerCase().includes('debug') || key.toLowerCase().includes('test')) {
        debugParams.push(`${key}=${value}`);
      }
    }

    return debugParams.join(', ');
  }

  /**
   * Called when extension is unloaded
   */
  cleanup() {
    this.api.log('Example Scanner cleaned up');
    const totalScans = this.api.storage.get('scan_count') || 0;
    this.api.log(`Total scans performed: ${totalScans}`);
  }
}

module.exports = ExampleScanner;
