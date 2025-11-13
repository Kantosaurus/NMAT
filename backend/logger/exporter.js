const fs = require('fs');
const path = require('path');
const { dialog } = require('electron');

/**
 * Logger Exporter - Export HTTP history in various formats
 * Supports JSON, CSV, XML, HAR, and Burp XML formats
 */
class LoggerExporter {
  constructor(mainWindow) {
    this.mainWindow = mainWindow;
  }

  /**
   * Export history items to JSON format
   */
  exportToJSON(items) {
    return JSON.stringify(items, null, 2);
  }

  /**
   * Export history items to CSV format
   */
  exportToCSV(items) {
    const headers = [
      'ID',
      'Timestamp',
      'Method',
      'URL',
      'Status Code',
      'Status Message',
      'Response Time (ms)',
      'Response Length',
      'Source'
    ];

    const rows = items.map(item => {
      return [
        item.id || '',
        new Date(item.timestamp).toISOString(),
        item.method || '',
        this.escapeCsv(item.url || ''),
        item.response?.statusCode || '',
        this.escapeCsv(item.response?.statusMessage || ''),
        item.response?.time || '',
        item.response?.length || '',
        item.source || 'proxy'
      ];
    });

    return [
      headers.join(','),
      ...rows.map(row => row.join(','))
    ].join('\n');
  }

  /**
   * Export history items to XML format
   */
  exportToXML(items) {
    const xmlItems = items.map(item => {
      const request = this.escapeXml(JSON.stringify(item.request || {}));
      const response = this.escapeXml(JSON.stringify(item.response || {}));

      return `  <item>
    <id>${item.id || ''}</id>
    <timestamp>${item.timestamp || ''}</timestamp>
    <method>${this.escapeXml(item.method || '')}</method>
    <url>${this.escapeXml(item.url || '')}</url>
    <source>${this.escapeXml(item.source || 'proxy')}</source>
    <request>${request}</request>
    <response>${response}</response>
  </item>`;
    }).join('\n');

    return `<?xml version="1.0" encoding="UTF-8"?>
<history>
${xmlItems}
</history>`;
  }

  /**
   * Export history items to HAR (HTTP Archive) format
   * Compatible with Chrome DevTools and other HAR viewers
   */
  exportToHAR(items) {
    const entries = items.map(item => {
      const request = item.request || {};
      const response = item.response || {};

      return {
        startedDateTime: new Date(item.timestamp).toISOString(),
        time: response.time || 0,
        request: {
          method: item.method || 'GET',
          url: item.url || '',
          httpVersion: 'HTTP/1.1',
          cookies: this.parseCookies(request.headers?.Cookie),
          headers: this.convertHeadersToHAR(request.headers),
          queryString: this.parseQueryString(item.url),
          postData: request.bodyString ? {
            mimeType: request.headers?.['Content-Type'] || 'application/octet-stream',
            text: request.bodyString
          } : undefined,
          headersSize: -1,
          bodySize: request.bodyString ? request.bodyString.length : 0
        },
        response: {
          status: response.statusCode || 0,
          statusText: response.statusMessage || '',
          httpVersion: 'HTTP/1.1',
          cookies: this.parseCookies(response.headers?.['set-cookie']),
          headers: this.convertHeadersToHAR(response.headers),
          content: {
            size: response.length || 0,
            mimeType: response.headers?.['content-type'] || 'application/octet-stream',
            text: response.bodyString || ''
          },
          redirectURL: response.headers?.location || '',
          headersSize: -1,
          bodySize: response.length || 0
        },
        cache: {},
        timings: {
          send: 0,
          wait: response.time || 0,
          receive: 0
        }
      };
    });

    return JSON.stringify({
      log: {
        version: '1.2',
        creator: {
          name: 'NMAT',
          version: '1.0.0'
        },
        entries: entries
      }
    }, null, 2);
  }

  /**
   * Export history items to Burp XML format
   * Compatible with Burp Suite for importing into other projects
   */
  exportToBurpXML(items) {
    const xmlItems = items.map(item => {
      const request = item.request || {};
      const response = item.response || {};

      // Build request string
      const requestLine = `${item.method || 'GET'} ${this.getPathFromUrl(item.url)} HTTP/1.1`;
      const requestHeaders = this.buildHeadersString(request.headers);
      const requestBody = request.bodyString || '';
      const fullRequest = `${requestLine}\r\n${requestHeaders}\r\n\r\n${requestBody}`;

      // Build response string
      const responseLine = `HTTP/1.1 ${response.statusCode || 200} ${response.statusMessage || 'OK'}`;
      const responseHeaders = this.buildHeadersString(response.headers);
      const responseBody = response.bodyString || '';
      const fullResponse = `${responseLine}\r\n${responseHeaders}\r\n\r\n${responseBody}`;

      const urlObj = new URL(item.url || 'http://example.com');

      return `  <item>
    <time>${new Date(item.timestamp).toISOString()}</time>
    <url>${this.escapeXml(item.url || '')}</url>
    <host ip="">${this.escapeXml(urlObj.hostname)}</host>
    <port>${urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80)}</port>
    <protocol>${urlObj.protocol.replace(':', '')}</protocol>
    <method>${this.escapeXml(item.method || 'GET')}</method>
    <path>${this.escapeXml(urlObj.pathname + urlObj.search)}</path>
    <extension>${this.getExtension(urlObj.pathname)}</extension>
    <request base64="false"><![CDATA[${fullRequest}]]></request>
    <status>${response.statusCode || 200}</status>
    <responselength>${response.length || 0}</responselength>
    <mimetype>${this.escapeXml(response.headers?.['content-type'] || '')}</mimetype>
    <response base64="false"><![CDATA[${fullResponse}]]></response>
    <comment></comment>
  </item>`;
    }).join('\n');

    return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>
<!ELEMENT time (#PCDATA)>
<!ELEMENT url (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT port (#PCDATA)>
<!ELEMENT protocol (#PCDATA)>
<!ELEMENT method (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT extension (#PCDATA)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request base64 (true|false) "false">
<!ELEMENT status (#PCDATA)>
<!ELEMENT responselength (#PCDATA)>
<!ELEMENT mimetype (#PCDATA)>
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 (true|false) "false">
<!ELEMENT comment (#PCDATA)>
]>
<items burpVersion="2023.1" exportTime="${new Date().toISOString()}">
${xmlItems}
</items>`;
  }

  /**
   * Show save dialog and export history
   */
  async export(items, format = 'json') {
    try {
      const formatExtensions = {
        json: 'json',
        csv: 'csv',
        xml: 'xml',
        har: 'har',
        burp: 'xml'
      };

      const formatNames = {
        json: 'JSON',
        csv: 'CSV',
        xml: 'XML',
        har: 'HAR (HTTP Archive)',
        burp: 'Burp XML'
      };

      const extension = formatExtensions[format] || 'txt';
      const formatName = formatNames[format] || 'Text';

      const result = await dialog.showSaveDialog(this.mainWindow, {
        title: 'Export HTTP History',
        defaultPath: `http-history-${Date.now()}.${extension}`,
        filters: [
          { name: formatName, extensions: [extension] },
          { name: 'All Files', extensions: ['*'] }
        ]
      });

      if (result.canceled || !result.filePath) {
        return { success: false, error: 'Export cancelled' };
      }

      let content;
      switch (format) {
        case 'json':
          content = this.exportToJSON(items);
          break;
        case 'csv':
          content = this.exportToCSV(items);
          break;
        case 'xml':
          content = this.exportToXML(items);
          break;
        case 'har':
          content = this.exportToHAR(items);
          break;
        case 'burp':
          content = this.exportToBurpXML(items);
          break;
        default:
          return { success: false, error: 'Unsupported format' };
      }

      fs.writeFileSync(result.filePath, content, 'utf-8');

      return {
        success: true,
        filepath: result.filePath,
        itemCount: items.length,
        format
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Helper: Escape CSV values
   */
  escapeCsv(value) {
    if (typeof value !== 'string') value = String(value);
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  }

  /**
   * Helper: Escape XML special characters
   */
  escapeXml(value) {
    if (typeof value !== 'string') value = String(value);
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  /**
   * Helper: Parse cookies from header string
   */
  parseCookies(cookieHeader) {
    if (!cookieHeader) return [];
    const cookieStrings = Array.isArray(cookieHeader) ? cookieHeader : [cookieHeader];
    return cookieStrings.flatMap(str =>
      str.split(';').map(cookie => {
        const [name, ...valueParts] = cookie.trim().split('=');
        return { name: name.trim(), value: valueParts.join('=').trim() };
      })
    );
  }

  /**
   * Helper: Convert headers object to HAR format array
   */
  convertHeadersToHAR(headers) {
    if (!headers) return [];
    return Object.entries(headers).map(([name, value]) => ({
      name,
      value: Array.isArray(value) ? value.join(', ') : String(value)
    }));
  }

  /**
   * Helper: Parse query string from URL
   */
  parseQueryString(url) {
    try {
      const urlObj = new URL(url);
      const params = [];
      urlObj.searchParams.forEach((value, name) => {
        params.push({ name, value });
      });
      return params;
    } catch {
      return [];
    }
  }

  /**
   * Helper: Build headers string from object
   */
  buildHeadersString(headers) {
    if (!headers) return '';
    return Object.entries(headers)
      .map(([name, value]) => `${name}: ${value}`)
      .join('\r\n');
  }

  /**
   * Helper: Get path from URL
   */
  getPathFromUrl(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.pathname + urlObj.search;
    } catch {
      return '/';
    }
  }

  /**
   * Helper: Get file extension from path
   */
  getExtension(pathname) {
    const ext = path.extname(pathname);
    return ext ? ext.substring(1) : '';
  }
}

module.exports = LoggerExporter;
