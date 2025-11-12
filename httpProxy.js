const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const { URL } = require('url');
const EventEmitter = require('events');
const forge = require('node-forge');

class HTTPProxy extends EventEmitter {
  constructor(port = 8080) {
    super();
    this.port = port;
    this.server = null;
    this.interceptEnabled = false;
    this.interceptQueue = [];
    this.history = [];
    this.requestId = 0;
    this.caCert = null;
    this.caKey = null;
    this.certCache = new Map();
    this.certInstalled = false;
    this.certPath = null;
  }

  generateCACertificate() {
    console.log('Generating new CA certificate for this session...');

    // Generate a keypair for the CA
    const keys = forge.pki.rsa.generateKeyPair(2048);

    // Create a certificate with random serial for anonymity
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = Math.floor(Math.random() * 1000000000).toString();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1); // 1 year validity

    // Use randomized organization name for anonymity
    const randomId = Math.random().toString(36).substring(2, 8).toUpperCase();
    const attrs = [{
      name: 'commonName',
      value: `Local Proxy CA ${randomId}`
    }, {
      name: 'countryName',
      value: 'US'
    }, {
      shortName: 'ST',
      value: 'State'
    }, {
      name: 'localityName',
      value: 'City'
    }, {
      name: 'organizationName',
      value: `LocalDev ${randomId}`
    }, {
      shortName: 'OU',
      value: 'Development'
    }];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([{
      name: 'basicConstraints',
      cA: true
    }, {
      name: 'keyUsage',
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true
    }]);

    // Self-sign certificate
    cert.sign(keys.privateKey, forge.md.sha256.create());

    this.caCert = cert;
    this.caKey = keys.privateKey;
    this.certCache.clear(); // Clear cached certificates

    console.log('CA Certificate generated with serial:', cert.serialNumber);
  }

  async installCACertificate() {
    const fs = require('fs');
    const path = require('path');
    const { execFile } = require('child_process');
    const { promisify } = require('util');
    const execFileAsync = promisify(execFile);

    try {
      const caCertPem = forge.pki.certificateToPem(this.caCert);

      // Use temp directory with random name for anonymity
      const os = require('os');
      const tempDir = os.tmpdir();
      const randomName = `cert_${Math.random().toString(36).substring(2, 10)}.pem`;
      this.certPath = path.join(tempDir, randomName);

      fs.writeFileSync(this.certPath, caCertPem);
      console.log('Certificate written to:', this.certPath);

      const platform = process.platform;

      if (platform === 'win32') {
        // Windows: Use certutil to install certificate
        console.log('Installing certificate to Windows trust store...');
        try {
          await execFileAsync('certutil', ['-addstore', '-user', 'Root', this.certPath]);
          console.log('✓ Certificate installed successfully to Windows trust store');
          this.certInstalled = true;
        } catch (error) {
          console.error('Failed to auto-install certificate. Error:', error.message);
          console.log('You may need to run as Administrator or install manually.');
          console.log('Run this command manually: certutil -addstore -user Root "' + this.certPath + '"');
        }
      } else if (platform === 'darwin') {
        // macOS: Use security command to install certificate
        console.log('Installing certificate to macOS Keychain...');
        try {
          await execFileAsync('sudo', ['security', 'add-trusted-cert', '-d', '-r', 'trustRoot', '-k', '/Library/Keychains/System.keychain', this.certPath]);
          console.log('✓ Certificate installed successfully to macOS Keychain');
          this.certInstalled = true;
        } catch (error) {
          console.error('Failed to auto-install certificate. Error:', error.message);
          console.log('Run this command manually:');
          console.log('sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "' + this.certPath + '"');
        }
      } else if (platform === 'linux') {
        // Linux: Copy to ca-certificates and update
        console.log('Installing certificate to Linux trust store...');
        try {
          const destPath = `/usr/local/share/ca-certificates/${randomName.replace('.pem', '.crt')}`;
          await execFileAsync('sudo', ['cp', this.certPath, destPath]);
          await execFileAsync('sudo', ['update-ca-certificates']);
          console.log('✓ Certificate installed successfully to Linux trust store');
          this.certInstalled = true;
        } catch (error) {
          console.error('Failed to auto-install certificate. Error:', error.message);
          console.log('Run these commands manually:');
          console.log('sudo cp "' + this.certPath + '" /usr/local/share/ca-certificates/');
          console.log('sudo update-ca-certificates');
        }
      }

      if (this.certInstalled) {
        console.log('');
        console.log('='.repeat(70));
        console.log('HTTPS interception is now enabled!');
        console.log('Certificate will be automatically removed when proxy stops.');
        console.log('='.repeat(70));
        console.log('');
      }

    } catch (error) {
      console.error('Failed to install CA certificate:', error.message);
    }
  }

  async uninstallCACertificate() {
    if (!this.certInstalled || !this.certPath) {
      return;
    }

    const fs = require('fs');
    const { execFile } = require('child_process');
    const { promisify } = require('util');
    const execFileAsync = promisify(execFile);

    try {
      const platform = process.platform;
      console.log('Removing installed certificate...');

      if (platform === 'win32') {
        // Windows: Remove from certificate store
        const certName = `Local Proxy CA`;
        try {
          await execFileAsync('certutil', ['-delstore', '-user', 'Root', certName]);
          console.log('✓ Certificate removed from Windows trust store');
        } catch (error) {
          console.log('Note: Certificate may need manual removal from Windows Certificate Manager');
        }
      } else if (platform === 'darwin') {
        // macOS: Remove from keychain
        try {
          await execFileAsync('sudo', ['security', 'delete-certificate', '-c', 'Local Proxy CA', '/Library/Keychains/System.keychain']);
          console.log('✓ Certificate removed from macOS Keychain');
        } catch (error) {
          console.log('Note: Certificate may need manual removal from Keychain Access');
        }
      } else if (platform === 'linux') {
        // Linux: Remove from ca-certificates
        const path = require('path');
        const certFileName = path.basename(this.certPath).replace('.pem', '.crt');
        try {
          await execFileAsync('sudo', ['rm', `/usr/local/share/ca-certificates/${certFileName}`]);
          await execFileAsync('sudo', ['update-ca-certificates', '--fresh']);
          console.log('✓ Certificate removed from Linux trust store');
        } catch (error) {
          console.log('Note: Certificate may need manual removal');
        }
      }

      // Delete temp file
      if (fs.existsSync(this.certPath)) {
        fs.unlinkSync(this.certPath);
      }

      this.certInstalled = false;
      this.certPath = null;

    } catch (error) {
      console.error('Error during certificate cleanup:', error.message);
    }
  }

  generateCertificateForHostname(hostname) {
    // Check cache first
    if (this.certCache.has(hostname)) {
      return this.certCache.get(hostname);
    }

    // Generate a keypair for this domain
    const keys = forge.pki.rsa.generateKeyPair(2048);

    // Create a certificate
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = Math.floor(Math.random() * 100000).toString();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [{
      name: 'commonName',
      value: hostname
    }];

    cert.setSubject(attrs);
    cert.setIssuer(this.caCert.subject.attributes);

    cert.setExtensions([{
      name: 'subjectAltName',
      altNames: [{
        type: 2, // DNS
        value: hostname
      }]
    }, {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true
    }, {
      name: 'extKeyUsage',
      serverAuth: true
    }]);

    // Sign with CA
    cert.sign(this.caKey, forge.md.sha256.create());

    const certPem = forge.pki.certificateToPem(cert);
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

    const result = { cert: certPem, key: keyPem };
    this.certCache.set(hostname, result);

    return result;
  }

  async start() {
    // Generate a new CA certificate for this session (anonymity)
    this.generateCACertificate();

    // Automatically install the certificate BEFORE starting server
    await this.installCACertificate();

    // Signal that certificate is ready (so Electron can reinit session)
    if (this.certInstalled) {
      this.emit('cert-ready');
    }

    this.server = http.createServer((req, res) => {
      this.handleHTTPRequest(req, res);
    });

    // Handle HTTPS CONNECT method
    this.server.on('connect', (req, clientSocket, head) => {
      this.handleHTTPSConnect(req, clientSocket, head);
    });

    this.server.listen(this.port, () => {
      console.log(`HTTP Proxy listening on port ${this.port}`);
      this.emit('started', this.port);
    });

    this.server.on('error', (error) => {
      this.emit('error', error);
    });
  }

  async stop() {
    if (this.server) {
      this.server.close(async () => {
        console.log('HTTP Proxy stopped');

        // Remove the certificate from system trust store
        await this.uninstallCACertificate();

        this.emit('stopped');
      });
    }
  }

  setIntercept(enabled) {
    this.interceptEnabled = enabled;
    this.emit('intercept-changed', enabled);
  }

  async handleHTTPRequest(clientReq, clientRes) {
    const requestId = ++this.requestId;
    const startTime = Date.now();

    // Parse request
    const requestData = {
      id: requestId,
      method: clientReq.method,
      url: clientReq.url,
      httpVersion: clientReq.httpVersion,
      headers: { ...clientReq.headers },
      timestamp: new Date().toISOString(),
      protocol: 'HTTP'
    };

    // Collect body
    const bodyChunks = [];
    clientReq.on('data', chunk => bodyChunks.push(chunk));

    await new Promise((resolve) => {
      clientReq.on('end', () => {
        requestData.body = Buffer.concat(bodyChunks);
        requestData.bodyString = requestData.body.toString('utf-8');
        resolve();
      });
    });

    // Check if intercept is enabled
    if (this.interceptEnabled) {
      const result = await this.interceptRequest(requestData);
      if (result.action === 'drop') {
        clientRes.writeHead(200);
        clientRes.end('Request dropped by proxy');
        return;
      }
      if (result.action === 'forward') {
        requestData.method = result.request.method;
        requestData.url = result.request.url;
        requestData.headers = result.request.headers;
        requestData.body = Buffer.from(result.request.bodyString || '');
      }
    }

    // Forward request
    try {
      const targetUrl = new URL(requestData.url);

      const options = {
        hostname: targetUrl.hostname,
        port: targetUrl.port || 80,
        path: targetUrl.pathname + targetUrl.search,
        method: requestData.method,
        headers: requestData.headers
      };

      const proxyReq = http.request(options, (proxyRes) => {
        const responseChunks = [];
        proxyRes.on('data', chunk => responseChunks.push(chunk));
        proxyRes.on('end', () => {
          const responseBody = Buffer.concat(responseChunks);

          const responseData = {
            id: requestId,
            statusCode: proxyRes.statusCode,
            statusMessage: proxyRes.statusMessage,
            headers: { ...proxyRes.headers },
            body: responseBody,
            bodyString: responseBody.toString('utf-8'),
            length: responseBody.length,
            time: Date.now() - startTime
          };

          // Add to history
          this.addToHistory({
            ...requestData,
            response: responseData
          });

          // Forward response to client
          clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
          clientRes.end(responseBody);
        });
      });

      proxyReq.on('error', (error) => {
        console.error('Proxy request error:', error);
        clientRes.writeHead(502);
        clientRes.end('Bad Gateway');
      });

      if (requestData.body.length > 0) {
        proxyReq.write(requestData.body);
      }
      proxyReq.end();

    } catch (error) {
      console.error('Request handling error:', error);
      clientRes.writeHead(500);
      clientRes.end('Internal Proxy Error');
    }
  }

  handleHTTPSConnect(req, clientSocket, head) {
    const { port, hostname } = new URL(`https://${req.url}`);

    // Generate a fake certificate for this hostname
    const fakeCert = this.generateCertificateForHostname(hostname);

    // Tell the client the connection is established
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n', () => {
      // After the response is fully sent, start TLS
      try {
        const tlsOptions = {
          key: fakeCert.key,
          cert: fakeCert.cert,
          rejectUnauthorized: false,
          requestCert: false,
          honorCipherOrder: true,
          secureOptions: require('constants').SSL_OP_NO_TLSv1 | require('constants').SSL_OP_NO_TLSv1_1
        };

        // Create a secure socket wrapper
        const tlsSocket = new tls.TLSSocket(clientSocket, {
          isServer: true,
          ...tlsOptions
        });

        // Handle any TLS handshake errors
        tlsSocket.on('error', (error) => {
          console.error(`TLS handshake error for ${hostname}:`, error.message);
          try {
            tlsSocket.destroy();
          } catch (e) {
            // Already destroyed
          }
        });

        // Once TLS handshake is complete, handle the connection
        tlsSocket.on('secure', () => {
          this.handleTLSConnection(tlsSocket, hostname, port || 443);
        });

      } catch (error) {
        console.error('Failed to create TLS socket:', error);
        clientSocket.destroy();
      }
    });
  }

  handleTLSConnection(tlsSocket, hostname, port) {

    // Buffer to collect the decrypted HTTPS request
    let buffer = Buffer.alloc(0);

    tlsSocket.on('data', async (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);

      // Try to parse the HTTP request from the buffer
      const bufferStr = buffer.toString('utf-8');
      const headerEndIndex = bufferStr.indexOf('\r\n\r\n');

      if (headerEndIndex === -1) {
        // Headers not complete yet, wait for more data
        return;
      }

      // Parse the request
      const headerStr = bufferStr.substring(0, headerEndIndex);
      const lines = headerStr.split('\r\n');
      const [method, path, httpVersion] = lines[0].split(' ');

      const headers = {};
      for (let i = 1; i < lines.length; i++) {
        const colonIndex = lines[i].indexOf(':');
        if (colonIndex !== -1) {
          const headerName = lines[i].substring(0, colonIndex).trim();
          const headerValue = lines[i].substring(colonIndex + 1).trim();
          headers[headerName.toLowerCase()] = headerValue;
        }
      }

      // Get body if present
      const bodyStartIndex = headerEndIndex + 4;
      const bodyBuffer = buffer.slice(bodyStartIndex);

      // Check if we have the complete body based on Content-Length
      const contentLength = parseInt(headers['content-length'] || '0', 10);
      if (bodyBuffer.length < contentLength) {
        // Body not complete yet, wait for more data
        return;
      }

      const requestId = ++this.requestId;
      const fullUrl = `https://${hostname}${path}`;

      // Only use the exact amount of body bytes specified by Content-Length
      const requestBody = bodyBuffer.slice(0, contentLength);

      const requestData = {
        id: requestId,
        method: method,
        url: fullUrl,
        path: path,
        httpVersion: httpVersion,
        headers: headers,
        body: requestBody,
        bodyString: requestBody.toString('utf-8'),
        timestamp: new Date().toISOString(),
        protocol: 'HTTPS',
        hostname: hostname
      };

      // Reset buffer, keeping any data after this request for the next request
      buffer = bodyBuffer.slice(contentLength);

      // Check if intercept is enabled
      if (this.interceptEnabled) {
        const result = await this.interceptRequest(requestData);
        if (result.action === 'drop') {
          tlsSocket.write('HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\nRequest dropped by proxy');
          tlsSocket.end();
          return;
        }
        if (result.action === 'forward') {
          requestData.method = result.request.method;
          requestData.url = result.request.url;
          requestData.path = result.request.path || path;
          requestData.headers = result.request.headers;
          requestData.body = Buffer.from(result.request.bodyString || '');
        }
      }

      // Forward the request to the real server
      const startTime = Date.now();

      try {
        const targetUrl = new URL(requestData.url);

        const options = {
          hostname: targetUrl.hostname,
          port: targetUrl.port || 443,
          path: targetUrl.pathname + targetUrl.search,
          method: requestData.method,
          headers: requestData.headers,
          rejectUnauthorized: false
        };

        const proxyReq = https.request(options, (proxyRes) => {
          const responseChunks = [];
          proxyRes.on('data', chunk => responseChunks.push(chunk));
          proxyRes.on('end', () => {
            const responseBody = Buffer.concat(responseChunks);

            const responseData = {
              id: requestId,
              statusCode: proxyRes.statusCode,
              statusMessage: proxyRes.statusMessage,
              headers: { ...proxyRes.headers },
              body: responseBody,
              bodyString: responseBody.toString('utf-8'),
              length: responseBody.length,
              time: Date.now() - startTime
            };

            // Add to history
            this.addToHistory({
              ...requestData,
              response: responseData
            });

            // Forward response to client
            let responseStr = `HTTP/1.1 ${proxyRes.statusCode} ${proxyRes.statusMessage}\r\n`;
            for (const [key, value] of Object.entries(proxyRes.headers)) {
              responseStr += `${key}: ${value}\r\n`;
            }
            responseStr += '\r\n';

            tlsSocket.write(responseStr);
            tlsSocket.write(responseBody);
            tlsSocket.end();
          });
        });

        proxyReq.on('error', (error) => {
          console.error('HTTPS proxy request error:', error);
          tlsSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
          tlsSocket.end();
        });

        if (requestData.body.length > 0) {
          proxyReq.write(requestData.body);
        }
        proxyReq.end();

      } catch (error) {
        console.error('HTTPS request handling error:', error);
        tlsSocket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
        tlsSocket.end();
      }
    });

    tlsSocket.on('error', (error) => {
      console.error(`TLS socket error for ${hostname}:`, error.message);
      try {
        tlsSocket.destroy();
      } catch (e) {
        // Socket already destroyed
      }
    });

    tlsSocket.on('end', () => {
      tlsSocket.end();
    });
  }

  interceptRequest(requestData) {
    return new Promise((resolve) => {
      const interceptItem = {
        ...requestData,
        resolve
      };

      this.interceptQueue.push(interceptItem);
      this.emit('intercept', interceptItem);
    });
  }

  forwardIntercept(id, modifiedRequest) {
    const item = this.interceptQueue.find(i => i.id === id);
    if (item) {
      item.resolve({ action: 'forward', request: modifiedRequest });
      this.interceptQueue = this.interceptQueue.filter(i => i.id !== id);
    }
  }

  dropIntercept(id) {
    const item = this.interceptQueue.find(i => i.id === id);
    if (item) {
      item.resolve({ action: 'drop' });
      this.interceptQueue = this.interceptQueue.filter(i => i.id !== id);
    }
  }

  addToHistory(item) {
    this.history.push(item);

    // Limit history to 1000 items
    if (this.history.length > 1000) {
      this.history.shift();
    }

    this.emit('history-update', item);
  }

  getHistory() {
    return this.history;
  }

  clearHistory() {
    this.history = [];
    this.emit('history-cleared');
  }

  // Repeater: Resend a request
  async repeatRequest(requestData) {
    const repeatedId = ++this.requestId;
    const startTime = Date.now();

    try {
      const targetUrl = new URL(requestData.url);

      const options = {
        hostname: targetUrl.hostname,
        port: targetUrl.port || 80,
        path: targetUrl.pathname + targetUrl.search,
        method: requestData.method,
        headers: requestData.headers
      };

      return new Promise((resolve, reject) => {
        const proxyReq = http.request(options, (proxyRes) => {
          const responseChunks = [];
          proxyRes.on('data', chunk => responseChunks.push(chunk));
          proxyRes.on('end', () => {
            const responseBody = Buffer.concat(responseChunks);

            resolve({
              id: repeatedId,
              request: requestData,
              response: {
                statusCode: proxyRes.statusCode,
                statusMessage: proxyRes.statusMessage,
                headers: { ...proxyRes.headers },
                body: responseBody,
                bodyString: responseBody.toString('utf-8'),
                length: responseBody.length,
                time: Date.now() - startTime
              }
            });
          });
        });

        proxyReq.on('error', reject);

        if (requestData.bodyString) {
          proxyReq.write(requestData.bodyString);
        }
        proxyReq.end();
      });

    } catch (error) {
      throw error;
    }
  }

  // Intruder: Fuzz a request with payloads
  async intruderAttack(requestData, positions, payloads, attackType = 'sniper') {
    const results = [];

    if (attackType === 'sniper') {
      // Sniper: One position at a time, one payload at a time
      for (const payload of payloads) {
        for (const position of positions) {
          const modifiedRequest = this.replacePosition(requestData, position, payload);
          const result = await this.repeatRequest(modifiedRequest);
          results.push({
            payload,
            position,
            ...result
          });

          this.emit('intruder-progress', {
            current: results.length,
            total: positions.length * payloads.length
          });
        }
      }
    } else if (attackType === 'battering-ram') {
      // Battering Ram: All positions get same payload
      for (const payload of payloads) {
        let modifiedRequest = { ...requestData };
        for (const position of positions) {
          modifiedRequest = this.replacePosition(modifiedRequest, position, payload);
        }
        const result = await this.repeatRequest(modifiedRequest);
        results.push({
          payload,
          ...result
        });

        this.emit('intruder-progress', {
          current: results.length,
          total: payloads.length
        });
      }
    }

    return results;
  }

  replacePosition(requestData, position, payload) {
    const modified = { ...requestData };

    if (position.type === 'body') {
      modified.bodyString = modified.bodyString.replace(position.marker, payload);
    } else if (position.type === 'header') {
      modified.headers[position.headerName] = modified.headers[position.headerName].replace(position.marker, payload);
    } else if (position.type === 'url') {
      modified.url = modified.url.replace(position.marker, payload);
    }

    return modified;
  }
}

module.exports = HTTPProxy;
