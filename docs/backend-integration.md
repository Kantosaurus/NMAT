# Backend Integration Guide

This guide explains how to integrate the newly created backend modules into your existing NMAT application.

## Overview

The backend architecture has been implemented with the following components:

- **Database Layer** (`backend/database/index.js`): SQLite database for persistent storage
- **Repeater** (`backend/proxy/repeater.js`): HTTP request replay functionality
- **Spider** (`backend/spider/index.js`): Web crawler with JavaScript rendering support
- **Scanner** (`backend/scanner/index.js`): Vulnerability scanner with 21 vulnerability types
- **Intruder** (`backend/intruder/index.js`): Fuzzing and attack automation engine
- **Sequencer** (`backend/sequencer/index.js`): Token randomness analysis
- **Decoder** (`backend/decoder/index.js`): Encoding/decoding utilities
- **Backend Manager** (`backend/proxy-backend.js`): Central IPC handler registration

## Step 1: Install Dependencies

Run the following command to install all required dependencies:

```bash
npm install
```

New dependencies added:
- `axios`: HTTP client for repeater and scanner
- `better-sqlite3`: Fast SQLite database
- `cheerio`: HTML parsing for spider
- `puppeteer`: Headless browser for JavaScript-aware crawling

## Step 2: Update main.js

Add the following import at the top of `main.js`:

```javascript
const ProxyBackend = require('./backend/proxy-backend');
```

Add a variable to hold the backend instance after the other variable declarations (around line 16):

```javascript
let proxyBackend;
```

Initialize the backend in the `app.whenReady()` block, right after `createWindow()` (around line 97):

```javascript
app.whenReady().then(() => {
  // ... existing code ...

  createWindow();

  // Initialize proxy backend
  proxyBackend = new ProxyBackend(mainWindow);

  // ... rest of existing code ...
});
```

Update the window close handler to clean up the backend (around line 69):

```javascript
mainWindow.on('closed', () => {
  if (packetCapture) {
    packetCapture.stop();
  }
  if (httpProxy) {
    httpProxy.stop();
  }
  if (proxyBackend) {
    proxyBackend.close();
  }
  mainWindow = null;
});
```

## Step 3: Update Existing HTTP Proxy Integration

If you're using the existing `httpProxy.js`, you can integrate it with the backend to save history:

In the existing proxy event handlers (if any), add history logging:

```javascript
// Example: When proxy captures a request/response
httpProxy.on('request-completed', (item) => {
  if (proxyBackend) {
    proxyBackend.addHistoryItem(item);
  }
});
```

## Step 4: Verify IPC Handlers

The following IPC handlers are now registered via `ProxyBackend`:

### Repeater
- `repeat-request` - Send HTTP requests

### Spider
- `start-spider` - Start web crawling
- `stop-spider` - Stop crawling
- `get-discovered-endpoints` - Get discovered URLs

### Scanner
- `start-scan` - Start vulnerability scan
- `stop-scan` - Stop scanning
- `get-vulnerabilities` - Get found vulnerabilities
- `get-scan-policies` - Get scan policies

### Intruder
- `start-intruder-attack` - Start fuzzing attack
- `stop-intruder-attack` - Stop attack
- `get-intruder-results` - Get attack results

### Sequencer
- `analyze-tokens` - Analyze token randomness

### Decoder
- `encode-text` - Encode text
- `decode-text` - Decode text
- `apply-transformation-chain` - Apply multiple transformations
- `detect-encoding` - Auto-detect encoding

### Comparer
- `compare-texts` - Compare two texts

### Settings
- `get-proxy-settings` - Get proxy configuration
- `update-proxy-settings` - Update proxy configuration
- `get-scope-rules` - Get scope rules
- `add-scope-rule` - Add scope rule
- `delete-scope-rule` - Delete scope rule
- `get-match-replace-rules` - Get match/replace rules
- `add-match-replace-rule` - Add rule
- `delete-match-replace-rule` - Delete rule

### History
- `get-proxy-history` - Get HTTP history with filters
- `clear-proxy-history` - Clear all history

## Step 5: Event Listeners

The backend emits the following events to the renderer:

### Spider Events
- `spider-started` - Spider has started
- `spider-progress` - Progress update with stats
- `spider-endpoint-discovered` - New endpoint found
- `spider-completed` - Spider finished
- `spider-stopped` - Spider was stopped

### Scanner Events
- `scan-started` - Scan has started
- `scan-progress` - Progress update
- `vulnerability-found` - New vulnerability discovered
- `scan-completed` - Scan finished
- `scan-stopped` - Scan was stopped

### Intruder Events
- `intruder-progress` - Attack progress update
- `intruder-result` - Individual result
- `intruder-completed` - Attack finished

### Proxy Events
- `proxy-history-update` - New history item added

## Step 6: Database Location

The SQLite database is created at:
```
{userData}/nmat-proxy.db
```

Where `{userData}` is the Electron app's user data directory:
- Windows: `C:\Users\{username}\AppData\Roaming\network-monitor-analysis-tool`
- macOS: `~/Library/Application Support/network-monitor-analysis-tool`
- Linux: `~/.config/network-monitor-analysis-tool`

## Step 7: Testing the Integration

After integration, you can test each module:

### Test Repeater
```javascript
const response = await window.api.repeatRequest({
  method: 'GET',
  url: 'https://example.com',
  headers: {},
  bodyString: ''
});
```

### Test Spider
```javascript
await window.api.startSpider({
  maxDepth: 3,
  maxRequests: 100,
  javascriptRendering: false
}, ['https://example.com']);

window.api.onSpiderEndpointDiscovered((endpoint) => {
  console.log('Discovered:', endpoint.url);
});
```

### Test Scanner
```javascript
await window.api.startScan({
  activeScanning: true,
  passiveScanning: true
}, ['https://example.com'], {
  vulnerabilityChecks: { sqlInjection: true, xssReflected: true }
});

window.api.onVulnerabilityFound((vuln) => {
  console.log('Vulnerability:', vuln.vulnerabilityType);
});
```

### Test Sequencer
```javascript
const tokens = ['abc123', 'def456', 'ghi789'];
const analysis = await window.api.analyzeTokens(tokens);
console.log('Entropy:', analysis.estimatedEntropy.shannon);
```

### Test Decoder
```javascript
const encoded = await window.api.encodeText('Hello World', 'base64', 'encode');
const decoded = await window.api.decodeText(encoded.result, 'base64');
```

## Step 8: Error Handling

All IPC handlers return responses in the format:
```javascript
{
  success: true,
  result: /* data */
}
// or
{
  success: false,
  error: /* error message */
}
```

Always check the `success` field before accessing `result`:

```javascript
const response = await window.api.repeatRequest(requestData);
if (response.success) {
  console.log('Response:', response.result);
} else {
  console.error('Error:', response.error);
}
```

## Security Considerations

1. **SSL Certificates**: The CA certificate is stored temporarily and should be removed after use
2. **Database**: Contains sensitive data (passwords, tokens, etc.) - ensure proper file permissions
3. **Scanner**: Only use on authorized targets - contains active exploitation capabilities
4. **Puppeteer**: Downloads Chromium (~170MB) on first run

## Performance Optimization

1. **Database**: Uses WAL mode for better concurrency
2. **Spider**: Limit `maxRequests` and `maxDepth` to prevent resource exhaustion
3. **Scanner**: Use `maxRequestsPerSecond` to throttle scans
4. **Intruder**: Use `throttle` settings to control load

## Troubleshooting

### Database Locked Error
- Close all instances of the application
- Delete the database file and restart

### Puppeteer Download Fails
- Set `PUPPETEER_SKIP_DOWNLOAD=true` in environment
- Or manually download Chromium

### Memory Issues with Spider
- Reduce `maxRequests` and `maxDepth`
- Disable `javascriptRendering` if not needed

### Scanner False Positives
- Adjust `confidence` thresholds
- Review vulnerability details in `proofOfConcept`

## Next Steps

1. **Extend Vulnerability Checks**: Add more vulnerability types in `backend/scanner/index.js`
2. **Add Payload Lists**: Create payload libraries for intruder in `backend/intruder/payloads/`
3. **Implement Collaborator**: Add out-of-band detection server
4. **Create Extensions API**: Allow loading custom modules
5. **Add Session Management**: Implement macro recording and token extraction

## API Reference

See `preload.js` for the complete list of exposed APIs. All functions are available on the `window.api` object in the renderer process.

## Support

For issues or questions:
- Check the console logs for detailed error messages
- Review the database schema in `backend/database/index.js`
- Test individual modules in isolation before integration
