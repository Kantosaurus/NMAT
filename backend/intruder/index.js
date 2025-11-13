const EventEmitter = require('events');
const axios = require('axios');
const https = require('https');
const crypto = require('crypto');

class Intruder extends EventEmitter {
  constructor(database) {
    super();
    this.db = database;
    this.isRunning = false;
    this.httpsAgent = new https.Agent({
      rejectUnauthorized: false
    });
  }

  async startAttack(attack) {
    if (this.isRunning) {
      throw new Error('An attack is already running');
    }

    this.isRunning = true;
    this.emit('started', attack.id);

    try {
      const requests = this.generateRequests(attack);
      const totalRequests = requests.length;

      this.emit('progress', {
        attackId: attack.id,
        current: 0,
        total: totalRequests,
        percentage: 0
      });

      // Process requests with throttling
      const results = [];
      const concurrent = attack.throttle.enabled ? attack.throttle.maxConcurrent : 10;
      const delay = attack.throttle.enabled ? attack.throttle.delayMs : 0;

      for (let i = 0; i < requests.length; i += concurrent) {
        if (!this.isRunning) break;

        const batch = requests.slice(i, i + concurrent);
        const batchResults = await Promise.all(
          batch.map(req => this.executeRequest(req, attack))
        );

        results.push(...batchResults);

        // Save results to database
        batchResults.forEach(result => {
          this.db.addIntruderResult(result);
          this.emit('result', result);
        });

        this.emit('progress', {
          attackId: attack.id,
          current: i + batch.length,
          total: totalRequests,
          percentage: Math.round(((i + batch.length) / totalRequests) * 100)
        });

        // Apply delay between batches
        if (delay > 0 && i + concurrent < requests.length) {
          await this.sleep(delay);
        }
      }

      this.emit('completed', {
        attackId: attack.id,
        totalRequests,
        results
      });

    } catch (error) {
      this.emit('error', error);
    } finally {
      this.isRunning = false;
    }
  }

  generateRequests(attack) {
    const { attackType, positions, payloadSets, baseRequest } = attack;

    if (positions.length === 0) {
      return [];
    }

    let requests = [];

    switch (attackType) {
      case 'sniper':
        requests = this.generateSniperRequests(attack);
        break;
      case 'battering-ram':
        requests = this.generateBatteringRamRequests(attack);
        break;
      case 'pitchfork':
        requests = this.generatePitchforkRequests(attack);
        break;
      case 'cluster-bomb':
        requests = this.generateClusterBombRequests(attack);
        break;
      default:
        throw new Error(`Unknown attack type: ${attackType}`);
    }

    return requests;
  }

  generateSniperRequests(attack) {
    const requests = [];
    const { positions, payloadSets, baseRequest } = attack;
    const payloads = payloadSets[0]?.payloads || [];

    let requestNumber = 1;

    // For each position
    for (let posIdx = 0; posIdx < positions.length; posIdx++) {
      // For each payload
      for (const payload of payloads) {
        const request = this.buildRequest(baseRequest, positions, [payload], posIdx);
        requests.push({
          requestNumber: requestNumber++,
          payload,
          positionIndex: posIdx,
          ...request
        });
      }
    }

    return requests;
  }

  generateBatteringRamRequests(attack) {
    const requests = [];
    const { positions, payloadSets, baseRequest } = attack;
    const payloads = payloadSets[0]?.payloads || [];

    let requestNumber = 1;

    // Each payload is placed in ALL positions simultaneously
    for (const payload of payloads) {
      const payloadArray = new Array(positions.length).fill(payload);
      const request = this.buildRequest(baseRequest, positions, payloadArray, -1);
      requests.push({
        requestNumber: requestNumber++,
        payload,
        ...request
      });
    }

    return requests;
  }

  generatePitchforkRequests(attack) {
    const requests = [];
    const { positions, payloadSets, baseRequest } = attack;

    let requestNumber = 1;

    // Get minimum length of all payload sets
    const minLength = Math.min(...payloadSets.map(set => set.payloads.length));

    // Iterate through payloads in parallel
    for (let i = 0; i < minLength; i++) {
      const payloadArray = payloadSets.map(set => set.payloads[i]);
      const request = this.buildRequest(baseRequest, positions, payloadArray, -1);
      requests.push({
        requestNumber: requestNumber++,
        payload: payloadArray,
        ...request
      });
    }

    return requests;
  }

  generateClusterBombRequests(attack) {
    const requests = [];
    const { positions, payloadSets, baseRequest } = attack;

    let requestNumber = 1;

    // Generate all combinations (Cartesian product)
    const combinations = this.cartesianProduct(
      ...payloadSets.map(set => set.payloads)
    );

    for (const payloadArray of combinations) {
      const request = this.buildRequest(baseRequest, positions, payloadArray, -1);
      requests.push({
        requestNumber: requestNumber++,
        payload: payloadArray,
        ...request
      });
    }

    return requests;
  }

  buildRequest(baseRequest, positions, payloads, singlePositionIndex) {
    let url = baseRequest.url;
    let headers = baseRequest.headers;
    let body = baseRequest.body;

    // For Sniper mode, only replace the specific position
    if (singlePositionIndex >= 0) {
      const position = positions[singlePositionIndex];
      const payload = payloads[0];

      // Simple replacement in URL, headers, or body
      // In a real implementation, you'd track exact positions
      url = url.replace(/§([^§]*)§/, payload);
      headers = headers.replace(/§([^§]*)§/, payload);
      body = body.replace(/§([^§]*)§/, payload);
    } else {
      // For other modes, replace all positions
      positions.forEach((position, idx) => {
        const payload = payloads[idx] || '';
        const marker = `§${position.name}§`;

        url = url.replace(marker, payload);
        headers = headers.replace(marker, payload);
        body = body.replace(marker, payload);
      });
    }

    return {
      method: baseRequest.method,
      url,
      headers,
      body
    };
  }

  async executeRequest(requestData, attack) {
    const startTime = Date.now();

    try {
      // Parse headers
      const headersObj = {};
      if (requestData.headers) {
        requestData.headers.split('\n').forEach(line => {
          const [key, ...valueParts] = line.split(':');
          if (key && valueParts.length > 0) {
            headersObj[key.trim()] = valueParts.join(':').trim();
          }
        });
      }

      // Apply payload processors
      let processedPayload = requestData.payload;
      if (attack.processors && attack.processors.length > 0) {
        processedPayload = this.applyProcessors(requestData.payload, attack.processors);
      }

      // Make request
      const config = {
        method: requestData.method.toLowerCase(),
        url: requestData.url,
        headers: headersObj,
        data: requestData.body || undefined,
        maxRedirects: 5,
        validateStatus: () => true,
        httpsAgent: this.httpsAgent,
        timeout: 10000
      };

      const response = await axios(config);
      const endTime = Date.now();

      const responseBody = typeof response.data === 'string'
        ? response.data
        : JSON.stringify(response.data);

      // Apply grep rules
      const matches = {};
      const extractions = {};

      if (attack.grepRules) {
        attack.grepRules.forEach(rule => {
          if (rule.type === 'grep-match') {
            const regex = rule.isRegex ? new RegExp(rule.pattern) : null;
            if (regex) {
              matches[rule.id] = regex.test(responseBody);
            } else {
              matches[rule.id] = responseBody.includes(rule.pattern);
            }
          } else if (rule.type === 'grep-extract') {
            const regex = rule.isRegex ? new RegExp(rule.pattern) : null;
            if (regex) {
              const match = responseBody.match(regex);
              extractions[rule.id] = match ? match[0] : '';
            }
          }
        });
      }

      return {
        id: Date.now().toString() + Math.random(),
        attackId: attack.id,
        requestNumber: requestData.requestNumber,
        payload: processedPayload,
        statusCode: response.status,
        length: Buffer.byteLength(responseBody),
        time: endTime - startTime,
        matches,
        extractions,
        request: `${requestData.method} ${requestData.url}\n${requestData.headers}\n\n${requestData.body}`,
        response: responseBody.substring(0, 5000) // Limit response size
      };

    } catch (error) {
      const endTime = Date.now();

      return {
        id: Date.now().toString() + Math.random(),
        attackId: attack.id,
        requestNumber: requestData.requestNumber,
        payload: requestData.payload,
        statusCode: null,
        length: 0,
        time: endTime - startTime,
        matches: {},
        extractions: {},
        request: `${requestData.method} ${requestData.url}`,
        response: '',
        error: error.message
      };
    }
  }

  applyProcessors(payload, processors) {
    let result = Array.isArray(payload) ? payload.join(',') : payload;

    processors.forEach(processor => {
      if (!processor.enabled) return;

      switch (processor.type) {
        case 'url-encode':
          result = encodeURIComponent(result);
          break;
        case 'html-encode':
          result = result.replace(/[&<>"']/g, char => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
          }[char]));
          break;
        case 'base64-encode':
          result = Buffer.from(result).toString('base64');
          break;
        case 'base64-decode':
          try {
            result = Buffer.from(result, 'base64').toString('utf-8');
          } catch (e) {
            // Invalid base64, skip
          }
          break;
        case 'hash':
          result = crypto.createHash('md5').update(result).digest('hex');
          break;
        case 'add-prefix':
          result = (processor.config?.prefix || '') + result;
          break;
        case 'add-suffix':
          result = result + (processor.config?.suffix || '');
          break;
        case 'match-replace':
          if (processor.config?.match && processor.config?.replace) {
            const regex = new RegExp(processor.config.match, 'g');
            result = result.replace(regex, processor.config.replace);
          }
          break;
        case 'reverse':
          result = result.split('').reverse().join('');
          break;
        case 'lowercase':
          result = result.toLowerCase();
          break;
        case 'uppercase':
          result = result.toUpperCase();
          break;
      }
    });

    return result;
  }

  cartesianProduct(...arrays) {
    return arrays.reduce((acc, array) => {
      return acc.flatMap(x => array.map(y => [...(Array.isArray(x) ? x : [x]), y]));
    }, [[]]);
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  stop() {
    this.isRunning = false;
    this.emit('stopped');
  }
}

module.exports = Intruder;
