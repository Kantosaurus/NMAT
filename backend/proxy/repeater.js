const axios = require('axios');
const https = require('https');

class Repeater {
  constructor() {
    this.httpsAgent = new https.Agent({
      rejectUnauthorized: false // Allow self-signed certificates
    });
  }

  async sendRequest(requestData) {
    try {
      const startTime = Date.now();

      const config = {
        method: requestData.method.toLowerCase(),
        url: requestData.url,
        headers: requestData.headers || {},
        data: requestData.bodyString || undefined,
        maxRedirects: 5,
        validateStatus: () => true, // Accept all status codes
        httpsAgent: this.httpsAgent,
        timeout: 30000
      };

      const response = await axios(config);
      const endTime = Date.now();

      return {
        statusCode: response.status,
        statusMessage: response.statusText,
        headers: response.headers,
        bodyString: typeof response.data === 'string'
          ? response.data
          : JSON.stringify(response.data, null, 2),
        time: endTime - startTime,
        length: Buffer.byteLength(
          typeof response.data === 'string'
            ? response.data
            : JSON.stringify(response.data)
        )
      };
    } catch (error) {
      // Even on error, try to return response if available
      if (error.response) {
        const endTime = Date.now();
        return {
          statusCode: error.response.status,
          statusMessage: error.response.statusText,
          headers: error.response.headers,
          bodyString: typeof error.response.data === 'string'
            ? error.response.data
            : JSON.stringify(error.response.data, null, 2),
          time: endTime - Date.now(),
          length: 0,
          error: error.message
        };
      }

      throw new Error(`Request failed: ${error.message}`);
    }
  }
}

module.exports = Repeater;
