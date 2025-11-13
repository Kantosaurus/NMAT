const EventEmitter = require('events');
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');
const puppeteer = require('puppeteer');

class Spider extends EventEmitter {
  constructor(config, database) {
    super();
    this.config = config;
    this.db = database;
    this.isRunning = false;
    this.queue = [];
    this.visited = new Set();
    this.discovered = new Set();
    this.stats = {
      discovered: 0,
      crawled: 0
    };
    this.browser = null;
  }

  async start(startUrls) {
    if (this.isRunning) {
      throw new Error('Spider is already running');
    }

    this.isRunning = true;
    this.queue = startUrls.map(url => ({ url, depth: 0 }));
    this.visited.clear();
    this.discovered.clear();
    this.stats = { discovered: startUrls.length, crawled: 0 };

    // Initialize browser if JavaScript rendering is enabled
    if (this.config.javascriptRendering && this.config.headlessBrowser) {
      this.browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
    }

    this.emit('started');

    // Process queue
    while (this.queue.length > 0 && this.isRunning) {
      const item = this.queue.shift();
      await this.crawlUrl(item.url, item.depth);

      this.emit('progress', {
        discovered: this.stats.discovered,
        crawled: this.stats.crawled
      });

      // Respect request delay
      if (this.config.requestDelay > 0) {
        await this.sleep(this.config.requestDelay);
      }

      // Check limits
      if (this.stats.crawled >= this.config.maxRequests) {
        console.log('Max requests limit reached');
        break;
      }
    }

    await this.stop();
    this.emit('completed', this.stats);
  }

  async crawlUrl(url, depth) {
    try {
      // Skip if already visited
      if (this.visited.has(url)) {
        return;
      }

      // Check depth limit
      if (depth >= this.config.maxDepth) {
        return;
      }

      // Check scope
      if (!this.isInScope(url)) {
        return;
      }

      this.visited.add(url);
      this.stats.crawled++;

      console.log(`Crawling: ${url} (depth: ${depth})`);

      let html;
      let statusCode;
      let headers;

      // Choose crawling method
      if (this.config.javascriptRendering && this.browser) {
        const result = await this.crawlWithBrowser(url);
        html = result.html;
        statusCode = result.statusCode;
        headers = result.headers;
      } else {
        const result = await this.crawlWithHttp(url);
        html = result.html;
        statusCode = result.statusCode;
        headers = result.headers;
      }

      // Parse HTML and extract data
      const $ = cheerio.load(html);
      const links = this.extractLinks($, url);
      const forms = this.extractForms($, url);
      const parameters = this.extractParameters(url);

      // Save discovered endpoint
      const endpoint = {
        id: Date.now().toString() + Math.random(),
        url,
        host: new URL(url).host,
        path: new URL(url).pathname,
        method: 'GET',
        discovered_at: Date.now(),
        statusCode,
        contentType: headers['content-type'] || '',
        parameters,
        forms: forms.map(f => ({
          action: f.action,
          method: f.method,
          fields: f.fields
        })),
        links: links.slice(0, 100), // Limit stored links
        responseTime: 0,
        responseSize: html.length
      };

      this.db.addEndpoint(endpoint);
      this.emit('endpoint-discovered', endpoint);

      // Add links to queue
      for (const link of links) {
        if (!this.visited.has(link) && !this.discovered.has(link)) {
          this.discovered.add(link);
          this.stats.discovered++;
          this.queue.push({ url: link, depth: depth + 1 });
        }
      }

      // Handle forms if enabled
      if (this.config.submitForms && forms.length > 0) {
        for (const form of forms) {
          await this.handleForm(form, url);
        }
      }

    } catch (error) {
      console.error(`Error crawling ${url}:`, error.message);
    }
  }

  async crawlWithHttp(url) {
    const response = await axios.get(url, {
      maxRedirects: this.config.followRedirects ? 5 : 0,
      validateStatus: () => true,
      timeout: 10000,
      headers: {
        'User-Agent': 'NMAT Spider/1.0'
      }
    });

    return {
      html: response.data,
      statusCode: response.status,
      headers: response.headers
    };
  }

  async crawlWithBrowser(url) {
    const page = await this.browser.newPage();

    try {
      const response = await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.config.browserTimeout || 30000
      });

      const html = await page.content();
      const headers = response.headers();
      const statusCode = response.status();

      await page.close();

      return { html, statusCode, headers };
    } catch (error) {
      await page.close();
      throw error;
    }
  }

  extractLinks($, baseUrl) {
    const links = new Set();
    const base = new URL(baseUrl);

    $('a[href]').each((i, elem) => {
      try {
        const href = $(elem).attr('href');
        if (!href) return;

        // Skip javascript:, mailto:, tel:, etc.
        if (href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:')) {
          return;
        }

        // Resolve relative URLs
        const absoluteUrl = new URL(href, baseUrl).href;

        // Remove hash fragments
        const urlWithoutHash = absoluteUrl.split('#')[0];

        if (urlWithoutHash && this.isInScope(urlWithoutHash)) {
          links.add(urlWithoutHash);
        }
      } catch (e) {
        // Invalid URL, skip
      }
    });

    // Extract from script tags if parseScripts is enabled
    if (this.config.parseScripts) {
      $('script').each((i, elem) => {
        const script = $(elem).html() || '';
        const urlRegex = /(https?:\/\/[^\s"'<>]+)/g;
        const matches = script.match(urlRegex) || [];
        matches.forEach(url => {
          if (this.isInScope(url)) {
            links.add(url.split('#')[0]);
          }
        });
      });
    }

    return Array.from(links);
  }

  extractForms($, baseUrl) {
    const forms = [];

    $('form').each((i, elem) => {
      const $form = $(elem);
      const action = $form.attr('action') || baseUrl;
      const method = ($form.attr('method') || 'GET').toUpperCase();
      const fields = [];

      $form.find('input, select, textarea').each((j, input) => {
        const $input = $(input);
        const name = $input.attr('name');
        const type = $input.attr('type') || 'text';
        const value = $input.attr('value') || '';

        if (name) {
          fields.push({ name, type, value });
        }
      });

      try {
        const absoluteAction = new URL(action, baseUrl).href;
        forms.push({ action: absoluteAction, method, fields });
      } catch (e) {
        // Invalid URL, skip
      }
    });

    return forms;
  }

  extractParameters(url) {
    try {
      const urlObj = new URL(url);
      return Array.from(urlObj.searchParams.keys());
    } catch (e) {
      return [];
    }
  }

  async handleForm(form, sourceUrl) {
    // Check if we have form configuration for this form
    // For now, just log it - can be extended with auto-fill logic
    console.log(`Found form: ${form.action} (${form.method})`);
  }

  isInScope(url) {
    try {
      const urlObj = new URL(url);

      // Only HTTP/HTTPS
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        return false;
      }

      // Check file type exclusions
      if (this.config.detectFileTypes) {
        const path = urlObj.pathname.toLowerCase();
        const excluded = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.svg', '.woff', '.woff2', '.ttf'];
        if (excluded.some(ext => path.endsWith(ext))) {
          return false;
        }
      }

      // Check query string length
      if (this.config.maxQueryStringLength && urlObj.search.length > this.config.maxQueryStringLength) {
        return false;
      }

      return true;
    } catch (e) {
      return false;
    }
  }

  async stop() {
    this.isRunning = false;
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
    this.emit('stopped');
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = Spider;
