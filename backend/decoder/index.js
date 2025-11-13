const crypto = require('crypto');
const zlib = require('zlib');

class Decoder {
  // Base64 operations
  base64Encode(text) {
    try {
      return Buffer.from(text, 'utf-8').toString('base64');
    } catch (error) {
      throw new Error(`Base64 encode error: ${error.message}`);
    }
  }

  base64Decode(text) {
    try {
      return Buffer.from(text, 'base64').toString('utf-8');
    } catch (error) {
      throw new Error(`Base64 decode error: ${error.message}`);
    }
  }

  // URL encoding operations
  urlEncode(text) {
    try {
      return encodeURIComponent(text);
    } catch (error) {
      throw new Error(`URL encode error: ${error.message}`);
    }
  }

  urlDecode(text) {
    try {
      return decodeURIComponent(text);
    } catch (error) {
      throw new Error(`URL decode error: ${error.message}`);
    }
  }

  // HTML encoding operations
  htmlEncode(text) {
    const htmlEntities = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '/': '&#x2F;'
    };

    return text.replace(/[&<>"'/]/g, char => htmlEntities[char]);
  }

  htmlDecode(text) {
    const htmlEntities = {
      '&amp;': '&',
      '&lt;': '<',
      '&gt;': '>',
      '&quot;': '"',
      '&#39;': "'",
      '&#x2F;': '/'
    };

    return text.replace(/&[^;]+;/g, entity => htmlEntities[entity] || entity);
  }

  // Hex encoding operations
  hexEncode(text) {
    try {
      return Buffer.from(text, 'utf-8').toString('hex');
    } catch (error) {
      throw new Error(`Hex encode error: ${error.message}`);
    }
  }

  hexDecode(text) {
    try {
      return Buffer.from(text, 'hex').toString('utf-8');
    } catch (error) {
      throw new Error(`Hex decode error: ${error.message}`);
    }
  }

  // ASCII Hex operations
  asciiHexEncode(text) {
    try {
      return text.split('').map(char =>
        char.charCodeAt(0).toString(16).padStart(2, '0')
      ).join(' ');
    } catch (error) {
      throw new Error(`ASCII Hex encode error: ${error.message}`);
    }
  }

  asciiHexDecode(text) {
    try {
      const hexValues = text.replace(/\s/g, '').match(/.{1,2}/g) || [];
      return hexValues.map(hex =>
        String.fromCharCode(parseInt(hex, 16))
      ).join('');
    } catch (error) {
      throw new Error(`ASCII Hex decode error: ${error.message}`);
    }
  }

  // GZip compression operations
  gzipEncode(text) {
    try {
      const compressed = zlib.gzipSync(Buffer.from(text, 'utf-8'));
      return compressed.toString('base64');
    } catch (error) {
      throw new Error(`GZip encode error: ${error.message}`);
    }
  }

  gzipDecode(text) {
    try {
      const buffer = Buffer.from(text, 'base64');
      const decompressed = zlib.gunzipSync(buffer);
      return decompressed.toString('utf-8');
    } catch (error) {
      throw new Error(`GZip decode error: ${error.message}`);
    }
  }

  // Hashing operations (one-way, no decode)
  md5Hash(text) {
    try {
      return crypto.createHash('md5').update(text).digest('hex');
    } catch (error) {
      throw new Error(`MD5 hash error: ${error.message}`);
    }
  }

  sha1Hash(text) {
    try {
      return crypto.createHash('sha1').update(text).digest('hex');
    } catch (error) {
      throw new Error(`SHA1 hash error: ${error.message}`);
    }
  }

  sha256Hash(text) {
    try {
      return crypto.createHash('sha256').update(text).digest('hex');
    } catch (error) {
      throw new Error(`SHA256 hash error: ${error.message}`);
    }
  }

  // Apply transformation chain
  applyChain(input, transformations) {
    let result = input;

    for (const transform of transformations) {
      try {
        result = this.applyTransformation(result, transform);
      } catch (error) {
        throw new Error(`Error in transformation ${transform.method}: ${error.message}`);
      }
    }

    return result;
  }

  applyTransformation(text, transform) {
    const { type, method } = transform;

    switch (method) {
      case 'base64':
        return type === 'encode' ? this.base64Encode(text) : this.base64Decode(text);

      case 'url':
        return type === 'encode' ? this.urlEncode(text) : this.urlDecode(text);

      case 'html':
        return type === 'encode' ? this.htmlEncode(text) : this.htmlDecode(text);

      case 'hex':
        return type === 'encode' ? this.hexEncode(text) : this.hexDecode(text);

      case 'ascii-hex':
        return type === 'encode' ? this.asciiHexEncode(text) : this.asciiHexDecode(text);

      case 'gzip':
        return type === 'encode' ? this.gzipEncode(text) : this.gzipDecode(text);

      case 'md5':
        if (type === 'encode') return this.md5Hash(text);
        throw new Error('MD5 cannot be decoded (one-way hash)');

      case 'sha1':
        if (type === 'encode') return this.sha1Hash(text);
        throw new Error('SHA1 cannot be decoded (one-way hash)');

      case 'sha256':
        if (type === 'encode') return this.sha256Hash(text);
        throw new Error('SHA256 cannot be decoded (one-way hash)');

      default:
        throw new Error(`Unknown transformation method: ${method}`);
    }
  }

  // Auto-detect encoding
  detectEncoding(text) {
    const detections = [];

    // Check for Base64
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length % 4 === 0) {
      try {
        const decoded = this.base64Decode(text);
        if (this.isPrintable(decoded)) {
          detections.push({ type: 'base64', decoded });
        }
      } catch (e) {
        // Not valid base64
      }
    }

    // Check for URL encoding
    if (text.includes('%')) {
      try {
        const decoded = this.urlDecode(text);
        if (decoded !== text) {
          detections.push({ type: 'url', decoded });
        }
      } catch (e) {
        // Not valid URL encoding
      }
    }

    // Check for HTML entities
    if (text.includes('&') && text.includes(';')) {
      const decoded = this.htmlDecode(text);
      if (decoded !== text) {
        detections.push({ type: 'html', decoded });
      }
    }

    // Check for Hex
    if (/^[0-9a-fA-F]+$/.test(text) && text.length % 2 === 0) {
      try {
        const decoded = this.hexDecode(text);
        if (this.isPrintable(decoded)) {
          detections.push({ type: 'hex', decoded });
        }
      } catch (e) {
        // Not valid hex
      }
    }

    return detections;
  }

  isPrintable(text) {
    // Check if text contains mostly printable ASCII characters
    const printable = text.split('').filter(char => {
      const code = char.charCodeAt(0);
      return (code >= 32 && code <= 126) || code === 10 || code === 13;
    });

    return printable.length / text.length > 0.9;
  }

  // Compare two texts (for Comparer functionality)
  compare(text1, text2, mode = 'text') {
    let content1 = text1;
    let content2 = text2;

    if (mode === 'hex') {
      content1 = this.hexEncode(text1);
      content2 = this.hexEncode(text2);
    } else if (mode === 'binary') {
      content1 = text1.split('').map(c =>
        c.charCodeAt(0).toString(2).padStart(8, '0')
      ).join(' ');
      content2 = text2.split('').map(c =>
        c.charCodeAt(0).toString(2).padStart(8, '0')
      ).join(' ');
    }

    const differences = {
      leftSize: text1.length,
      rightSize: text2.length,
      sizeDifference: Math.abs(text1.length - text2.length),
      identical: text1 === text2,
      differencePositions: []
    };

    if (!differences.identical) {
      const maxLen = Math.max(content1.length, content2.length);
      for (let i = 0; i < maxLen; i++) {
        if (content1[i] !== content2[i]) {
          differences.differencePositions.push({
            position: i,
            left: content1[i] || '',
            right: content2[i] || ''
          });
        }
      }
    }

    return differences;
  }
}

module.exports = Decoder;
