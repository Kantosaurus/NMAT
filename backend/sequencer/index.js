const crypto = require('crypto');
const zlib = require('zlib');

class Sequencer {
  analyzeTokens(tokens) {
    if (!tokens || tokens.length === 0) {
      throw new Error('No tokens provided for analysis');
    }

    const analysis = {
      totalTokens: tokens.length,
      uniqueTokens: new Set(tokens).size,
      entropy: 0,
      compressionRatio: 0,
      characterFrequency: {},
      bitDistribution: [0, 0, 0, 0, 0, 0, 0, 0],
      serialCorrelation: 0,
      estimatedEntropy: {
        shannon: 0,
        minEntropy: 0
      }
    };

    // Calculate character frequency
    analysis.characterFrequency = this.calculateCharacterFrequency(tokens);

    // Calculate Shannon entropy
    analysis.estimatedEntropy.shannon = this.calculateShannonEntropy(analysis.characterFrequency, tokens.join('').length);
    analysis.entropy = analysis.estimatedEntropy.shannon;

    // Calculate min entropy (simplified)
    analysis.estimatedEntropy.minEntropy = this.calculateMinEntropy(tokens);

    // Calculate compression ratio
    analysis.compressionRatio = this.calculateCompressionRatio(tokens);

    // Calculate bit distribution (for hex tokens)
    analysis.bitDistribution = this.calculateBitDistribution(tokens);

    // Calculate serial correlation
    analysis.serialCorrelation = this.calculateSerialCorrelation(tokens);

    return analysis;
  }

  calculateCharacterFrequency(tokens) {
    const frequency = {};
    const allChars = tokens.join('');

    for (const char of allChars) {
      frequency[char] = (frequency[char] || 0) + 1;
    }

    return frequency;
  }

  calculateShannonEntropy(charFrequency, totalChars) {
    let entropy = 0;

    for (const count of Object.values(charFrequency)) {
      const probability = count / totalChars;
      entropy -= probability * Math.log2(probability);
    }

    return entropy;
  }

  calculateMinEntropy(tokens) {
    // Min entropy is based on the most common token
    const frequency = {};

    tokens.forEach(token => {
      frequency[token] = (frequency[token] || 0) + 1;
    });

    const maxFrequency = Math.max(...Object.values(frequency));
    const probability = maxFrequency / tokens.length;

    return -Math.log2(probability);
  }

  calculateCompressionRatio(tokens) {
    try {
      const originalData = tokens.join('');
      const compressed = zlib.deflateSync(Buffer.from(originalData));

      return compressed.length / originalData.length;
    } catch (error) {
      return 1; // If compression fails, ratio is 1 (no compression)
    }
  }

  calculateBitDistribution(tokens) {
    const bitCounts = [0, 0, 0, 0, 0, 0, 0, 0];

    tokens.forEach(token => {
      // Try to parse as hex
      try {
        const hex = token.replace(/[^0-9a-fA-F]/g, '');
        if (hex.length > 0) {
          const buffer = Buffer.from(hex, 'hex');

          buffer.forEach(byte => {
            for (let i = 0; i < 8; i++) {
              if ((byte >> i) & 1) {
                bitCounts[i]++;
              }
            }
          });
        }
      } catch (e) {
        // Not hex, try binary representation of ASCII
        for (const char of token) {
          const byte = char.charCodeAt(0);
          for (let i = 0; i < 8; i++) {
            if ((byte >> i) & 1) {
              bitCounts[i]++;
            }
          }
        }
      }
    });

    return bitCounts;
  }

  calculateSerialCorrelation(tokens) {
    if (tokens.length < 2) {
      return 0;
    }

    // Simple serial correlation: check how similar consecutive tokens are
    let correlation = 0;
    let comparisons = 0;

    for (let i = 0; i < tokens.length - 1; i++) {
      const token1 = tokens[i];
      const token2 = tokens[i + 1];

      // Calculate similarity (Levenshtein distance normalized)
      const similarity = this.calculateSimilarity(token1, token2);
      correlation += similarity;
      comparisons++;
    }

    return comparisons > 0 ? correlation / comparisons : 0;
  }

  calculateSimilarity(str1, str2) {
    // Simplified Levenshtein distance
    const len1 = str1.length;
    const len2 = str2.length;

    if (len1 === 0) return len2;
    if (len2 === 0) return len1;

    const matrix = Array(len1 + 1).fill(null).map(() => Array(len2 + 1).fill(0));

    for (let i = 0; i <= len1; i++) {
      matrix[i][0] = i;
    }

    for (let j = 0; j <= len2; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= len1; i++) {
      for (let j = 1; j <= len2; j++) {
        const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,      // deletion
          matrix[i][j - 1] + 1,      // insertion
          matrix[i - 1][j - 1] + cost // substitution
        );
      }
    }

    const distance = matrix[len1][len2];
    const maxLen = Math.max(len1, len2);

    return distance / maxLen; // Normalized distance
  }

  // Generate random tokens for testing
  generateRandomTokens(count, length = 32) {
    const tokens = [];

    for (let i = 0; i < count; i++) {
      tokens.push(crypto.randomBytes(length).toString('hex'));
    }

    return tokens;
  }

  // Generate weak tokens for testing
  generateWeakTokens(count) {
    const tokens = [];
    const base = Date.now();

    for (let i = 0; i < count; i++) {
      // Sequential tokens (weak)
      tokens.push((base + i).toString(16));
    }

    return tokens;
  }
}

module.exports = Sequencer;
