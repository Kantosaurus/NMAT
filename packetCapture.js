const { Cap, decoders } = require('cap');
const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');

class PacketCapture extends EventEmitter {
  constructor(deviceName, options = {}) {
    super();
    this.deviceName = deviceName;
    this.cap = new Cap();
    this.device = null;
    this.buffer = null;
    this.packetCount = 0;
    this.startTime = Date.now();

    // Advanced options
    this.options = {
      promiscuous: options.promiscuous !== false, // Default true
      monitor: options.monitor || false, // Monitor mode for Wi-Fi
      filter: options.filter || '', // BPF filter syntax
      snaplen: options.snaplen || 65535, // Snapshot length
      maxPackets: options.maxPackets || 0, // 0 = unlimited
      maxDuration: options.maxDuration || 0, // 0 = unlimited (seconds)
      ringBuffer: options.ringBuffer || false,
      maxFileSize: options.maxFileSize || 100 * 1024 * 1024, // 100MB
      maxFiles: options.maxFiles || 5,
      outputDir: options.outputDir || null,
      outputFile: options.outputFile || null
    };

    // Ring buffer state
    this.currentFile = null;
    this.currentFileSize = 0;
    this.fileIndex = 0;
    this.pcapFiles = [];

    // Capture control
    this.captureTimer = null;
    this.isOfflineMode = false;
  }

  start() {
    try {
      const devices = Cap.deviceList();
      this.device = devices.find(d => d.name === this.deviceName);

      if (!this.device) {
        throw new Error('Device not found');
      }

      const bufSize = 10 * 1024 * 1024;
      this.buffer = Buffer.alloc(this.options.snaplen);

      const linkType = this.cap.open(
        this.device.name,
        this.options.filter, // Apply BPF filter
        bufSize,
        this.buffer,
        this.options.promiscuous, // Promiscuous mode
        this.options.monitor // Monitor mode (Wi-Fi)
      );

      this.cap.setMinBytes(0);

      this.cap.on('packet', (nbytes, trunc) => {
        this.handlePacket(nbytes, trunc, linkType);
      });

      console.log('Packet capture started on device:', this.device.name);
      console.log('Promiscuous mode:', this.options.promiscuous);
      console.log('Monitor mode:', this.options.monitor);
      console.log('Filter:', this.options.filter || '(none)');

      // Set up time-based capture control
      if (this.options.maxDuration > 0) {
        this.captureTimer = setTimeout(() => {
          console.log(`Capture duration limit (${this.options.maxDuration}s) reached`);
          this.stop();
        }, this.options.maxDuration * 1000);
      }

      // Initialize ring buffer if enabled
      if (this.options.ringBuffer && this.options.outputDir) {
        this.initializeRingBuffer();
      }

      this.startTime = Date.now();
    } catch (error) {
      this.emit('error', error);
    }
  }

  initializeRingBuffer() {
    if (!fs.existsSync(this.options.outputDir)) {
      fs.mkdirSync(this.options.outputDir, { recursive: true });
    }

    this.rotateFile();
    console.log('Ring buffer initialized:', this.options.outputDir);
  }

  rotateFile() {
    // Close current file if open
    if (this.currentFile) {
      this.currentFile.end();
    }

    // Remove oldest file if we've hit the limit
    if (this.pcapFiles.length >= this.options.maxFiles) {
      const oldestFile = this.pcapFiles.shift();
      try {
        fs.unlinkSync(oldestFile);
        console.log('Removed oldest file:', oldestFile);
      } catch (error) {
        console.error('Error removing old file:', error);
      }
    }

    // Create new file
    this.fileIndex++;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `capture_${timestamp}_${this.fileIndex}.pcap`;
    const filepath = path.join(this.options.outputDir, filename);

    this.currentFile = fs.createWriteStream(filepath);
    this.currentFileSize = 0;
    this.pcapFiles.push(filepath);

    // Write pcap header
    this.writePcapHeader();

    console.log('Created new capture file:', filepath);
    this.emit('file-rotated', filepath);
  }

  writePcapHeader() {
    // Global pcap header (24 bytes)
    const header = Buffer.alloc(24);
    header.writeUInt32LE(0xa1b2c3d4, 0);  // Magic number
    header.writeUInt16LE(2, 4);            // Version major
    header.writeUInt16LE(4, 6);            // Version minor
    header.writeInt32LE(0, 8);             // Timezone offset
    header.writeUInt32LE(0, 12);           // Timestamp accuracy
    header.writeUInt32LE(65535, 16);       // Snapshot length
    header.writeUInt32LE(1, 20);           // Link-layer type (Ethernet)

    this.currentFile.write(header);
  }

  writePacketToFile(nbytes, timestamp) {
    if (!this.currentFile) return;

    // Check if we need to rotate based on file size
    if (this.currentFileSize >= this.options.maxFileSize) {
      this.rotateFile();
    }

    // Packet header (16 bytes)
    const packetHeader = Buffer.alloc(16);
    const seconds = Math.floor(timestamp.getTime() / 1000);
    const microseconds = (timestamp.getTime() % 1000) * 1000;

    packetHeader.writeUInt32LE(seconds, 0);         // Timestamp seconds
    packetHeader.writeUInt32LE(microseconds, 4);    // Timestamp microseconds
    packetHeader.writeUInt32LE(nbytes, 8);          // Captured length
    packetHeader.writeUInt32LE(nbytes, 12);         // Original length

    this.currentFile.write(packetHeader);
    this.currentFile.write(this.buffer.slice(0, nbytes));

    this.currentFileSize += 16 + nbytes;
  }

  handlePacket(nbytes, trunc, linkType) {
    try {
      this.packetCount++;
      const timestamp = new Date();
      const timestampISO = timestamp.toISOString();

      // Write to file if ring buffer is enabled
      if (this.options.ringBuffer && this.currentFile) {
        this.writePacketToFile(nbytes, timestamp);
      }

      // Check packet count limit
      if (this.options.maxPackets > 0 && this.packetCount >= this.options.maxPackets) {
        console.log(`Packet count limit (${this.options.maxPackets}) reached`);
        this.stop();
        return;
      }

      let ret;
      if (linkType === 'ETHERNET') {
        ret = decoders.Ethernet(this.buffer);

        if (ret.info.type === 2048) { // IPv4
          ret.info.ipv4 = decoders.IPV4(this.buffer, ret.offset);
          const ipInfo = ret.info.ipv4.info;

          let protocol = 'Unknown';
          let srcPort = '';
          let dstPort = '';
          let info = '';

          if (ipInfo.protocol === 6) { // TCP
            protocol = 'TCP';
            const tcp = decoders.TCP(this.buffer, ret.info.ipv4.offset);
            srcPort = tcp.info.srcport;
            dstPort = tcp.info.dstport;

            const flags = [];
            if (tcp.info.flags & 0x01) flags.push('FIN');
            if (tcp.info.flags & 0x02) flags.push('SYN');
            if (tcp.info.flags & 0x04) flags.push('RST');
            if (tcp.info.flags & 0x08) flags.push('PSH');
            if (tcp.info.flags & 0x10) flags.push('ACK');
            if (tcp.info.flags & 0x20) flags.push('URG');

            info = `${srcPort} → ${dstPort} [${flags.join(', ')}] Seq=${tcp.info.seqno} Ack=${tcp.info.ackno} Win=${tcp.info.window}`;
          } else if (ipInfo.protocol === 17) { // UDP
            protocol = 'UDP';
            const udp = decoders.UDP(this.buffer, ret.info.ipv4.offset);
            srcPort = udp.info.srcport;
            dstPort = udp.info.dstport;
            info = `${srcPort} → ${dstPort} Len=${udp.info.length}`;
          } else if (ipInfo.protocol === 1) { // ICMP
            protocol = 'ICMP';
            const icmp = decoders.ICMP(this.buffer, ret.info.ipv4.offset);
            info = `Type=${icmp.info.type} Code=${icmp.info.code}`;
          }

          const packet = {
            no: this.packetCount,
            timestamp: timestampISO,
            relativeTime: ((timestamp.getTime() - this.startTime) / 1000).toFixed(6),
            source: ipInfo.srcaddr,
            destination: ipInfo.dstaddr,
            protocol,
            length: nbytes,
            info,
            srcPort,
            dstPort,
            raw: {
              ethernet: {
                src: ret.info.srcmac,
                dst: ret.info.dstmac
              },
              ip: {
                version: ipInfo.version,
                ttl: ipInfo.ttl,
                protocol: ipInfo.protocol
              }
            },
            rawBuffer: Array.from(this.buffer.slice(0, nbytes))
          };

          this.emit('packet', packet);
        } else if (ret.info.type === 2054) { // ARP
          const arp = decoders.ARP(this.buffer, ret.offset);

          const packet = {
            no: this.packetCount,
            timestamp: timestampISO,
            relativeTime: ((timestamp.getTime() - this.startTime) / 1000).toFixed(6),
            source: arp.info.sender_pa,
            destination: arp.info.target_pa,
            protocol: 'ARP',
            length: nbytes,
            info: `Who has ${arp.info.target_pa}? Tell ${arp.info.sender_pa}`,
            srcPort: '',
            dstPort: '',
            raw: {
              ethernet: {
                src: ret.info.srcmac,
                dst: ret.info.dstmac
              },
              arp: arp.info
            },
            rawBuffer: Array.from(this.buffer.slice(0, nbytes))
          };

          this.emit('packet', packet);
        } else if (ret.info.type === 34525) { // IPv6
          ret.info.ipv6 = decoders.IPV6(this.buffer, ret.offset);
          const ipInfo = ret.info.ipv6.info;

          const packet = {
            no: this.packetCount,
            timestamp: timestampISO,
            relativeTime: ((timestamp.getTime() - this.startTime) / 1000).toFixed(6),
            source: ipInfo.srcaddr,
            destination: ipInfo.dstaddr,
            protocol: 'IPv6',
            length: nbytes,
            info: `IPv6 packet`,
            srcPort: '',
            dstPort: '',
            raw: {
              ethernet: {
                src: ret.info.srcmac,
                dst: ret.info.dstmac
              },
              ip: ipInfo
            },
            rawBuffer: Array.from(this.buffer.slice(0, nbytes))
          };

          this.emit('packet', packet);
        }
      }
    } catch (error) {
      console.error('Error parsing packet:', error);
    }
  }

  stop() {
    try {
      // Clear capture timer
      if (this.captureTimer) {
        clearTimeout(this.captureTimer);
        this.captureTimer = null;
      }

      // Close current ring buffer file
      if (this.currentFile) {
        this.currentFile.end();
        this.currentFile = null;
        console.log('Closed capture file');
      }

      // Close live capture
      if (this.cap && !this.isOfflineMode) {
        this.cap.close();
        console.log('Packet capture stopped');
      }

      this.emit('stopped', {
        packetCount: this.packetCount,
        duration: ((Date.now() - this.startTime) / 1000).toFixed(2)
      });
    } catch (error) {
      console.error('Error stopping capture:', error);
    }
  }

  // Offline pcap/pcapng file analysis
  async loadPcapFile(filepath) {
    return new Promise((resolve, reject) => {
      try {
        this.isOfflineMode = true;
        this.packetCount = 0;
        this.startTime = Date.now();

        console.log('Loading pcap file:', filepath);

        const fileBuffer = fs.readFileSync(filepath);
        let offset = 0;

        // Read global header (24 bytes)
        const magicNumber = fileBuffer.readUInt32LE(0);

        // Check if it's a valid pcap file
        if (magicNumber !== 0xa1b2c3d4 && magicNumber !== 0xd4c3b2a1) {
          throw new Error('Invalid pcap file format');
        }

        offset = 24; // Skip global header

        const packets = [];

        // Read packets
        while (offset < fileBuffer.length) {
          if (offset + 16 > fileBuffer.length) break;

          // Read packet header
          const tsSeconds = fileBuffer.readUInt32LE(offset);
          const tsMicroseconds = fileBuffer.readUInt32LE(offset + 4);
          const capturedLength = fileBuffer.readUInt32LE(offset + 8);
          const originalLength = fileBuffer.readUInt32LE(offset + 12);

          offset += 16;

          if (offset + capturedLength > fileBuffer.length) break;

          // Read packet data
          this.buffer = fileBuffer.slice(offset, offset + capturedLength);
          offset += capturedLength;

          this.packetCount++;
          const timestamp = new Date(tsSeconds * 1000 + tsMicroseconds / 1000);

          // Parse packet (reuse existing parsing logic)
          try {
            const ret = decoders.Ethernet(this.buffer);

            if (ret.info.type === 2048) { // IPv4
              ret.info.ipv4 = decoders.IPV4(this.buffer, ret.offset);
              const ipInfo = ret.info.ipv4.info;

              let protocol = 'Unknown';
              let srcPort = '';
              let dstPort = '';
              let info = '';

              if (ipInfo.protocol === 6) { // TCP
                protocol = 'TCP';
                const tcp = decoders.TCP(this.buffer, ret.info.ipv4.offset);
                srcPort = tcp.info.srcport;
                dstPort = tcp.info.dstport;

                const flags = [];
                if (tcp.info.flags & 0x01) flags.push('FIN');
                if (tcp.info.flags & 0x02) flags.push('SYN');
                if (tcp.info.flags & 0x04) flags.push('RST');
                if (tcp.info.flags & 0x08) flags.push('PSH');
                if (tcp.info.flags & 0x10) flags.push('ACK');
                if (tcp.info.flags & 0x20) flags.push('URG');

                info = `${srcPort} → ${dstPort} [${flags.join(', ')}]`;
              } else if (ipInfo.protocol === 17) { // UDP
                protocol = 'UDP';
                const udp = decoders.UDP(this.buffer, ret.info.ipv4.offset);
                srcPort = udp.info.srcport;
                dstPort = udp.info.dstport;
                info = `${srcPort} → ${dstPort}`;
              } else if (ipInfo.protocol === 1) { // ICMP
                protocol = 'ICMP';
                info = 'Echo request/reply';
              }

              const packet = {
                no: this.packetCount,
                timestamp: timestamp.toISOString(),
                relativeTime: ((timestamp.getTime() - this.startTime) / 1000).toFixed(6),
                source: ipInfo.srcaddr,
                destination: ipInfo.dstaddr,
                protocol,
                length: capturedLength,
                info,
                srcPort,
                dstPort
              };

              packets.push(packet);
              this.emit('packet', packet);
            }
          } catch (parseError) {
            console.error('Error parsing packet:', parseError);
          }
        }

        console.log(`Loaded ${packets.length} packets from ${filepath}`);
        resolve({
          packetCount: packets.length,
          packets
        });

      } catch (error) {
        reject(error);
      }
    });
  }

  // Get available network devices
  static getDevices() {
    try {
      return Cap.deviceList();
    } catch (error) {
      console.error('Error getting devices:', error);
      return [];
    }
  }
}

module.exports = PacketCapture;
