const dns = require('dns').promises;
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class StatisticsAnalyzer {
  constructor() {
    this.packets = [];
    this.protocolHierarchy = {};
    this.conversations = {
      ip: new Map(),
      tcp: new Map(),
      udp: new Map()
    };
    this.endpoints = {
      ip: new Map(),
      tcp: new Map(),
      udp: new Map()
    };
    this.ioGraphData = [];
    this.tcpStreams = new Map();
    this.expertAlerts = [];

    // Name resolution caches
    this.hostnameCache = new Map();
    this.macVendorCache = new Map();
    this.serviceCache = new Map();

    // Load MAC vendor database
    this.loadMacVendors();
    this.loadServiceNames();
  }

  loadMacVendors() {
    // Common MAC vendor prefixes (OUI - Organizationally Unique Identifier)
    this.macVendorCache.set('00:00:0c', 'Cisco Systems');
    this.macVendorCache.set('00:50:56', 'VMware');
    this.macVendorCache.set('00:1b:63', 'Apple');
    this.macVendorCache.set('00:0c:29', 'VMware');
    this.macVendorCache.set('08:00:27', 'Oracle VirtualBox');
    this.macVendorCache.set('52:54:00', 'QEMU/KVM');
    this.macVendorCache.set('00:15:5d', 'Microsoft Hyper-V');
    this.macVendorCache.set('00:16:3e', 'Xen');
    this.macVendorCache.set('00:1c:42', 'Parallels');
    this.macVendorCache.set('ac:de:48', 'Intel Corporate');
    this.macVendorCache.set('00:03:ff', 'Microsoft');
    this.macVendorCache.set('00:0d:3a', 'Microsoft');
    this.macVendorCache.set('b8:27:eb', 'Raspberry Pi Foundation');
    this.macVendorCache.set('dc:a6:32', 'Raspberry Pi Foundation');
    this.macVendorCache.set('e4:5f:01', 'Raspberry Pi Foundation');
    this.macVendorCache.set('00:e0:4c', 'Realtek');
    this.macVendorCache.set('00:25:9c', 'Cisco-Linksys');
    this.macVendorCache.set('00:1a:70', 'Linksys');
  }

  loadServiceNames() {
    // Common port to service mappings
    this.serviceCache.set(20, 'FTP-DATA');
    this.serviceCache.set(21, 'FTP');
    this.serviceCache.set(22, 'SSH');
    this.serviceCache.set(23, 'Telnet');
    this.serviceCache.set(25, 'SMTP');
    this.serviceCache.set(53, 'DNS');
    this.serviceCache.set(67, 'DHCP-Server');
    this.serviceCache.set(68, 'DHCP-Client');
    this.serviceCache.set(69, 'TFTP');
    this.serviceCache.set(80, 'HTTP');
    this.serviceCache.set(110, 'POP3');
    this.serviceCache.set(123, 'NTP');
    this.serviceCache.set(143, 'IMAP');
    this.serviceCache.set(161, 'SNMP');
    this.serviceCache.set(162, 'SNMP-TRAP');
    this.serviceCache.set(179, 'BGP');
    this.serviceCache.set(389, 'LDAP');
    this.serviceCache.set(443, 'HTTPS');
    this.serviceCache.set(445, 'SMB');
    this.serviceCache.set(465, 'SMTPS');
    this.serviceCache.set(514, 'Syslog');
    this.serviceCache.set(587, 'SMTP-Submission');
    this.serviceCache.set(636, 'LDAPS');
    this.serviceCache.set(993, 'IMAPS');
    this.serviceCache.set(995, 'POP3S');
    this.serviceCache.set(1433, 'MS-SQL');
    this.serviceCache.set(1521, 'Oracle-DB');
    this.serviceCache.set(3306, 'MySQL');
    this.serviceCache.set(3389, 'RDP');
    this.serviceCache.set(5432, 'PostgreSQL');
    this.serviceCache.set(5900, 'VNC');
    this.serviceCache.set(6379, 'Redis');
    this.serviceCache.set(8080, 'HTTP-Proxy');
    this.serviceCache.set(8443, 'HTTPS-Alt');
    this.serviceCache.set(27017, 'MongoDB');
  }

  // Name Resolution Functions
  async resolveHostname(ip) {
    if (this.hostnameCache.has(ip)) {
      return this.hostnameCache.get(ip);
    }

    try {
      const hostnames = await dns.reverse(ip);
      if (hostnames && hostnames.length > 0) {
        this.hostnameCache.set(ip, hostnames[0]);
        return hostnames[0];
      }
    } catch (error) {
      // DNS lookup failed, return IP
    }

    this.hostnameCache.set(ip, ip);
    return ip;
  }

  resolveMacVendor(mac) {
    if (!mac) return 'Unknown';

    // Extract OUI (first 3 octets)
    const oui = mac.toLowerCase().split(':').slice(0, 3).join(':');
    return this.macVendorCache.get(oui) || 'Unknown';
  }

  resolveService(port) {
    return this.serviceCache.get(port) || `Port ${port}`;
  }

  // Add packet for analysis
  addPacket(packet) {
    this.packets.push(packet);

    // Update protocol hierarchy
    this.updateProtocolHierarchy(packet);

    // Update conversations
    this.updateConversations(packet);

    // Update endpoints
    this.updateEndpoints(packet);

    // Update IO graph data
    this.updateIOGraph(packet);

    // Update TCP stream tracking
    if (packet.protocol === 'TCP') {
      this.updateTCPStream(packet);
    }

    // Run expert system analysis
    this.runExpertAnalysis(packet);
  }

  updateProtocolHierarchy(packet) {
    const protocol = packet.protocol;

    if (!this.protocolHierarchy[protocol]) {
      this.protocolHierarchy[protocol] = {
        packets: 0,
        bytes: 0,
        percentage: 0
      };
    }

    this.protocolHierarchy[protocol].packets++;
    this.protocolHierarchy[protocol].bytes += packet.length;

    // Calculate percentages
    const totalPackets = this.packets.length;
    for (const proto in this.protocolHierarchy) {
      this.protocolHierarchy[proto].percentage =
        ((this.protocolHierarchy[proto].packets / totalPackets) * 100).toFixed(2);
    }
  }

  updateConversations(packet) {
    // IP conversations
    if (packet.source && packet.destination) {
      const ipKey = this.getConversationKey(packet.source, packet.destination);

      if (!this.conversations.ip.has(ipKey)) {
        this.conversations.ip.set(ipKey, {
          addressA: packet.source,
          addressB: packet.destination,
          packets: 0,
          bytesAtoB: 0,
          bytesBtoA: 0,
          packetsAtoB: 0,
          packetsBtoA: 0,
          start: packet.timestamp,
          duration: 0
        });
      }

      const conv = this.conversations.ip.get(ipKey);
      conv.packets++;

      // Determine direction
      if (packet.source < packet.destination) {
        conv.bytesAtoB += packet.length;
        conv.packetsAtoB++;
      } else {
        conv.bytesBtoA += packet.length;
        conv.packetsBtoA++;
      }

      // Update duration
      const startTime = new Date(conv.start).getTime();
      const currentTime = new Date(packet.timestamp).getTime();
      conv.duration = ((currentTime - startTime) / 1000).toFixed(3);
    }

    // TCP/UDP conversations
    if (packet.protocol === 'TCP' || packet.protocol === 'UDP') {
      const proto = packet.protocol.toLowerCase();
      const key = this.getPortConversationKey(
        packet.source, packet.srcPort,
        packet.destination, packet.dstPort
      );

      if (!this.conversations[proto].has(key)) {
        this.conversations[proto].set(key, {
          addressA: packet.source,
          portA: packet.srcPort,
          addressB: packet.destination,
          portB: packet.dstPort,
          packets: 0,
          bytes: 0,
          start: packet.timestamp,
          duration: 0
        });
      }

      const conv = this.conversations[proto].get(key);
      conv.packets++;
      conv.bytes += packet.length;

      const startTime = new Date(conv.start).getTime();
      const currentTime = new Date(packet.timestamp).getTime();
      conv.duration = ((currentTime - startTime) / 1000).toFixed(3);
    }
  }

  updateEndpoints(packet) {
    // Update source endpoint
    if (packet.source) {
      this.updateEndpoint('ip', packet.source, packet.length, true);
    }

    // Update destination endpoint
    if (packet.destination) {
      this.updateEndpoint('ip', packet.destination, packet.length, false);
    }

    // TCP/UDP endpoints
    if (packet.protocol === 'TCP' || packet.protocol === 'UDP') {
      const proto = packet.protocol.toLowerCase();

      if (packet.source && packet.srcPort) {
        const key = `${packet.source}:${packet.srcPort}`;
        this.updateEndpoint(proto, key, packet.length, true, packet.srcPort);
      }

      if (packet.destination && packet.dstPort) {
        const key = `${packet.destination}:${packet.dstPort}`;
        this.updateEndpoint(proto, key, packet.length, false, packet.dstPort);
      }
    }
  }

  updateEndpoint(type, key, bytes, isSender, port = null) {
    if (!this.endpoints[type].has(key)) {
      this.endpoints[type].set(key, {
        address: key,
        port: port,
        packets: 0,
        bytes: 0,
        txPackets: 0,
        txBytes: 0,
        rxPackets: 0,
        rxBytes: 0
      });
    }

    const endpoint = this.endpoints[type].get(key);
    endpoint.packets++;
    endpoint.bytes += bytes;

    if (isSender) {
      endpoint.txPackets++;
      endpoint.txBytes += bytes;
    } else {
      endpoint.rxPackets++;
      endpoint.rxBytes += bytes;
    }
  }

  updateIOGraph(packet) {
    // Group packets by time intervals (1 second)
    const timestamp = new Date(packet.timestamp).getTime();
    const interval = Math.floor(timestamp / 1000) * 1000;

    let dataPoint = this.ioGraphData.find(dp => dp.time === interval);

    if (!dataPoint) {
      dataPoint = {
        time: interval,
        packets: 0,
        bytes: 0,
        avgPacketSize: 0,
        protocols: {}
      };
      this.ioGraphData.push(dataPoint);
      this.ioGraphData.sort((a, b) => a.time - b.time);
    }

    dataPoint.packets++;
    dataPoint.bytes += packet.length;
    dataPoint.avgPacketSize = dataPoint.bytes / dataPoint.packets;

    // Track protocol distribution per interval
    if (!dataPoint.protocols[packet.protocol]) {
      dataPoint.protocols[packet.protocol] = 0;
    }
    dataPoint.protocols[packet.protocol]++;
  }

  updateTCPStream(packet) {
    if (!packet.srcPort || !packet.dstPort) return;

    const streamKey = this.getPortConversationKey(
      packet.source, packet.srcPort,
      packet.destination, packet.dstPort
    );

    if (!this.tcpStreams.has(streamKey)) {
      this.tcpStreams.set(streamKey, {
        packets: [],
        seqNumbers: [],
        ackNumbers: [],
        timestamps: [],
        rtts: [],
        retransmissions: 0,
        outOfOrder: 0
      });
    }

    const stream = this.tcpStreams.get(streamKey);
    stream.packets.push(packet);
    stream.timestamps.push(new Date(packet.timestamp).getTime());

    // Extract TCP details if available in packet info
    const tcpInfo = this.parseTCPInfo(packet.info);
    if (tcpInfo) {
      if (tcpInfo.seq) stream.seqNumbers.push(tcpInfo.seq);
      if (tcpInfo.ack) stream.ackNumbers.push(tcpInfo.ack);
    }
  }

  parseTCPInfo(info) {
    if (!info) return null;

    const seqMatch = info.match(/Seq=(\d+)/);
    const ackMatch = info.match(/Ack=(\d+)/);

    return {
      seq: seqMatch ? parseInt(seqMatch[1]) : null,
      ack: ackMatch ? parseInt(ackMatch[1]) : null
    };
  }

  runExpertAnalysis(packet) {
    // Detect TCP retransmissions
    if (packet.protocol === 'TCP') {
      this.detectRetransmission(packet);
    }

    // Detect protocol violations
    this.detectProtocolViolations(packet);

    // Detect suspicious patterns
    this.detectSuspiciousPatterns(packet);
  }

  detectRetransmission(packet) {
    const streamKey = this.getPortConversationKey(
      packet.source, packet.srcPort,
      packet.destination, packet.dstPort
    );

    const stream = this.tcpStreams.get(streamKey);
    if (!stream || stream.seqNumbers.length < 2) return;

    // Check if current sequence number matches a previous one
    const currentSeq = stream.seqNumbers[stream.seqNumbers.length - 1];
    const previousSeqs = stream.seqNumbers.slice(0, -1);

    if (previousSeqs.includes(currentSeq)) {
      stream.retransmissions++;

      this.expertAlerts.push({
        severity: 'medium',
        category: 'Sequence',
        protocol: 'TCP',
        message: 'TCP Retransmission',
        details: `Retransmission detected for ${packet.source}:${packet.srcPort} → ${packet.destination}:${packet.dstPort}`,
        packet: packet.no,
        timestamp: packet.timestamp
      });
    }
  }

  detectProtocolViolations(packet) {
    // Check for malformed packets (basic checks)
    if (packet.length < 20 && packet.protocol !== 'ARP') {
      this.expertAlerts.push({
        severity: 'high',
        category: 'Malformed',
        protocol: packet.protocol,
        message: 'Malformed Packet',
        details: `Packet ${packet.no} is unusually small (${packet.length} bytes)`,
        packet: packet.no,
        timestamp: packet.timestamp
      });
    }

    // Check for unusual port usage
    if (packet.protocol === 'TCP' || packet.protocol === 'UDP') {
      if (packet.srcPort < 1024 && packet.dstPort < 1024) {
        this.expertAlerts.push({
          severity: 'low',
          category: 'Unusual Traffic',
          protocol: packet.protocol,
          message: 'Both ports are privileged',
          details: `Communication between privileged ports ${packet.srcPort} and ${packet.dstPort}`,
          packet: packet.no,
          timestamp: packet.timestamp
        });
      }
    }
  }

  detectSuspiciousPatterns(packet) {
    // Detect potential port scans
    const recentPackets = this.packets.slice(-100);
    const portScans = new Map();

    for (const p of recentPackets) {
      if (p.source === packet.source && p.protocol === 'TCP') {
        const key = p.source;
        if (!portScans.has(key)) {
          portScans.set(key, new Set());
        }
        portScans.get(key).add(p.dstPort);

        // If more than 20 different destination ports from same source
        if (portScans.get(key).size > 20) {
          this.expertAlerts.push({
            severity: 'critical',
            category: 'Security',
            protocol: 'TCP',
            message: 'Possible Port Scan',
            details: `${packet.source} is connecting to many different ports (${portScans.get(key).size} ports)`,
            packet: packet.no,
            timestamp: packet.timestamp
          });
          portScans.get(key).clear(); // Reset to avoid duplicate alerts
        }
      }
    }
  }

  getConversationKey(addr1, addr2) {
    return addr1 < addr2 ? `${addr1}-${addr2}` : `${addr2}-${addr1}`;
  }

  getPortConversationKey(addr1, port1, addr2, port2) {
    if (addr1 < addr2) {
      return `${addr1}:${port1}-${addr2}:${port2}`;
    } else if (addr1 > addr2) {
      return `${addr2}:${port2}-${addr1}:${port1}`;
    } else {
      return port1 < port2 ?
        `${addr1}:${port1}-${addr2}:${port2}` :
        `${addr2}:${port2}-${addr1}:${port1}`;
    }
  }

  // Export functions
  getProtocolHierarchy() {
    return Object.entries(this.protocolHierarchy)
      .map(([protocol, stats]) => ({
        protocol,
        ...stats
      }))
      .sort((a, b) => b.packets - a.packets);
  }

  getConversations(type = 'ip') {
    return Array.from(this.conversations[type].values())
      .sort((a, b) => b.packets - a.packets);
  }

  getEndpoints(type = 'ip') {
    return Array.from(this.endpoints[type].values())
      .sort((a, b) => b.packets - a.packets);
  }

  getIOGraphData() {
    return this.ioGraphData;
  }

  getTCPStreamStats(streamKey) {
    return this.tcpStreams.get(streamKey);
  }

  getAllTCPStreams() {
    const streams = [];
    for (const [key, stream] of this.tcpStreams) {
      streams.push({
        stream: key,
        packets: stream.packets.length,
        retransmissions: stream.retransmissions,
        outOfOrder: stream.outOfOrder
      });
    }
    return streams.sort((a, b) => b.packets - a.packets);
  }

  getExpertAlerts() {
    return this.expertAlerts.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
  }

  // Service Response Time statistics
  getSRTStatistics() {
    const srt = new Map();

    for (const [key, stream] of this.tcpStreams) {
      if (stream.timestamps.length < 2) continue;

      const times = [];
      for (let i = 1; i < stream.timestamps.length; i++) {
        times.push(stream.timestamps[i] - stream.timestamps[i - 1]);
      }

      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const minTime = Math.min(...times);
      const maxTime = Math.max(...times);

      srt.set(key, {
        stream: key,
        packets: stream.packets.length,
        avgResponseTime: avgTime.toFixed(2),
        minResponseTime: minTime.toFixed(2),
        maxResponseTime: maxTime.toFixed(2)
      });
    }

    return Array.from(srt.values());
  }

  // Flow graph data
  getFlowGraph() {
    const flows = [];

    for (const packet of this.packets) {
      flows.push({
        no: packet.no,
        timestamp: packet.timestamp,
        source: packet.source,
        destination: packet.destination,
        protocol: packet.protocol,
        info: packet.info,
        length: packet.length
      });
    }

    return flows;
  }

  // Clear all statistics
  clear() {
    this.packets = [];
    this.protocolHierarchy = {};
    this.conversations = {
      ip: new Map(),
      tcp: new Map(),
      udp: new Map()
    };
    this.endpoints = {
      ip: new Map(),
      tcp: new Map(),
      udp: new Map()
    };
    this.ioGraphData = [];
    this.tcpStreams = new Map();
    this.expertAlerts = [];
  }

  // Export statistics to various formats
  exportToJSON() {
    return JSON.stringify({
      protocolHierarchy: this.getProtocolHierarchy(),
      conversations: {
        ip: this.getConversations('ip'),
        tcp: this.getConversations('tcp'),
        udp: this.getConversations('udp')
      },
      endpoints: {
        ip: this.getEndpoints('ip'),
        tcp: this.getEndpoints('tcp'),
        udp: this.getEndpoints('udp')
      },
      ioGraph: this.getIOGraphData(),
      tcpStreams: this.getAllTCPStreams(),
      expertAlerts: this.getExpertAlerts(),
      srtStats: this.getSRTStatistics()
    }, null, 2);
  }

  exportToCSV(type) {
    let rows = [];
    let headers = [];

    switch (type) {
      case 'protocol-hierarchy':
        headers = ['Protocol', 'Packets', 'Bytes', 'Percentage'];
        rows = this.getProtocolHierarchy().map(p =>
          [p.protocol, p.packets, p.bytes, p.percentage]
        );
        break;

      case 'conversations-ip':
        headers = ['Address A', 'Address B', 'Packets', 'Bytes A→B', 'Bytes B→A', 'Duration'];
        rows = this.getConversations('ip').map(c =>
          [c.addressA, c.addressB, c.packets, c.bytesAtoB, c.bytesBtoA, c.duration]
        );
        break;

      case 'endpoints-ip':
        headers = ['Address', 'Packets', 'Bytes', 'TX Packets', 'TX Bytes', 'RX Packets', 'RX Bytes'];
        rows = this.getEndpoints('ip').map(e =>
          [e.address, e.packets, e.bytes, e.txPackets, e.txBytes, e.rxPackets, e.rxBytes]
        );
        break;

      case 'expert-alerts':
        headers = ['Severity', 'Category', 'Protocol', 'Message', 'Details', 'Packet', 'Timestamp'];
        rows = this.getExpertAlerts().map(a =>
          [a.severity, a.category, a.protocol, a.message, a.details, a.packet, a.timestamp]
        );
        break;
    }

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');

    return csvContent;
  }

  exportToXML() {
    const xmlParts = ['<?xml version="1.0" encoding="UTF-8"?>'];
    xmlParts.push('<statistics>');

    // Protocol Hierarchy
    xmlParts.push('  <protocol-hierarchy>');
    for (const p of this.getProtocolHierarchy()) {
      xmlParts.push(`    <protocol name="${p.protocol}" packets="${p.packets}" bytes="${p.bytes}" percentage="${p.percentage}"/>`);
    }
    xmlParts.push('  </protocol-hierarchy>');

    // Expert Alerts
    xmlParts.push('  <expert-alerts>');
    for (const alert of this.getExpertAlerts()) {
      xmlParts.push(`    <alert severity="${alert.severity}" category="${alert.category}" protocol="${alert.protocol}" packet="${alert.packet}">`);
      xmlParts.push(`      <message>${alert.message}</message>`);
      xmlParts.push(`      <details>${alert.details}</details>`);
      xmlParts.push(`    </alert>`);
    }
    xmlParts.push('  </expert-alerts>');

    xmlParts.push('</statistics>');

    return xmlParts.join('\n');
  }
}

module.exports = StatisticsAnalyzer;
