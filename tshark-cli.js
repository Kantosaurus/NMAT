#!/usr/bin/env node

/**
 * TShark-like CLI Tool for NMAT
 * Command-line packet capture and analysis
 */

const PacketCapture = require('./packetCapture');
const StatisticsAnalyzer = require('./statisticsAnalyzer');
const { program } = require('commander');
const fs = require('fs');
const path = require('path');

class TSharkCLI {
  constructor() {
    this.packetCapture = null;
    this.statisticsAnalyzer = null;
    this.packets = [];
    this.captureOptions = {};
  }

  setupCommands() {
    program
      .name('nmat-tshark')
      .description('TShark-like CLI tool for network packet analysis')
      .version('1.0.0');

    // Live capture command
    program
      .command('capture')
      .description('Capture packets from a network interface')
      .requiredOption('-i, --interface <name>', 'Network interface name')
      .option('-c, --count <number>', 'Stop after capturing N packets', parseInt)
      .option('-a, --autostop <duration>', 'Stop after duration (seconds)', parseInt)
      .option('-f, --filter <bpf>', 'BPF capture filter')
      .option('-w, --write <file>', 'Write packets to file')
      .option('-F, --file-format <format>', 'Output file format (pcap, json, csv)', 'pcap')
      .option('-p, --no-promiscuous', 'Disable promiscuous mode')
      .option('-s, --snaplen <length>', 'Snapshot length', parseInt, 65535)
      .option('--statistics', 'Show statistics after capture')
      .option('-q, --quiet', 'Quiet mode (minimal output)')
      .option('-v, --verbose', 'Verbose output')
      .action((options) => this.handleCapture(options));

    // Read file command
    program
      .command('read')
      .description('Read and analyze packets from a file')
      .requiredOption('-r, --read <file>', 'Read from pcap file')
      .option('-c, --count <number>', 'Read only N packets', parseInt)
      .option('-Y, --display-filter <filter>', 'Display filter')
      .option('--statistics', 'Show statistics')
      .option('--protocol-hierarchy', 'Show protocol hierarchy')
      .option('--conversations', 'Show conversations')
      .option('--endpoints', 'Show endpoints')
      .option('--export <file>', 'Export results to file')
      .option('--export-format <format>', 'Export format (json, csv, xml)', 'json')
      .option('-q, --quiet', 'Quiet mode')
      .option('-v, --verbose', 'Verbose output')
      .action((options) => this.handleRead(options));

    // Statistics command
    program
      .command('statistics')
      .description('Generate statistics from pcap file')
      .requiredOption('-r, --read <file>', 'Read from pcap file')
      .option('--protocol-hierarchy', 'Protocol hierarchy statistics')
      .option('--conversations <type>', 'Conversations (ip, tcp, udp)', 'ip')
      .option('--endpoints <type>', 'Endpoints (ip, tcp, udp)', 'ip')
      .option('--io-graph', 'I/O graph data')
      .option('--expert', 'Expert alerts')
      .option('--srt', 'Service response time')
      .option('--export <file>', 'Export to file')
      .option('--format <format>', 'Output format (json, csv, text)', 'text')
      .action((options) => this.handleStatistics(options));

    // Export command
    program
      .command('export')
      .description('Export packets in various formats')
      .requiredOption('-r, --read <file>', 'Read from pcap file')
      .requiredOption('-w, --write <file>', 'Write to output file')
      .option('-F, --format <format>', 'Output format (json, csv, xml)', 'json')
      .option('-Y, --display-filter <filter>', 'Display filter')
      .action((options) => this.handleExport(options));

    // List interfaces command
    program
      .command('interfaces')
      .alias('list')
      .description('List available network interfaces')
      .action(() => this.handleListInterfaces());
  }

  async handleCapture(options) {
    console.log('Starting packet capture...');

    if (options.verbose) {
      console.log('Options:', options);
    }

    const captureOptions = {
      filter: options.filter || '',
      promiscuous: options.promiscuous !== false,
      snaplen: options.snaplen,
      maxPackets: options.count || 0,
      maxDuration: options.autostop || 0
    };

    this.packetCapture = new PacketCapture(options.interface, captureOptions);
    this.statisticsAnalyzer = new StatisticsAnalyzer();

    let packetCount = 0;

    this.packetCapture.on('packet', (packet) => {
      packetCount++;
      this.packets.push(packet);

      if (options.statistics) {
        this.statisticsAnalyzer.addPacket(packet);
      }

      if (!options.quiet) {
        this.printPacket(packet, options.verbose);
      }
    });

    this.packetCapture.on('stopped', (stats) => {
      console.log(`\nCapture stopped.`);
      console.log(`Packets captured: ${stats.packetCount}`);
      console.log(`Duration: ${stats.duration}s`);

      if (options.write) {
        this.writeOutput(options.write, options.fileFormat);
      }

      if (options.statistics) {
        this.printStatistics();
      }

      process.exit(0);
    });

    this.packetCapture.on('error', (error) => {
      console.error('Capture error:', error.message);
      process.exit(1);
    });

    try {
      this.packetCapture.start();
    } catch (error) {
      console.error('Failed to start capture:', error.message);
      process.exit(1);
    }
  }

  async handleRead(options) {
    console.log(`Reading from ${options.read}...`);

    this.packetCapture = new PacketCapture(null);
    this.statisticsAnalyzer = new StatisticsAnalyzer();

    try {
      const result = await this.packetCapture.loadPcapFile(options.read);

      this.packetCapture.on('packet', (packet) => {
        if (options.count && this.packets.length >= options.count) {
          return;
        }

        if (options.displayFilter && !this.matchesFilter(packet, options.displayFilter)) {
          return;
        }

        this.packets.push(packet);

        if (options.statistics) {
          this.statisticsAnalyzer.addPacket(packet);
        }

        if (!options.quiet) {
          this.printPacket(packet, options.verbose);
        }
      });

      // Wait a bit for all packets to be processed
      await new Promise(resolve => setTimeout(resolve, 1000));

      console.log(`\nTotal packets: ${this.packets.length}`);

      if (options.statistics) {
        this.printStatistics();
      }

      if (options.protocolHierarchy) {
        this.printProtocolHierarchy();
      }

      if (options.conversations) {
        this.printConversations();
      }

      if (options.endpoints) {
        this.printEndpoints();
      }

      if (options.export) {
        this.exportResults(options.export, options.exportFormat);
      }

    } catch (error) {
      console.error('Error reading file:', error.message);
      process.exit(1);
    }

    process.exit(0);
  }

  async handleStatistics(options) {
    console.log(`Generating statistics from ${options.read}...`);

    this.packetCapture = new PacketCapture(null);
    this.statisticsAnalyzer = new StatisticsAnalyzer();

    try {
      await this.packetCapture.loadPcapFile(options.read);

      this.packetCapture.on('packet', (packet) => {
        this.packets.push(packet);
        this.statisticsAnalyzer.addPacket(packet);
      });

      await new Promise(resolve => setTimeout(resolve, 1000));

      if (options.protocolHierarchy) {
        this.printProtocolHierarchy();
      }

      if (options.conversations) {
        this.printConversations(options.conversations);
      }

      if (options.endpoints) {
        this.printEndpoints(options.endpoints);
      }

      if (options.ioGraph) {
        this.printIOGraph();
      }

      if (options.expert) {
        this.printExpertAlerts();
      }

      if (options.srt) {
        this.printSRT();
      }

      if (options.export) {
        this.exportStatistics(options.export, options.format);
      }

    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }

    process.exit(0);
  }

  async handleExport(options) {
    console.log(`Exporting ${options.read} to ${options.write}...`);

    this.packetCapture = new PacketCapture(null);

    try {
      await this.packetCapture.loadPcapFile(options.read);

      this.packetCapture.on('packet', (packet) => {
        if (options.displayFilter && !this.matchesFilter(packet, options.displayFilter)) {
          return;
        }

        this.packets.push(packet);
      });

      await new Promise(resolve => setTimeout(resolve, 1000));

      let content;

      if (options.format === 'json') {
        content = JSON.stringify(this.packets, null, 2);
      } else if (options.format === 'csv') {
        content = this.packetsToCSV(this.packets);
      } else if (options.format === 'xml') {
        content = this.packetsToXML(this.packets);
      }

      fs.writeFileSync(options.write, content);
      console.log(`Exported ${this.packets.length} packets to ${options.write}`);

    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }

    process.exit(0);
  }

  handleListInterfaces() {
    try {
      const Cap = require('cap').Cap;
      const devices = Cap.deviceList();

      console.log('\nAvailable network interfaces:\n');

      devices.forEach((device, index) => {
        console.log(`${index + 1}. ${device.name}`);
        if (device.description) {
          console.log(`   Description: ${device.description}`);
        }
        if (device.addresses && device.addresses.length > 0) {
          console.log(`   Addresses:`);
          device.addresses.forEach(addr => {
            console.log(`     - ${addr.addr}`);
          });
        }
        console.log('');
      });

    } catch (error) {
      console.error('Error listing interfaces:', error.message);
      process.exit(1);
    }

    process.exit(0);
  }

  printPacket(packet, verbose) {
    if (verbose) {
      console.log(`[${packet.no}] ${packet.timestamp} ${packet.source} → ${packet.destination} ${packet.protocol} Length: ${packet.length} ${packet.info}`);
    } else {
      console.log(`${packet.no}\t${packet.source}\t${packet.destination}\t${packet.protocol}\t${packet.length}`);
    }
  }

  printStatistics() {
    console.log('\n=== STATISTICS ===\n');

    const hierarchy = this.statisticsAnalyzer.getProtocolHierarchy();
    console.log('Protocol Distribution:');
    hierarchy.forEach(proto => {
      console.log(`  ${proto.protocol}: ${proto.packets} packets (${proto.percentage}%) - ${proto.bytes} bytes`);
    });

    console.log('');
  }

  printProtocolHierarchy() {
    console.log('\n=== PROTOCOL HIERARCHY ===\n');

    const hierarchy = this.statisticsAnalyzer.getProtocolHierarchy();

    console.log('Protocol                Packets      Bytes        Percentage');
    console.log('─'.repeat(70));

    hierarchy.forEach(proto => {
      const name = proto.protocol.padEnd(20);
      const packets = proto.packets.toString().padStart(8);
      const bytes = proto.bytes.toString().padStart(12);
      const pct = proto.percentage.padStart(6);

      console.log(`${name}    ${packets}    ${bytes}    ${pct}%`);
    });

    console.log('');
  }

  printConversations(type = 'ip') {
    console.log(`\n=== CONVERSATIONS (${type.toUpperCase()}) ===\n`);

    const conversations = this.statisticsAnalyzer.getConversations(type);

    if (type === 'ip') {
      console.log('Address A            Address B            Packets    Bytes      Duration');
      console.log('─'.repeat(80));

      conversations.slice(0, 20).forEach(conv => {
        const addrA = conv.addressA.padEnd(20);
        const addrB = conv.addressB.padEnd(20);
        const packets = conv.packets.toString().padStart(8);
        const bytes = ((conv.bytesAtoB || 0) + (conv.bytesBtoA || 0)).toString().padStart(10);
        const duration = conv.duration.padStart(8);

        console.log(`${addrA} ${addrB} ${packets}  ${bytes}  ${duration}s`);
      });
    }

    console.log('');
  }

  printEndpoints(type = 'ip') {
    console.log(`\n=== ENDPOINTS (${type.toUpperCase()}) ===\n`);

    const endpoints = this.statisticsAnalyzer.getEndpoints(type);

    console.log('Address              Packets    TX Bytes   RX Bytes');
    console.log('─'.repeat(60));

    endpoints.slice(0, 20).forEach(endpoint => {
      const addr = endpoint.address.padEnd(20);
      const packets = endpoint.packets.toString().padStart(8);
      const txBytes = endpoint.txBytes.toString().padStart(10);
      const rxBytes = endpoint.rxBytes.toString().padStart(10);

      console.log(`${addr} ${packets}  ${txBytes}  ${rxBytes}`);
    });

    console.log('');
  }

  printIOGraph() {
    console.log('\n=== I/O GRAPH ===\n');

    const ioData = this.statisticsAnalyzer.getIOGraphData();

    console.log('Time                 Packets    Bytes      Avg Size');
    console.log('─'.repeat(65));

    ioData.forEach(dp => {
      const time = new Date(dp.time).toLocaleTimeString().padEnd(20);
      const packets = dp.packets.toString().padStart(8);
      const bytes = dp.bytes.toString().padStart(10);
      const avgSize = dp.avgPacketSize.toFixed(2).padStart(8);

      console.log(`${time} ${packets}  ${bytes}  ${avgSize}B`);
    });

    console.log('');
  }

  printExpertAlerts() {
    console.log('\n=== EXPERT ALERTS ===\n');

    const alerts = this.statisticsAnalyzer.getExpertAlerts();

    alerts.forEach(alert => {
      console.log(`[${alert.severity.toUpperCase()}] ${alert.message}`);
      console.log(`  ${alert.details}`);
      console.log(`  Packet: ${alert.packet}, Protocol: ${alert.protocol}`);
      console.log('');
    });
  }

  printSRT() {
    console.log('\n=== SERVICE RESPONSE TIME ===\n');

    const srt = this.statisticsAnalyzer.getSRTStatistics();

    console.log('Stream                                   Packets    Avg(ms)    Min(ms)    Max(ms)');
    console.log('─'.repeat(90));

    srt.forEach(stat => {
      const stream = stat.stream.substring(0, 40).padEnd(40);
      const packets = stat.packets.toString().padStart(8);
      const avg = stat.avgResponseTime.padStart(10);
      const min = stat.minResponseTime.padStart(10);
      const max = stat.maxResponseTime.padStart(10);

      console.log(`${stream} ${packets}  ${avg}  ${min}  ${max}`);
    });

    console.log('');
  }

  writeOutput(filename, format) {
    let content;

    if (format === 'json') {
      content = JSON.stringify(this.packets, null, 2);
    } else if (format === 'csv') {
      content = this.packetsToCSV(this.packets);
    }

    fs.writeFileSync(filename, content);
    console.log(`Output written to ${filename}`);
  }

  exportResults(filename, format) {
    if (format === 'json') {
      fs.writeFileSync(filename, JSON.stringify(this.packets, null, 2));
    } else if (format === 'csv') {
      fs.writeFileSync(filename, this.packetsToCSV(this.packets));
    }

    console.log(`Results exported to ${filename}`);
  }

  exportStatistics(filename, format) {
    let content;

    if (format === 'json') {
      content = this.statisticsAnalyzer.exportToJSON();
    } else if (format === 'xml') {
      content = this.statisticsAnalyzer.exportToXML();
    } else {
      // Text format
      content = 'Statistics Report\n\n';
      content += '=== Protocol Hierarchy ===\n\n';

      const hierarchy = this.statisticsAnalyzer.getProtocolHierarchy();
      hierarchy.forEach(proto => {
        content += `${proto.protocol}: ${proto.packets} packets (${proto.percentage}%)\n`;
      });

      content += '\n=== Expert Alerts ===\n\n';
      const alerts = this.statisticsAnalyzer.getExpertAlerts();
      alerts.forEach(alert => {
        content += `[${alert.severity.toUpperCase()}] ${alert.message}\n`;
        content += `  ${alert.details}\n\n`;
      });
    }

    fs.writeFileSync(filename, content);
    console.log(`Statistics exported to ${filename}`);
  }

  packetsToCSV(packets) {
    const headers = 'No,Timestamp,Source,Destination,Protocol,Length,Info\n';
    const rows = packets.map(p =>
      `${p.no},"${p.timestamp}","${p.source}","${p.destination}",${p.protocol},${p.length},"${p.info}"`
    ).join('\n');

    return headers + rows;
  }

  packetsToXML(packets) {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<packets>\n';

    packets.forEach(p => {
      xml += `  <packet no="${p.no}" timestamp="${p.timestamp}" protocol="${p.protocol}" length="${p.length}">\n`;
      xml += `    <source>${p.source}</source>\n`;
      xml += `    <destination>${p.destination}</destination>\n`;
      xml += `    <info>${p.info}</info>\n`;
      xml += `  </packet>\n`;
    });

    xml += '</packets>';

    return xml;
  }

  matchesFilter(packet, filter) {
    // Simple filter matching (can be expanded)
    const lowerFilter = filter.toLowerCase();

    if (lowerFilter.includes(':')) {
      const [field, value] = lowerFilter.split(':').map(s => s.trim());

      if (field === 'protocol') {
        return packet.protocol.toLowerCase() === value;
      } else if (field === 'src' || field === 'source') {
        return packet.source.includes(value);
      } else if (field === 'dst' || field === 'destination') {
        return packet.destination.includes(value);
      }
    }

    // Default: search in all string fields
    return Object.values(packet).some(val =>
      typeof val === 'string' && val.toLowerCase().includes(lowerFilter)
    );
  }

  run() {
    this.setupCommands();
    program.parse(process.argv);
  }
}

// Run if executed directly
if (require.main === module) {
  const cli = new TSharkCLI();
  cli.run();
}

module.exports = TSharkCLI;
