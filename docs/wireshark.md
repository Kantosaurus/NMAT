# 🦈 Wireshark: Full Capabilities and Toolsets

Wireshark is an open-source, industry-standard **network protocol analyzer** used by cybersecurity professionals, network engineers, and researchers for real-time packet inspection, troubleshooting, and analysis.

---

## 🧩 1. Packet Capture Capabilities

- **Real-time Capture**: Capture live network traffic from Ethernet, Wi-Fi, Bluetooth, USB, or loopback interfaces.
- **Offline Analysis**: Load and analyze pre-captured `.pcap` or `.pcapng` files.
- **Promiscuous Mode**: Capture all packets visible to the network adapter, not just those addressed to your host.
- **Monitor Mode (Wi-Fi)**: Capture raw IEEE 802.11 frames including management and control packets.
- **Remote Capture**: Capture packets from remote interfaces using protocols such as SSH, RPCAP, or extcap.
- **Custom Capture Filters**: Define filters using libpcap syntax to capture only relevant traffic (e.g., TCP port 443).
- **Ring Buffers**: Automatically create new capture files when a specified size or time limit is reached.
- **Time-based Capture Control**: Stop or rotate captures based on duration or packet count.

---

## 🔍 2. Deep Packet Inspection and Analysis

- **Over 3,000 Supported Protocols**, including:
  - Layer 2: Ethernet, ARP, PPP, VLAN, 802.1Q
  - Layer 3: IPv4, IPv6, ICMP, OSPF, BGP
  - Layer 4: TCP, UDP, SCTP, DCCP
  - Application Layer: DNS, HTTP, HTTPS, TLS/SSL, SSH, SMTP, IMAP, POP3, FTP, DHCP, SNMP, SIP, RTP, MQTT, SMB, NFS, and many more.
- **Automatic Protocol Detection**: Identifies protocols even when using non-standard ports.
- **Decryption Support**:
  - TLS/SSL with provided session keys or private keys.
  - WPA/WPA2/WPA3 for Wi-Fi traffic (with capture of 4-way handshake).
  - IPsec, Kerberos, and other encryption protocols (when keys are available).
- **Stream Reassembly**: Reconstructs TCP and UDP streams for full-session analysis.
- **Packet Coloring Rules**: Highlights packets of interest based on filters and traffic type.
- **Follow Streams**: View full conversations (TCP, UDP, HTTP, TLS) in order.
- **Expert Information System**: Flags protocol anomalies, retransmissions, malformed packets, and performance issues.

---

## 🧠 3. Analysis Tools and Features

- **Display Filters**: Advanced filter engine using Wireshark’s custom syntax (e.g., `ip.src == 192.168.1.1 && tcp.port == 80`).
- **Statistics and Graphs**:
  - Protocol Hierarchy Statistics
  - Conversations (by IP, port, protocol)
  - Endpoints (host-level summaries)
  - IO Graphs (packet rate, throughput, latency over time)
  - TCP Stream Graphs (Round-trip time, sequence numbers, window scaling)
  - Flow Graphs (sequence of conversations)
  - Service Response Time (SRT) statistics
- **Name Resolution**: Resolve IPs to hostnames, MACs to vendors, ports to services.
- **Export Functions**: Export packets, streams, or statistical summaries to text, CSV, JSON, or XML.
- **Expert System Alerts**: Highlights retransmissions, malformed packets, and protocol violations.

---

## ⚙️ 4. Extensibility and Customization

- **Custom Plugins**:
  - Create dissectors in C, Lua, or Python.
  - Extend UI or automate workflows.
- **TShark CLI Tool**:
  - Command-line version of Wireshark for remote or automated analysis.
  - Supports filters, statistics, and export options identical to the GUI.
- **Extcap Interface**:
  - Integrate with third-party capture utilities (e.g., for USB, Bluetooth, or SDN environments).
- **Configuration Profiles**:
  - Save display filters, layouts, and color schemes per project.
- **Custom Columns**:
  - Add and arrange columns for any packet field dynamically.
- **Lua Scripting**:
  - Automate repetitive analysis or custom dissector logic.

---

## 📊 5. Visualization and Reporting

- **IO Graphs**: Time-based traffic visualization (packet rate, bytes per second, etc.).
- **TCP Stream Graphs**: Visualize congestion windows, round-trip times, and throughput.
- **Flow Graphs**: Sequence diagrams of communications between endpoints.
- **Packet Length and Timing Graphs**: Analyze jitter, delay, and packet size distribution.
- **Conversation Maps**: Visual summaries of network flows.
- **Export to CSV, JSON, XML, and PSML** for reporting and further analysis in external tools.

---

## 🧱 6. Network Troubleshooting Use Cases

- **Latency Diagnosis**: Measure TCP handshake and round-trip delays.
- **Dropped Packets and Retransmission Detection**.
- **Protocol Errors**: Identify malformed packets or misconfigurations.
- **Bandwidth Analysis**: Determine top talkers and data-heavy endpoints.
- **DNS Troubleshooting**: Inspect query/response delays and failures.
- **VoIP Analysis**: Decode SIP, RTP, and jitter metrics; reconstruct audio streams.
- **HTTP/HTTPS Debugging**: View requests, responses, cookies, and headers.
- **Security Auditing**:
  - Detect suspicious traffic patterns or unauthorized connections.
  - Identify cleartext credentials or insecure protocols.

---

## 🔒 7. Security and Forensics Applications

- **Network Intrusion Analysis**: Identify suspicious flows and packet anomalies.
- **Malware Traffic Analysis**: Inspect Command-and-Control (C2) communications.
- **Decryption and Inspection** (when permitted): Analyze encrypted sessions with known keys.
- **PCAP Forensics**: Replay captured sessions for incident response.
- **Detection of Network Scans and Reconnaissance**.
- **Credential Leakage Detection** (FTP, Telnet, HTTP Basic Auth).

---

## 🧰 8. Integration and Export

- **File Format Support**:
  - PCAP, PCAPNG, ERF, and many others.
- **Export to**:
  - CSV, JSON, XML, plain text, PostScript, or PDML.
- **Interoperability with Other Tools**:
  - Tshark, tcpdump, Zeek (Bro), Suricata, Snort, NetworkMiner, and Splunk.
- **Command-Line Automation**:
  - Batch processing of captures with TShark or editcap.

---

## 💻 9. Companion Tools

- **TShark** – Command-line analyzer for headless environments.
- **Editcap** – Trim, merge, or split capture files.
- **Mergecap** – Combine multiple capture files into one.
- **Capinfos** – Display summary information about capture files.
- **Text2pcap** – Convert hex dumps into `.pcap` files.
- **Rawshark** – Extract data fields from `.pcap` for scripting.
- **Reordercap** – Reorder packets chronologically in a capture file.

---

## 🧩 10. Supported Platforms

- Windows
- macOS
- Linux (Ubuntu, Fedora, Arch, etc.)
- BSD, Solaris, and other UNIX-like systems

---

## 🧭 Summary

Wireshark is not just a packet sniffer — it’s a **comprehensive suite** for network analysis, troubleshooting, protocol development, and cybersecurity forensics. Its deep inspection capabilities, extensive protocol support, visualization tools, and scripting flexibility make it indispensable for both academic research and professional operations.
"""