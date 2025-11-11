import React, { useState, useEffect, useRef } from 'react';
import { IconNetwork, IconPlayerPlay, IconPlayerStop, IconTrash, IconFileExport, IconChartBar, IconAlertTriangle } from '@tabler/icons-react';
import { Packet, NetworkInterface, SecurityAlert } from '@/types';
import { cn } from '@/lib/utils';

export const PacketCapture: React.FC = () => {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [isCapturing, setIsCapturing] = useState(false);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [filter, setFilter] = useState('');
  const [securityAlerts, setSecurityAlerts] = useState<SecurityAlert[]>([]);

  // Format hex view from raw buffer
  const formatHexView = (buffer: Uint8Array): string => {
    const lines: string[] = [];
    const bytesPerLine = 16;

    for (let i = 0; i < buffer.length; i += bytesPerLine) {
      const offset = i.toString(16).padStart(8, '0');
      const chunk = buffer.slice(i, i + bytesPerLine);

      // Format hex bytes
      const hexBytes = Array.from(chunk)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');

      // Format ASCII representation
      const ascii = Array.from(chunk)
        .map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.')
        .join('');

      // Pad hex bytes if line is incomplete
      const paddedHex = hexBytes.padEnd(bytesPerLine * 3 - 1, ' ');

      lines.push(`${offset}  ${paddedHex}  ${ascii}`);
    }

    return lines.join('\n');
  };

  // Load interfaces on mount
  useEffect(() => {
    const loadInterfaces = async () => {
      if (!window.api) return;
      const result = await window.api.getInterfaces();
      if (result.success && result.devices) {
        setInterfaces(result.devices);
      }
    };
    loadInterfaces();
  }, []);

  // Set up packet capture listener
  useEffect(() => {
    if (!window.api) return;

    window.api.onPacketCaptured((packet) => {
      setPackets(prev => [...prev, packet]);
    });

    window.api.onCaptureError((error) => {
      alert(`Capture error: ${error}`);
    });

    window.api.onSecurityAlert((alert) => {
      setSecurityAlerts(prev => [alert, ...prev].slice(0, 50));
    });
  }, []);

  const handleStartCapture = async () => {
    if (!selectedInterface || !window.api) return;
    const result = await window.api.startCapture(selectedInterface);
    if (result.success) {
      setIsCapturing(true);
    } else {
      alert(`Error: ${result.error}`);
    }
  };

  const handleStopCapture = async () => {
    if (!window.api) return;
    const result = await window.api.stopCapture();
    if (result.success) {
      setIsCapturing(false);
    }
  };

  const handleClear = () => {
    setPackets([]);
    setSelectedPacket(null);
    setSecurityAlerts([]);
  };

  const handleExport = async (format: 'json' | 'csv') => {
    if (!window.api || packets.length === 0) return;
    await window.api.exportPackets(packets, format);
  };

  const filteredPackets = packets.filter(p => {
    if (!filter) return true;
    const f = filter.toLowerCase();
    return p.protocol.toLowerCase().includes(f) ||
           p.source.toLowerCase().includes(f) ||
           p.destination.toLowerCase().includes(f) ||
           p.info.toLowerCase().includes(f);
  });

  return (
    <div className="flex h-full flex-col gap-4">
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={selectedInterface}
          onChange={(e) => setSelectedInterface(e.target.value)}
          disabled={isCapturing}
          className="rounded-lg border border-neutral-300 bg-white px-4 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-200"
        >
          <option value="">Select Interface...</option>
          {interfaces.map((iface) => (
            <option key={iface.name} value={iface.name}>
              {iface.description || iface.name} ({iface.addresses.map(a => a.addr).join(', ')})
            </option>
          ))}
        </select>

        <button
          onClick={handleStartCapture}
          disabled={isCapturing || !selectedInterface}
          className="flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-700 disabled:opacity-50"
        >
          <IconPlayerPlay size={16} />
          Start
        </button>

        <button
          onClick={handleStopCapture}
          disabled={!isCapturing}
          className="flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
        >
          <IconPlayerStop size={16} />
          Stop
        </button>

        <button
          onClick={handleClear}
          className="flex items-center gap-2 rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium dark:border-neutral-700"
        >
          <IconTrash size={16} />
          Clear
        </button>

        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter packets..."
          className="rounded-lg border border-neutral-300 bg-white px-4 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-200"
        />

        <div className="ml-auto flex gap-2">
          <button
            onClick={() => handleExport('json')}
            disabled={packets.length === 0}
            className="flex items-center gap-2 rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium dark:border-neutral-700 disabled:opacity-50"
          >
            <IconFileExport size={16} />
            JSON
          </button>
          <button
            onClick={() => handleExport('csv')}
            disabled={packets.length === 0}
            className="flex items-center gap-2 rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium dark:border-neutral-700 disabled:opacity-50"
          >
            <IconFileExport size={16} />
            CSV
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="flex gap-4">
        <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-4 py-2 dark:border-neutral-700 dark:bg-neutral-800">
          <div className="text-xs text-neutral-500 dark:text-neutral-400">Status</div>
          <div className={cn("text-sm font-semibold", isCapturing ? "text-green-600" : "text-neutral-600")}>
            {isCapturing ? 'Capturing...' : 'Ready'}
          </div>
        </div>
        <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-4 py-2 dark:border-neutral-700 dark:bg-neutral-800">
          <div className="text-xs text-neutral-500 dark:text-neutral-400">Packets</div>
          <div className="text-sm font-semibold">{packets.length}</div>
        </div>
        <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-4 py-2 dark:border-neutral-700 dark:bg-neutral-800">
          <div className="text-xs text-neutral-500 dark:text-neutral-400">Displayed</div>
          <div className="text-sm font-semibold">{filteredPackets.length}</div>
        </div>
        <div className="rounded-lg border border-neutral-200 bg-neutral-50 px-4 py-2 dark:border-neutral-700 dark:bg-neutral-800">
          <div className="text-xs text-neutral-500 dark:text-neutral-400">Alerts</div>
          <div className="text-sm font-semibold text-red-600">{securityAlerts.length}</div>
        </div>
      </div>

      <div className="flex flex-1 gap-4 min-h-0">
        {/* Packet List */}
        <div className="flex-1 flex flex-col rounded-lg border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-900 overflow-hidden">
          <div className="border-b border-neutral-200 px-4 py-2 dark:border-neutral-700">
            <h3 className="text-sm font-semibold">Packets</h3>
          </div>
          <div className="flex-1 overflow-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-neutral-100 dark:bg-neutral-800">
                <tr>
                  <th className="p-2 text-left">No.</th>
                  <th className="p-2 text-left">Time</th>
                  <th className="p-2 text-left">Source</th>
                  <th className="p-2 text-left">Destination</th>
                  <th className="p-2 text-left">Protocol</th>
                  <th className="p-2 text-left">Length</th>
                  <th className="p-2 text-left">Info</th>
                </tr>
              </thead>
              <tbody>
                {filteredPackets.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-neutral-500">
                      <IconNetwork className="mx-auto mb-2 opacity-30" size={48} />
                      <p>No packets captured yet</p>
                    </td>
                  </tr>
                ) : (
                  filteredPackets.map((packet) => (
                    <tr
                      key={packet.no}
                      onClick={() => setSelectedPacket(packet)}
                      className={cn(
                        "cursor-pointer border-b border-neutral-100 hover:bg-neutral-50 dark:border-neutral-800 dark:hover:bg-neutral-800",
                        selectedPacket?.no === packet.no && "bg-purple-50 dark:bg-purple-900/20"
                      )}
                    >
                      <td className="p-2">{packet.no}</td>
                      <td className="p-2">{packet.relativeTime}</td>
                      <td className="p-2 font-mono">{packet.source}</td>
                      <td className="p-2 font-mono">{packet.destination}</td>
                      <td className="p-2">
                        <span className={cn(
                          "rounded px-2 py-0.5 text-xs font-semibold",
                          packet.protocol === 'TCP' && "bg-blue-100 text-blue-700",
                          packet.protocol === 'UDP' && "bg-yellow-100 text-yellow-700",
                          packet.protocol === 'ICMP' && "bg-orange-100 text-orange-700",
                          packet.protocol === 'ARP' && "bg-purple-100 text-purple-700"
                        )}>
                          {packet.protocol}
                        </span>
                      </td>
                      <td className="p-2">{packet.length}</td>
                      <td className="p-2 truncate max-w-xs">{packet.info}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Security Alerts */}
        {securityAlerts.length > 0 && (
          <div className="w-80 flex flex-col rounded-lg border border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950/20 overflow-hidden">
            <div className="border-b border-red-200 px-4 py-2 dark:border-red-900 flex items-center justify-between">
              <h3 className="text-sm font-semibold flex items-center gap-2 text-red-700 dark:text-red-400">
                <IconAlertTriangle size={16} />
                Security Alerts ({securityAlerts.length})
              </h3>
              <button
                onClick={() => setSecurityAlerts([])}
                className="text-xs text-red-600 hover:text-red-800"
              >
                Clear
              </button>
            </div>
            <div className="flex-1 overflow-auto p-2 space-y-2">
              {securityAlerts.map((alert, idx) => (
                <div
                  key={idx}
                  className="rounded border border-red-200 bg-white p-2 text-xs dark:border-red-900 dark:bg-neutral-900"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className={cn(
                      "rounded px-1.5 py-0.5 text-xs font-bold uppercase",
                      alert.severity === 'critical' && "bg-red-600 text-white",
                      alert.severity === 'high' && "bg-orange-600 text-white",
                      alert.severity === 'medium' && "bg-yellow-600 text-white",
                      alert.severity === 'low' && "bg-blue-600 text-white"
                    )}>
                      {alert.severity}
                    </span>
                    <span className="text-neutral-500">#{alert.packet}</span>
                  </div>
                  <div className="font-semibold mb-1">{alert.message}</div>
                  <div className="text-neutral-600 dark:text-neutral-400">{alert.details}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Packet Details & Hex View */}
      {selectedPacket && (
        <div className="grid grid-cols-2 gap-4 h-64">
          <div className="rounded-lg border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-900 overflow-hidden flex flex-col">
            <div className="border-b border-neutral-200 px-4 py-2 dark:border-neutral-700">
              <h3 className="text-sm font-semibold">Packet Details</h3>
            </div>
            <div className="flex-1 overflow-auto p-4 text-xs space-y-2 font-mono">
              <div><span className="text-neutral-500">Packet #:</span> {selectedPacket.no}</div>
              <div><span className="text-neutral-500">Timestamp:</span> {selectedPacket.timestamp}</div>
              <div><span className="text-neutral-500">Source:</span> {selectedPacket.source}</div>
              <div><span className="text-neutral-500">Destination:</span> {selectedPacket.destination}</div>
              <div><span className="text-neutral-500">Protocol:</span> {selectedPacket.protocol}</div>
              <div><span className="text-neutral-500">Length:</span> {selectedPacket.length} bytes</div>
              {selectedPacket.srcPort && <div><span className="text-neutral-500">Source Port:</span> {selectedPacket.srcPort}</div>}
              {selectedPacket.dstPort && <div><span className="text-neutral-500">Dest Port:</span> {selectedPacket.dstPort}</div>}
              <div><span className="text-neutral-500">Info:</span> {selectedPacket.info}</div>
            </div>
          </div>

          <div className="rounded-lg border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-900 overflow-hidden flex flex-col">
            <div className="border-b border-neutral-200 px-4 py-2 dark:border-neutral-700">
              <h3 className="text-sm font-semibold">Hex View</h3>
            </div>
            <div className="flex-1 overflow-auto p-4 bg-white dark:bg-neutral-900 text-neutral-800 dark:text-neutral-200 font-mono text-xs whitespace-pre">
              {selectedPacket.rawBuffer ? (
                formatHexView(selectedPacket.rawBuffer)
              ) : (
                <div className="text-neutral-500">No raw data available</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
