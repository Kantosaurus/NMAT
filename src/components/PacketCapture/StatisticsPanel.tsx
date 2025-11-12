import React, { useState, useEffect } from 'react';
import {
  IconChartBar,
  IconNetwork,
  IconServer,
  IconChartLine,
  IconAlertTriangle,
  IconDownload,
  IconRefresh
} from '@tabler/icons-react';
import {
  ProtocolHierarchyItem,
  ConversationItem,
  EndpointItem,
  IOGraphDataPoint,
  TCPStreamInfo,
  ExpertAlert,
  SRTStatistic,
  FlowGraphItem
} from '../../types';

interface StatisticsPanelProps {
  onClose: () => void;
}

type TabType = 'hierarchy' | 'conversations' | 'endpoints' | 'io-graph' | 'tcp-streams' | 'expert' | 'srt' | 'flow';

const StatisticsPanel: React.FC<StatisticsPanelProps> = ({ onClose }) => {
  const [activeTab, setActiveTab] = useState<TabType>('hierarchy');
  const [conversationType, setConversationType] = useState<'ip' | 'tcp' | 'udp'>('ip');
  const [endpointType, setEndpointType] = useState<'ip' | 'tcp' | 'udp'>('ip');

  // Data states
  const [protocolHierarchy, setProtocolHierarchy] = useState<ProtocolHierarchyItem[]>([]);
  const [conversations, setConversations] = useState<ConversationItem[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [ioGraph, setIOGraph] = useState<IOGraphDataPoint[]>([]);
  const [tcpStreams, setTCPStreams] = useState<TCPStreamInfo[]>([]);
  const [expertAlerts, setExpertAlerts] = useState<ExpertAlert[]>([]);
  const [srtStats, setSRTStats] = useState<SRTStatistic[]>([]);
  const [flowGraph, setFlowGraph] = useState<FlowGraphItem[]>([]);

  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadData();
  }, [activeTab, conversationType, endpointType]);

  const loadData = async () => {
    if (!window.api) return;

    setLoading(true);

    try {
      switch (activeTab) {
        case 'hierarchy':
          const hierarchyResult = await window.api.getProtocolHierarchy();
          if (hierarchyResult.success && hierarchyResult.data) {
            setProtocolHierarchy(hierarchyResult.data);
          }
          break;

        case 'conversations':
          const convsResult = await window.api.getConversations(conversationType);
          if (convsResult.success && convsResult.data) {
            setConversations(convsResult.data);
          }
          break;

        case 'endpoints':
          const endpointsResult = await window.api.getEndpoints(endpointType);
          if (endpointsResult.success && endpointsResult.data) {
            setEndpoints(endpointsResult.data);
          }
          break;

        case 'io-graph':
          const ioResult = await window.api.getIOGraph();
          if (ioResult.success && ioResult.data) {
            setIOGraph(ioResult.data);
          }
          break;

        case 'tcp-streams':
          const streamsResult = await window.api.getTCPStreams();
          if (streamsResult.success && streamsResult.data) {
            setTCPStreams(streamsResult.data);
          }
          break;

        case 'expert':
          const alertsResult = await window.api.getExpertAlerts();
          if (alertsResult.success && alertsResult.data) {
            setExpertAlerts(alertsResult.data);
          }
          break;

        case 'srt':
          const srtResult = await window.api.getSRTStatistics();
          if (srtResult.success && srtResult.data) {
            setSRTStats(srtResult.data);
          }
          break;

        case 'flow':
          const flowResult = await window.api.getFlowGraph();
          if (flowResult.success && flowResult.data) {
            setFlowGraph(flowResult.data);
          }
          break;
      }
    } catch (error) {
      console.error('Error loading statistics:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (format: 'json' | 'csv' | 'xml') => {
    if (!window.api) return;

    const typeMap: Record<TabType, string> = {
      'hierarchy': 'protocol-hierarchy',
      'conversations': `conversations-${conversationType}`,
      'endpoints': `endpoints-${endpointType}`,
      'io-graph': 'io-graph',
      'tcp-streams': 'tcp-streams',
      'expert': 'expert-alerts',
      'srt': 'srt-statistics',
      'flow': 'flow-graph'
    };

    const result = await window.api.exportStatistics(typeMap[activeTab], format);
    if (result.success) {
      alert('Statistics exported successfully!');
    } else {
      alert(`Export failed: ${result.error}`);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 dark:text-red-400';
      case 'high': return 'text-orange-600 dark:text-orange-400';
      case 'medium': return 'text-yellow-600 dark:text-yellow-400';
      case 'low': return 'text-blue-600 dark:text-blue-400';
      default: return 'text-gray-600 dark:text-gray-400';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-[90%] h-[90%] bg-white dark:bg-neutral-900 rounded-lg shadow-2xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 px-6 py-4">
          <div className="flex items-center gap-3">
            <IconChartBar size={24} className="text-purple-600" />
            <h2 className="text-xl font-semibold">Statistics & Analysis</h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={loadData}
              className="flex items-center gap-2 rounded-lg border border-neutral-300 px-3 py-2 text-sm font-medium hover:bg-neutral-100 dark:border-neutral-700 dark:hover:bg-neutral-800"
            >
              <IconRefresh size={16} />
              Refresh
            </button>
            <div className="flex gap-1 rounded-lg border border-neutral-300 dark:border-neutral-700 p-1">
              <button
                onClick={() => handleExport('json')}
                className="px-3 py-1 text-sm font-medium rounded hover:bg-neutral-100 dark:hover:bg-neutral-800"
                title="Export as JSON"
              >
                JSON
              </button>
              <button
                onClick={() => handleExport('csv')}
                className="px-3 py-1 text-sm font-medium rounded hover:bg-neutral-100 dark:hover:bg-neutral-800"
                title="Export as CSV"
              >
                CSV
              </button>
              <button
                onClick={() => handleExport('xml')}
                className="px-3 py-1 text-sm font-medium rounded hover:bg-neutral-100 dark:hover:bg-neutral-800"
                title="Export as XML"
              >
                XML
              </button>
            </div>
            <button
              onClick={onClose}
              className="rounded-lg px-4 py-2 text-sm font-medium hover:bg-neutral-100 dark:hover:bg-neutral-800"
            >
              Close
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-neutral-200 dark:border-neutral-800 px-6 overflow-x-auto">
          {[
            { id: 'hierarchy', label: 'Protocol Hierarchy', icon: IconChartBar },
            { id: 'conversations', label: 'Conversations', icon: IconNetwork },
            { id: 'endpoints', label: 'Endpoints', icon: IconServer },
            { id: 'io-graph', label: 'I/O Graph', icon: IconChartLine },
            { id: 'tcp-streams', label: 'TCP Streams', icon: IconNetwork },
            { id: 'expert', label: 'Expert Alerts', icon: IconAlertTriangle },
            { id: 'srt', label: 'Service Response Time', icon: IconChartLine },
            { id: 'flow', label: 'Flow Graph', icon: IconNetwork }
          ].map(tab => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as TabType)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'border-purple-600 text-purple-600'
                    : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
                }`}
              >
                <Icon size={16} />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-6">
          {loading ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-gray-500">Loading...</div>
            </div>
          ) : (
            <>
              {/* Protocol Hierarchy */}
              {activeTab === 'hierarchy' && (
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Protocol Distribution</h3>
                  <div className="overflow-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-neutral-100 dark:bg-neutral-800">
                        <tr>
                          <th className="px-4 py-2 text-left">Protocol</th>
                          <th className="px-4 py-2 text-right">Packets</th>
                          <th className="px-4 py-2 text-right">Bytes</th>
                          <th className="px-4 py-2 text-right">Percentage</th>
                        </tr>
                      </thead>
                      <tbody>
                        {protocolHierarchy.map((proto, idx) => (
                          <tr key={idx} className="border-b border-neutral-200 dark:border-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                            <td className="px-4 py-2 font-medium">{proto.protocol}</td>
                            <td className="px-4 py-2 text-right">{proto.packets.toLocaleString()}</td>
                            <td className="px-4 py-2 text-right">{formatBytes(proto.bytes)}</td>
                            <td className="px-4 py-2 text-right">{proto.percentage}%</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {protocolHierarchy.length === 0 && (
                      <div className="text-center py-8 text-gray-500">No protocol data available</div>
                    )}
                  </div>
                </div>
              )}

              {/* Conversations */}
              {activeTab === 'conversations' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold">Network Conversations</h3>
                    <select
                      value={conversationType}
                      onChange={(e) => setConversationType(e.target.value as 'ip' | 'tcp' | 'udp')}
                      className="rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-800"
                    >
                      <option value="ip">IPv4</option>
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                    </select>
                  </div>
                  <div className="overflow-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-neutral-100 dark:bg-neutral-800">
                        <tr>
                          <th className="px-4 py-2 text-left">Address A</th>
                          {conversationType !== 'ip' && <th className="px-4 py-2 text-left">Port A</th>}
                          <th className="px-4 py-2 text-left">Address B</th>
                          {conversationType !== 'ip' && <th className="px-4 py-2 text-left">Port B</th>}
                          <th className="px-4 py-2 text-right">Packets</th>
                          <th className="px-4 py-2 text-right">Bytes</th>
                          <th className="px-4 py-2 text-right">Duration (s)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {conversations.map((conv, idx) => (
                          <tr key={idx} className="border-b border-neutral-200 dark:border-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                            <td className="px-4 py-2 font-mono text-xs">{conv.addressA}</td>
                            {conversationType !== 'ip' && <td className="px-4 py-2">{conv.portA}</td>}
                            <td className="px-4 py-2 font-mono text-xs">{conv.addressB}</td>
                            {conversationType !== 'ip' && <td className="px-4 py-2">{conv.portB}</td>}
                            <td className="px-4 py-2 text-right">{conv.packets.toLocaleString()}</td>
                            <td className="px-4 py-2 text-right">
                              {conversationType === 'ip'
                                ? formatBytes((conv.bytesAtoB || 0) + (conv.bytesBtoA || 0))
                                : formatBytes(conv.bytes || 0)}
                            </td>
                            <td className="px-4 py-2 text-right">{conv.duration}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {conversations.length === 0 && (
                      <div className="text-center py-8 text-gray-500">No conversation data available</div>
                    )}
                  </div>
                </div>
              )}

              {/* Endpoints */}
              {activeTab === 'endpoints' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold">Network Endpoints</h3>
                    <select
                      value={endpointType}
                      onChange={(e) => setEndpointType(e.target.value as 'ip' | 'tcp' | 'udp')}
                      className="rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-800"
                    >
                      <option value="ip">IPv4</option>
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                    </select>
                  </div>
                  <div className="overflow-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-neutral-100 dark:bg-neutral-800">
                        <tr>
                          <th className="px-4 py-2 text-left">Address</th>
                          {endpointType !== 'ip' && <th className="px-4 py-2 text-left">Port</th>}
                          <th className="px-4 py-2 text-right">Packets</th>
                          <th className="px-4 py-2 text-right">Bytes</th>
                          <th className="px-4 py-2 text-right">TX Packets</th>
                          <th className="px-4 py-2 text-right">TX Bytes</th>
                          <th className="px-4 py-2 text-right">RX Packets</th>
                          <th className="px-4 py-2 text-right">RX Bytes</th>
                        </tr>
                      </thead>
                      <tbody>
                        {endpoints.map((endpoint, idx) => (
                          <tr key={idx} className="border-b border-neutral-200 dark:border-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                            <td className="px-4 py-2 font-mono text-xs">{endpoint.address}</td>
                            {endpointType !== 'ip' && <td className="px-4 py-2">{endpoint.port}</td>}
                            <td className="px-4 py-2 text-right">{endpoint.packets.toLocaleString()}</td>
                            <td className="px-4 py-2 text-right">{formatBytes(endpoint.bytes)}</td>
                            <td className="px-4 py-2 text-right">{endpoint.txPackets.toLocaleString()}</td>
                            <td className="px-4 py-2 text-right">{formatBytes(endpoint.txBytes)}</td>
                            <td className="px-4 py-2 text-right">{endpoint.rxPackets.toLocaleString()}</td>
                            <td className="px-4 py-2 text-right">{formatBytes(endpoint.rxBytes)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {endpoints.length === 0 && (
                      <div className="text-center py-8 text-gray-500">No endpoint data available</div>
                    )}
                  </div>
                </div>
              )}

              {/* I/O Graph */}
              {activeTab === 'io-graph' && (
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">I/O Graph (Packet Rate Over Time)</h3>
                  <div className="overflow-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-neutral-100 dark:bg-neutral-800">
                        <tr>
                          <th className="px-4 py-2 text-left">Time</th>
                          <th className="px-4 py-2 text-right">Packets</th>
                          <th className="px-4 py-2 text-right">Bytes</th>
                          <th className="px-4 py-2 text-right">Avg Packet Size</th>
                          <th className="px-4 py-2 text-left">Top Protocols</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ioGraph.map((dataPoint, idx) => (
                          <tr key={idx} className="border-b border-neutral-200 dark:border-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                            <td className="px-4 py-2 font-mono text-xs">
                              {new Date(dataPoint.time).toLocaleTimeString()}
                            </td>
                            <td className="px-4 py-2 text-right">{dataPoint.packets.toLocaleString()}</td>
                            <td className="px-4 py-2 text-right">{formatBytes(dataPoint.bytes)}</td>
                            <td className="px-4 py-2 text-right">{dataPoint.avgPacketSize.toFixed(2)} B</td>
                            <td className="px-4 py-2">
                              {Object.entries(dataPoint.protocols)
                                .sort((a, b) => b[1] - a[1])
                                .slice(0, 3)
                                .map(([proto, count]) => `${proto}(${count})`)
                                .join(', ')}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {ioGraph.length === 0 && (
                      <div className="text-center py-8 text-gray-500">No I/O graph data available</div>
                    )}
                  </div>
                </div>
              )}

              {/* TCP Streams */}
              {activeTab === 'tcp-streams' && (
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">TCP Stream Analysis</h3>
                  <div className="overflow-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-neutral-100 dark:bg-neutral-800">
                        <tr>
                          <th className="px-4 py-2 text-left">Stream</th>
                          <th className="px-4 py-2 text-right">Packets</th>
                          <th className="px-4 py-2 text-right">Retransmissions</th>
                          <th className="px-4 py-2 text-right">Out of Order</th>
                        </tr>
                      </thead>
                      <tbody>
                        {tcpStreams.map((stream, idx) => (
                          <tr key={idx} className="border-b border-neutral-200 dark:border-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                            <td className="px-4 py-2 font-mono text-xs">{stream.stream}</td>
                            <td className="px-4 py-2 text-right">{stream.packets.toLocaleString()}</td>
                            <td className={`px-4 py-2 text-right ${stream.retransmissions > 0 ? 'text-orange-600 font-semibold' : ''}`}>
                              {stream.retransmissions}
                            </td>
                            <td className={`px-4 py-2 text-right ${stream.outOfOrder > 0 ? 'text-yellow-600 font-semibold' : ''}`}>
                              {stream.outOfOrder}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {tcpStreams.length === 0 && (
                      <div className="text-center py-8 text-gray-500">No TCP stream data available</div>
                    )}
                  </div>
                </div>
              )}

              {/* Expert Alerts */}
              {activeTab === 'expert' && (
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Expert System Alerts</h3>
                  <div className="space-y-2">
                    {expertAlerts.map((alert, idx) => (
                      <div
                        key={idx}
                        className="rounded-lg border border-neutral-200 dark:border-neutral-800 p-4 hover:bg-neutral-50 dark:hover:bg-neutral-800/50"
                      >
                        <div className="flex items-start gap-3">
                          <IconAlertTriangle className={`mt-0.5 ${getSeverityColor(alert.severity)}`} size={20} />
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className={`text-sm font-semibold uppercase ${getSeverityColor(alert.severity)}`}>
                                {alert.severity}
                              </span>
                              <span className="text-sm text-gray-500">•</span>
                              <span className="text-sm text-gray-600 dark:text-gray-400">{alert.category}</span>
                              <span className="text-sm text-gray-500">•</span>
                              <span className="text-sm font-medium">{alert.protocol}</span>
                            </div>
                            <p className="mt-1 font-medium">{alert.message}</p>
                            <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">{alert.details}</p>
                            <div className="mt-2 flex gap-4 text-xs text-gray-500">
                              <span>Packet #{alert.packet}</span>
                              <span>{new Date(alert.timestamp).toLocaleString()}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                    {expertAlerts.length === 0 && (
                      <div className="text-center py-8 text-gray-500">No expert alerts</div>
                    )}
                  </div>
                </div>
              )}

              {/* Service Response Time */}
              {activeTab === 'srt' && (
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Service Response Time Statistics</h3>
                  <div className="overflow-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-neutral-100 dark:bg-neutral-800">
                        <tr>
                          <th className="px-4 py-2 text-left">Stream</th>
                          <th className="px-4 py-2 text-right">Packets</th>
                          <th className="px-4 py-2 text-right">Avg Time (ms)</th>
                          <th className="px-4 py-2 text-right">Min Time (ms)</th>
                          <th className="px-4 py-2 text-right">Max Time (ms)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {srtStats.map((stat, idx) => (
                          <tr key={idx} className="border-b border-neutral-200 dark:border-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                            <td className="px-4 py-2 font-mono text-xs">{stat.stream}</td>
                            <td className="px-4 py-2 text-right">{stat.packets.toLocaleString()}</td>
                            <td className="px-4 py-2 text-right">{stat.avgResponseTime}</td>
                            <td className="px-4 py-2 text-right">{stat.minResponseTime}</td>
                            <td className="px-4 py-2 text-right">{stat.maxResponseTime}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {srtStats.length === 0 && (
                      <div className="text-center py-8 text-gray-500">No SRT data available</div>
                    )}
                  </div>
                </div>
              )}

              {/* Flow Graph */}
              {activeTab === 'flow' && (
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Flow Graph (Packet Sequence)</h3>
                  <div className="overflow-auto max-h-[600px]">
                    <div className="space-y-2">
                      {flowGraph.map((flow, idx) => (
                        <div
                          key={idx}
                          className="flex items-center gap-4 border-b border-neutral-200 dark:border-neutral-800 pb-2"
                        >
                          <span className="text-xs text-gray-500 w-12">{flow.no}</span>
                          <span className="text-xs text-gray-500 w-24">{new Date(flow.timestamp).toLocaleTimeString()}</span>
                          <div className="flex items-center gap-2 flex-1">
                            <span className="font-mono text-xs bg-blue-100 dark:bg-blue-900/30 px-2 py-1 rounded">
                              {flow.source}
                            </span>
                            <span className="text-gray-400">→</span>
                            <span className="font-mono text-xs bg-green-100 dark:bg-green-900/30 px-2 py-1 rounded">
                              {flow.destination}
                            </span>
                          </div>
                          <span className="text-xs font-medium w-16">{flow.protocol}</span>
                          <span className="text-xs text-gray-600 dark:text-gray-400 w-20 text-right">{flow.length} B</span>
                          <span className="text-xs text-gray-500 flex-1 truncate">{flow.info}</span>
                        </div>
                      ))}
                    </div>
                    {flowGraph.length === 0 && (
                      <div className="text-center py-8 text-gray-500">No flow data available</div>
                    )}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default StatisticsPanel;
