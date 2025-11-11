import React, { useState, useEffect, useRef } from 'react';
import { IconPlayerPlay, IconPlayerStop, IconGlobe, IconArrowLeft, IconArrowRight, IconRefresh, IconHome } from '@tabler/icons-react';
import { ProxyHistoryItem, InterceptItem } from '@/types';
import { cn } from '@/lib/utils';

type ProxyTab = 'browser' | 'intercept' | 'history' | 'repeater' | 'intruder';

export const HTTPProxy: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ProxyTab>('browser');
  const [proxyPort, setProxyPort] = useState(8080);
  const [isRunning, setIsRunning] = useState(false);
  const [interceptEnabled, setInterceptEnabled] = useState(false);
  const [history, setHistory] = useState<ProxyHistoryItem[]>([]);
  const [currentIntercept, setCurrentIntercept] = useState<InterceptItem | null>(null);
  const [selectedHistoryItem, setSelectedHistoryItem] = useState<ProxyHistoryItem | null>(null);

  // Set up proxy listeners
  useEffect(() => {
    if (!window.api) return;

    window.api.onProxyStarted((port) => {
      setIsRunning(true);
      setProxyPort(port);
    });

    window.api.onProxyStopped(() => {
      setIsRunning(false);
      setInterceptEnabled(false);
    });

    window.api.onProxyError((error) => {
      alert(`Proxy error: ${error}`);
    });

    window.api.onProxyHistoryUpdate((item) => {
      setHistory(prev => [...prev, item]);
    });

    window.api.onProxyHistoryCleared(() => {
      setHistory([]);
      setSelectedHistoryItem(null);
    });

    window.api.onProxyIntercept((item) => {
      setCurrentIntercept(item);
      setActiveTab('intercept');
    });
  }, []);

  const handleStartProxy = async () => {
    if (!window.api) return;
    const result = await window.api.startProxy(proxyPort);
    if (!result.success) {
      alert(`Failed to start proxy: ${result.error}`);
    }
  };

  const handleStopProxy = async () => {
    if (!window.api) return;
    const result = await window.api.stopProxy();
    if (!result.success) {
      alert(`Failed to stop proxy: ${result.error}`);
    }
  };

  const handleToggleIntercept = async () => {
    if (!window.api) return;
    const result = await window.api.toggleIntercept(!interceptEnabled);
    if (result.success && result.enabled !== undefined) {
      setInterceptEnabled(result.enabled);
    }
  };

  const handleForwardIntercept = async (modifiedRequest?: string) => {
    if (!window.api || !currentIntercept) return;
    // Parse modified request if provided
    const requestData = modifiedRequest ? parseRequest(modifiedRequest) : currentIntercept;
    await window.api.forwardIntercept(currentIntercept.id, requestData);
    setCurrentIntercept(null);
  };

  const handleDropIntercept = async () => {
    if (!window.api || !currentIntercept) return;
    await window.api.dropIntercept(currentIntercept.id);
    setCurrentIntercept(null);
  };

  const parseRequest = (text: string) => {
    // Simple request parser
    const lines = text.split('\n');
    const [method, url, version] = lines[0].split(' ');
    const headers: Record<string, string> = {};
    let i = 1;
    while (i < lines.length && lines[i].trim() !== '') {
      const colonIdx = lines[i].indexOf(':');
      if (colonIdx > 0) {
        headers[lines[i].substring(0, colonIdx).trim()] = lines[i].substring(colonIdx + 1).trim();
      }
      i++;
    }
    return {
      method,
      url,
      httpVersion: version?.replace('HTTP/', '') || '1.1',
      headers,
      bodyString: lines.slice(i + 1).join('\n')
    };
  };

  return (
    <div className="flex h-full flex-col gap-4">
      {/* Controls */}
      <div className="flex items-center gap-4">
        <input
          type="number"
          value={proxyPort}
          onChange={(e) => setProxyPort(Number(e.target.value))}
          disabled={isRunning}
          min={1}
          max={65535}
          className="w-24 rounded-lg border border-neutral-300 bg-white px-4 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-200"
        />

        <button
          onClick={handleStartProxy}
          disabled={isRunning}
          className="flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-700 disabled:opacity-50"
        >
          <IconPlayerPlay size={16} />
          Start Proxy
        </button>

        <button
          onClick={handleStopProxy}
          disabled={!isRunning}
          className="flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
        >
          <IconPlayerStop size={16} />
          Stop Proxy
        </button>

        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={interceptEnabled}
            onChange={handleToggleIntercept}
            disabled={!isRunning}
            className="rounded"
          />
          <span className="text-sm font-medium">Intercept</span>
        </label>

        <div className="ml-auto flex items-center gap-2">
          <div className={cn(
            "flex items-center gap-2 rounded-lg px-3 py-1 text-xs font-semibold",
            isRunning ? "bg-green-100 text-green-700" : "bg-neutral-100 text-neutral-700"
          )}>
            <div className={cn("h-2 w-2 rounded-full", isRunning ? "bg-green-600" : "bg-neutral-400")} />
            {isRunning ? `Running on :${proxyPort}` : 'Stopped'}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-neutral-200 dark:border-neutral-700">
        {(['browser', 'intercept', 'history', 'repeater', 'intruder'] as ProxyTab[]).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={cn(
              "px-4 py-2 text-sm font-medium capitalize transition-colors",
              activeTab === tab
                ? "border-b-2 border-purple-600 text-purple-600"
                : "text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-200"
            )}
          >
            {tab}
            {tab === 'intercept' && currentIntercept && (
              <span className="ml-2 rounded-full bg-red-600 px-1.5 py-0.5 text-xs text-white">1</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="flex-1 min-h-0">
        {activeTab === 'browser' && (
          <BrowserTab isRunning={isRunning} proxyPort={proxyPort} />
        )}

        {activeTab === 'intercept' && (
          <InterceptTab
            currentIntercept={currentIntercept}
            onForward={handleForwardIntercept}
            onDrop={handleDropIntercept}
          />
        )}

        {activeTab === 'history' && (
          <HistoryTab
            history={history}
            selectedItem={selectedHistoryItem}
            onSelectItem={setSelectedHistoryItem}
            onClear={() => window.api?.clearProxyHistory()}
          />
        )}

        {activeTab === 'repeater' && (
          <RepeaterTab selectedItem={selectedHistoryItem} />
        )}

        {activeTab === 'intruder' && (
          <IntruderTab />
        )}
      </div>
    </div>
  );
};

// Intercept Tab Component
const InterceptTab: React.FC<{
  currentIntercept: InterceptItem | null;
  onForward: (modified?: string) => void;
  onDrop: () => void;
}> = ({ currentIntercept, onForward, onDrop }) => {
  const [modifiedRequest, setModifiedRequest] = useState('');

  useEffect(() => {
    if (currentIntercept) {
      const formatted = formatRequest(currentIntercept);
      setModifiedRequest(formatted);
    }
  }, [currentIntercept]);

  const formatRequest = (item: InterceptItem) => {
    let text = `${item.method} ${item.url} HTTP/${item.httpVersion}\n`;
    for (const [key, value] of Object.entries(item.headers)) {
      text += `${key}: ${value}\n`;
    }
    text += '\n';
    if (item.bodyString) {
      text += item.bodyString;
    }
    return text;
  };

  if (!currentIntercept) {
    return (
      <div className="h-full rounded-lg border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-900 flex items-center justify-center">
        <div className="text-center text-neutral-500">
          <p>No intercepted requests</p>
          <p className="text-xs mt-2">Enable intercept to capture HTTP requests</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col gap-4">
      <div className="flex gap-2">
        <button
          onClick={() => onForward(modifiedRequest)}
          className="flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-700"
        >
          Forward
        </button>
        <button
          onClick={onDrop}
          className="flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700"
        >
          Drop
        </button>
      </div>
      <textarea
        value={modifiedRequest}
        onChange={(e) => setModifiedRequest(e.target.value)}
        className="flex-1 rounded-lg border border-neutral-300 bg-white p-4 font-mono text-xs dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-200"
      />
    </div>
  );
};

// History Tab Component
const HistoryTab: React.FC<{
  history: ProxyHistoryItem[];
  selectedItem: ProxyHistoryItem | null;
  onSelectItem: (item: ProxyHistoryItem) => void;
  onClear: () => void;
}> = ({ history, selectedItem, onSelectItem, onClear }) => {
  return (
    <div className="h-full grid grid-cols-2 gap-4">
      <div className="flex flex-col rounded-lg border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-900 overflow-hidden">
        <div className="border-b border-neutral-200 px-4 py-2 dark:border-neutral-700 flex justify-between items-center">
          <h3 className="text-sm font-semibold">Requests ({history.length})</h3>
          <button onClick={onClear} className="text-xs text-red-600 hover:text-red-800">Clear</button>
        </div>
        <div className="flex-1 overflow-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-neutral-100 dark:bg-neutral-800">
              <tr>
                <th className="p-2 text-left">#</th>
                <th className="p-2 text-left">Method</th>
                <th className="p-2 text-left">URL</th>
                <th className="p-2 text-left">Status</th>
              </tr>
            </thead>
            <tbody>
              {history.map((item) => (
                <tr
                  key={item.id}
                  onClick={() => onSelectItem(item)}
                  className={cn(
                    "cursor-pointer border-b border-neutral-100 hover:bg-neutral-50 dark:border-neutral-800 dark:hover:bg-neutral-800",
                    selectedItem?.id === item.id && "bg-purple-50 dark:bg-purple-900/20"
                  )}
                >
                  <td className="p-2">{item.id}</td>
                  <td className="p-2">{item.method}</td>
                  <td className="p-2 truncate max-w-xs">{item.url}</td>
                  <td className="p-2">{item.response?.statusCode || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="flex flex-col rounded-lg border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-900 overflow-hidden">
        <div className="border-b border-neutral-200 px-4 py-2 dark:border-neutral-700">
          <h3 className="text-sm font-semibold">Details</h3>
        </div>
        <div className="flex-1 overflow-auto p-4 font-mono text-xs space-y-4">
          {selectedItem ? (
            <>
              <div>
                <h4 className="font-bold mb-2">Request</h4>
                <pre className="bg-neutral-100 p-2 rounded dark:bg-neutral-800 whitespace-pre-wrap break-all">
                  {`${selectedItem.method} ${selectedItem.url}\n${Object.entries(selectedItem.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}`}
                </pre>
              </div>
              {selectedItem.response && (
                <div>
                  <h4 className="font-bold mb-2">Response</h4>
                  <pre className="bg-neutral-100 p-2 rounded dark:bg-neutral-800 whitespace-pre-wrap break-all">
                    {`${selectedItem.response.statusCode} ${selectedItem.response.statusMessage}\n${Object.entries(selectedItem.response.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}`}
                  </pre>
                </div>
              )}
            </>
          ) : (
            <div className="text-center text-neutral-500">Select a request to view details</div>
          )}
        </div>
      </div>
    </div>
  );
};

// Repeater Tab Component
const RepeaterTab: React.FC<{ selectedItem: ProxyHistoryItem | null }> = ({ selectedItem }) => {
  const [requestText, setRequestText] = useState('');
  const [response, setResponse] = useState('');

  useEffect(() => {
    if (selectedItem) {
      const formatted = `${selectedItem.method} ${selectedItem.url} HTTP/${selectedItem.httpVersion}\n${Object.entries(selectedItem.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}`;
      setRequestText(formatted);
    }
  }, [selectedItem]);

  const handleSend = async () => {
    if (!window.api || !requestText) return;
    // Parse and send request
    const result = await window.api.repeatRequest({ raw: requestText });
    if (result.success && result.result?.response) {
      const resp = result.result.response;
      setResponse(`HTTP/1.1 ${resp.statusCode} ${resp.statusMessage}\n${Object.entries(resp.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${resp.bodyString || ''}`);
    }
  };

  return (
    <div className="h-full grid grid-cols-2 gap-4">
      <div className="flex flex-col gap-2">
        <button
          onClick={handleSend}
          className="self-start rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-700"
        >
          Send
        </button>
        <textarea
          value={requestText}
          onChange={(e) => setRequestText(e.target.value)}
          placeholder="Paste or load a request..."
          className="flex-1 rounded-lg border border-neutral-300 bg-white p-4 font-mono text-xs dark:border-neutral-700 dark:bg-neutral-900"
        />
      </div>
      <div className="flex flex-col">
        <h3 className="text-sm font-semibold mb-2">Response</h3>
        <pre className="flex-1 rounded-lg border border-neutral-300 bg-white p-4 font-mono text-xs overflow-auto dark:border-neutral-700 dark:bg-neutral-900">
          {response || 'Send a request to see the response'}
        </pre>
      </div>
    </div>
  );
};

// Intruder Tab Component
const IntruderTab: React.FC = () => {
  return (
    <div className="h-full rounded-lg border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-900 flex items-center justify-center">
      <div className="text-center text-neutral-500">
        <p>Intruder functionality</p>
        <p className="text-xs mt-2">Configure attack parameters and payloads</p>
      </div>
    </div>
  );
};

// Browser Tab Component
const BrowserTab: React.FC<{ isRunning: boolean; proxyPort: number }> = ({ isRunning, proxyPort }) => {
  const [url, setUrl] = useState('https://www.google.com');
  const [currentUrl, setCurrentUrl] = useState('https://www.google.com');
  const webviewRef = useRef<any>(null);

  useEffect(() => {
    const webview = webviewRef.current;
    if (!webview) return;

    const handleDidNavigate = (e: any) => {
      setCurrentUrl(e.url);
      setUrl(e.url);
    };

    const handleDidNavigateInPage = (e: any) => {
      if (e.isMainFrame) {
        setCurrentUrl(e.url);
        setUrl(e.url);
      }
    };

    webview.addEventListener('did-navigate', handleDidNavigate);
    webview.addEventListener('did-navigate-in-page', handleDidNavigateInPage);

    return () => {
      webview.removeEventListener('did-navigate', handleDidNavigate);
      webview.removeEventListener('did-navigate-in-page', handleDidNavigateInPage);
    };
  }, []);

  const handleNavigate = (e: React.FormEvent) => {
    e.preventDefault();
    if (webviewRef.current) {
      let navigationUrl = url;
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        navigationUrl = 'https://' + url;
      }
      webviewRef.current.loadURL(navigationUrl);
    }
  };

  const handleBack = () => {
    if (webviewRef.current?.canGoBack()) {
      webviewRef.current.goBack();
    }
  };

  const handleForward = () => {
    if (webviewRef.current?.canGoForward()) {
      webviewRef.current.goForward();
    }
  };

  const handleRefresh = () => {
    webviewRef.current?.reload();
  };

  const handleHome = () => {
    setUrl('https://www.google.com');
    webviewRef.current?.loadURL('https://www.google.com');
  };

  if (!isRunning) {
    return (
      <div className="h-full rounded-lg border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-900 flex items-center justify-center">
        <div className="text-center text-neutral-500">
          <IconGlobe className="mx-auto mb-4 h-16 w-16 opacity-30" />
          <p>Start the proxy to use the browser</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col rounded-lg border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-neutral-900 overflow-hidden">
      {/* Browser Controls */}
      <div className="flex items-center gap-2 p-2 border-b border-neutral-200 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-800">
        <button
          onClick={handleBack}
          className="p-2 hover:bg-neutral-200 dark:hover:bg-neutral-700 rounded"
          title="Back"
        >
          <IconArrowLeft size={18} />
        </button>
        <button
          onClick={handleForward}
          className="p-2 hover:bg-neutral-200 dark:hover:bg-neutral-700 rounded"
          title="Forward"
        >
          <IconArrowRight size={18} />
        </button>
        <button
          onClick={handleRefresh}
          className="p-2 hover:bg-neutral-200 dark:hover:bg-neutral-700 rounded"
          title="Refresh"
        >
          <IconRefresh size={18} />
        </button>
        <button
          onClick={handleHome}
          className="p-2 hover:bg-neutral-200 dark:hover:bg-neutral-700 rounded"
          title="Home"
        >
          <IconHome size={18} />
        </button>

        {/* URL Bar */}
        <form onSubmit={handleNavigate} className="flex-1 flex items-center gap-2">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="flex-1 px-4 py-1.5 bg-white dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-600 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
            placeholder="Enter URL..."
          />
          <button
            type="submit"
            className="px-4 py-1.5 bg-purple-600 text-white rounded-lg text-sm font-medium hover:bg-purple-700"
          >
            Go
          </button>
        </form>

        {/* Proxy indicator */}
        <div className="px-3 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 rounded text-xs font-medium">
          Proxy: {proxyPort}
        </div>
      </div>

      {/* Webview Browser */}
      <webview
        ref={webviewRef}
        src={currentUrl}
        partition="proxy-session"
        className="flex-1 w-full h-full"
        allowpopups="true"
      />
    </div>
  );
};
