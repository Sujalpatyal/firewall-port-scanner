import React, { useState, useEffect, useRef, useCallback } from 'react';
import { WarningBanner } from './components/WarningBanner';
import { Header } from './components/Header';
import { TargetInput } from './components/TargetInput';
import { ProfileSelector } from './components/ProfileSelector';
import { TerminalConsole } from './components/TerminalConsole';
import { ResultsDashboard } from './components/ResultsDashboard';
import { ScanHistoryView } from './components/ScanHistoryView';
import { ScanComparisonView } from './components/ScanComparisonView';
import { SchedulesView } from './components/SchedulesView';
import { AuditPolicyModal } from './components/AuditPolicyModal';
import {
  SystemHealth,
  ScanStatus,
  ScanResultPayload,
  CustomScanOptions,
} from './types';
import {
  fetchHealth,
  launchScan,
  requestCancelScan,
  fetchScanResults,
} from './services/api';

export function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'results' | 'history' | 'compare' | 'schedules' | 'audit'>('scanner');
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null);

  // Scan Configuration State
  const [target, setTarget] = useState('127.0.0.1');
  const [profile, setProfile] = useState('Quick');
  const [timing, setTiming] = useState('T4');
  const [customOptions, setCustomOptions] = useState<CustomScanOptions>({
    technique: 'sT',
    serviceDetection: true,
    timing: 'T3',
  });
  const [isPublicTargetConfirmed, setIsPublicTargetConfirmed] = useState(false);

  // Active Scan Execution State
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle');
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([
    '[CONSOLE] Ready for authorized security testing.',
    '[CONSOLE] Initialized Nmap Security Console engine.',
  ]);

  // Loaded Results State
  const [currentResults, setCurrentResults] = useState<ScanResultPayload | null>(null);

  // Comparison Preselection
  const [comparisonScanAId, setComparisonScanAId] = useState<string | null>(null);

  // Audit Policy Modal
  const [showAuditModal, setShowAuditModal] = useState(false);

  // SSE event source reference
  const eventSourceRef = useRef<EventSource | null>(null);

  // Fetch initial health & periodic polling
  const checkHealth = useCallback(async () => {
    try {
      const health = await fetchHealth();
      setSystemHealth(health);
    } catch {
      // Backend temporarily starting up
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 8000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  // Clean up SSE on unmount
  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

  // Keyboard shortcut listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Cancel scan on Ctrl+C or Cmd+C if scanning
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'c' && (scanStatus === 'running' || scanStatus === 'starting')) {
        e.preventDefault();
        handleCancelScan();
      }
      // Start scan on Enter if in scanner tab and not focused in a textarea
      if (e.key === 'Enter' && activeTab === 'scanner' && scanStatus === 'idle' && target.trim()) {
        const activeTag = document.activeElement?.tagName.toLowerCase();
        if (activeTag !== 'textarea') {
          handleStartScan();
        }
      }
      // Escape closes audit modal
      if (e.key === 'Escape' && showAuditModal) {
        setShowAuditModal(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [scanStatus, activeTab, target, showAuditModal]);

  // Connect SSE for live scan streaming
  const connectScanStream = (scanId: string) => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const apiBase = import.meta.env.VITE_API_BASE_URL || '';
    const es = new EventSource(`${apiBase}/api/scans/${scanId}/stream`);
    eventSourceRef.current = es;

    es.addEventListener('log', (e) => {
      try {
        const parsed = JSON.parse(e.data);
        if (parsed.line) {
          setLogs((prev) => [...prev, parsed.line]);
        }
      } catch {
        setLogs((prev) => [...prev, e.data]);
      }
    });

    es.addEventListener('status', (e) => {
      try {
        const parsed = JSON.parse(e.data);
        if (parsed.status) {
          setScanStatus(parsed.status);
        }
      } catch {}
    });

    es.addEventListener('complete', async (e) => {
      try {
        const parsed = JSON.parse(e.data);
        setLogs((prev) => [
          ...prev,
          `[CONSOLE] Scan completed successfully. Duration: ${parsed.summary?.elapsedSeconds || 0}s`,
        ]);
        setScanStatus('completed');
        es.close();

        // Fetch full normalized results payload
        const results = await fetchScanResults(scanId);
        setCurrentResults(results);
      } catch (err: any) {
        setLogs((prev) => [...prev, `[ERROR] Failed to load results payload: ${err.message}`]);
      }
    });

    es.addEventListener('error', (e: any) => {
      try {
        if (e.data) {
          const parsed = JSON.parse(e.data);
          setLogs((prev) => [...prev, `[ERROR] ${parsed.message || 'Stream error'}`]);
        }
      } catch {}
      // If error occurs and status is still running, check if process completed
      fetchScanResults(scanId)
        .then((res) => {
          setCurrentResults(res);
          setScanStatus(res.status as any);
        })
        .catch(() => {});
      es.close();
    });
  };

  // Launch scan handler
  const handleStartScan = async () => {
    if (!target.trim()) {
      alert('Please specify a target IP, hostname, or CIDR.');
      return;
    }

    // Reset console & state
    setLogs([
      `[CONSOLE] Initiating security scan on target: ${target.trim()}`,
      `[CONSOLE] Profile: ${profile} | Timing: ${timing}`,
      `[CONSOLE] Dispatching safe parameter verification...`,
    ]);
    setScanStatus('starting');
    setCurrentResults(null);

    try {
      const resp = await launchScan({
        target: target.trim(),
        profile,
        timing,
        customOptions: profile === 'Custom' ? customOptions : undefined,
        isPublicTargetConfirmed,
      });

      setActiveScanId(resp.scanId);
      setLogs((prev) => [
        ...prev,
        `[CONSOLE] Job queued with ID: ${resp.scanId}`,
        `[COMMAND] $ ${resp.commandDisplay}`,
      ]);
      setScanStatus(resp.status as ScanStatus);

      // Connect to SSE stream
      connectScanStream(resp.scanId);
    } catch (err: any) {
      setLogs((prev) => [
        ...prev,
        `[ERROR] Scan launch rejected: ${err.message}`,
      ]);
      setScanStatus('failed');
    }
  };

  // Cancel active scan handler
  const handleCancelScan = async () => {
    if (!activeScanId) return;
    setLogs((prev) => [...prev, '[CONSOLE] Requesting scan cancellation (SIGINT)...']);
    try {
      await requestCancelScan(activeScanId);
      setScanStatus('cancelled');
      setLogs((prev) => [...prev, '[CONSOLE] Scan cancelled by operator.']);
    } catch (err: any) {
      setLogs((prev) => [...prev, `[ERROR] Failed to cancel scan: ${err.message}`]);
    }
  };

  const handleClearConsole = () => {
    setLogs([]);
  };

  const handleLoadHistoricalScan = (results: ScanResultPayload) => {
    setCurrentResults(results);
    setActiveTab('results');
  };

  const handleCompareWith = (scanId: string) => {
    setComparisonScanAId(scanId);
    setActiveTab('compare');
  };

  return (
    <div className="min-h-screen bg-[#070b0e] text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-emerald-200">
      {/* Permanent Warning Banner */}
      <WarningBanner />

      {/* Main Header with Telemetry & Nav */}
      <Header
        activeTab={activeTab}
        setActiveTab={(tab) => {
          if (tab === 'audit') {
            setShowAuditModal(true);
          } else {
            setActiveTab(tab);
          }
        }}
        systemHealth={systemHealth}
        hasActiveScan={scanStatus === 'running' || scanStatus === 'starting'}
        hasResults={currentResults !== null}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-4">
        {activeTab === 'scanner' && (
          <div className="space-y-4">
            {/* Target Specification */}
            <TargetInput
              target={target}
              setTarget={setTarget}
              isPublicTargetConfirmed={isPublicTargetConfirmed}
              setIsPublicTargetConfirmed={setIsPublicTargetConfirmed}
              disabled={scanStatus === 'running' || scanStatus === 'starting'}
            />

            {/* Profile Selection & Custom Builder */}
            <ProfileSelector
              profile={profile}
              setProfile={setProfile}
              timing={timing}
              setTiming={setTiming}
              customOptions={customOptions}
              setCustomOptions={setCustomOptions}
              disabled={scanStatus === 'running' || scanStatus === 'starting'}
            />

            {/* Real-time Terminal Console */}
            <TerminalConsole
              logs={logs}
              status={scanStatus}
              activeScanId={activeScanId}
              onCancelScan={handleCancelScan}
              onStartScan={handleStartScan}
              onClearConsole={handleClearConsole}
              canStart={Boolean(target.trim()) && scanStatus !== 'running' && scanStatus !== 'starting'}
            />
          </div>
        )}

        {activeTab === 'results' && (
          <ResultsDashboard results={currentResults} onSelectScanForCompare={handleCompareWith} />
        )}

        {activeTab === 'history' && (
          <ScanHistoryView
            onLoadScan={handleLoadHistoricalScan}
            onCompareWith={handleCompareWith}
          />
        )}

        {activeTab === 'compare' && (
          <ScanComparisonView initialScanAId={comparisonScanAId} />
        )}

        {activeTab === 'schedules' && <SchedulesView />}
      </main>

      {/* Audit Policy & Architecture Modal */}
      <AuditPolicyModal isOpen={showAuditModal} onClose={() => setShowAuditModal(false)} />

      {/* Persistent Bottom Status Bar */}
      <footer className="border-t border-slate-900 bg-[#090d12] px-4 py-2 text-[11px] font-mono text-slate-500 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-4">
          <span>HOST: 0.0.0.0:3000</span>
          <span>PERSISTENCE: SQLITE (SQL.JS)</span>
          <span>PARSER: FAST-XML-PARSER</span>
        </div>
        <div className="flex items-center gap-4">
          <button
            type="button"
            onClick={() => setShowAuditModal(true)}
            className="hover:text-emerald-400 underline transition-colors"
          >
            Audit Governance Policy
          </button>
          <span>AUTHORIZED SECURITY TESTING ONLY</span>
        </div>
      </footer>
    </div>
  );
}
export default App;
