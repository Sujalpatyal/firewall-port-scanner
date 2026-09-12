import React, { useRef, useEffect, useState } from 'react';
import { Terminal, Play, Square, Trash2, Copy, Check, ArrowDownCircle, AlertOctagon } from 'lucide-react';
import { ScanStatus } from '../types';

interface TerminalConsoleProps {
  logs: string[];
  status: ScanStatus;
  activeScanId: string | null;
  onCancelScan: () => void;
  onStartScan: () => void;
  onClearConsole: () => void;
  canStart: boolean;
}

export const TerminalConsole: React.FC<TerminalConsoleProps> = ({
  logs,
  status,
  activeScanId,
  onCancelScan,
  onStartScan,
  onClearConsole,
  canStart,
}) => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [copied, setCopied] = useState(false);

  // Auto scroll to bottom as logs arrive
  useEffect(() => {
    if (autoScroll && terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const handleCopyLogs = () => {
    navigator.clipboard.writeText(logs.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isScanning = status === 'running' || status === 'starting' || status === 'queued';

  return (
    <div id="terminal-console-panel" className="bg-[#080c10] border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-[520px]">
      {/* Terminal Titlebar */}
      <div className="bg-[#0e141c] border-b border-slate-800/80 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 select-none">
        <div className="flex items-center gap-3">
          {/* Mac-style terminal dots */}
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500/70 inline-block" />
            <span className="w-3 h-3 rounded-full bg-yellow-500/70 inline-block" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/70 inline-block" />
          </div>

          <div className="flex items-center gap-2 font-mono text-xs text-slate-300">
            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
            <span className="font-bold tracking-wide">NMAP SECURITY CONSOLE</span>
            {activeScanId && (
              <span className="text-[10px] text-slate-500 px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800">
                ID: {activeScanId}
              </span>
            )}
          </div>
        </div>

        {/* Console Action Buttons */}
        <div className="flex items-center gap-2 font-mono text-xs">
          {/* Status Badge */}
          <div
            className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 ${
              status === 'running'
                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-500/50'
                : status === 'completed'
                ? 'bg-blue-950/80 text-blue-300 border border-blue-500/40'
                : status === 'cancelled'
                ? 'bg-amber-950/80 text-amber-300 border border-amber-500/40'
                : status === 'failed' || status === 'timeout'
                ? 'bg-red-950/80 text-red-300 border border-red-500/40'
                : 'bg-slate-900 text-slate-400 border border-slate-800'
            }`}
          >
            {status === 'running' && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />}
            <span>STATUS: {status}</span>
          </div>

          <button
            type="button"
            onClick={() => setAutoScroll(!autoScroll)}
            className={`p-1.5 rounded border transition-colors ${
              autoScroll
                ? 'bg-slate-800 text-emerald-300 border-slate-700'
                : 'bg-slate-900 text-slate-500 border-slate-800 hover:text-slate-300'
            }`}
            title={autoScroll ? 'Auto-scroll is ON' : 'Auto-scroll is OFF'}
          >
            <ArrowDownCircle className="w-3.5 h-3.5" />
          </button>

          <button
            type="button"
            onClick={handleCopyLogs}
            className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors"
            title="Copy Terminal Logs"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>

          <button
            type="button"
            onClick={onClearConsole}
            className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors"
            title="Clear Console"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          {/* Primary Action Button: Start or Cancel */}
          {isScanning ? (
            <button
              id="cancel-scan-button"
              type="button"
              onClick={onCancelScan}
              className="flex items-center gap-1.5 px-3 py-1 rounded bg-red-600/90 hover:bg-red-600 text-white font-bold transition-colors shadow-sm"
              title="Cancel Active Scan (Ctrl+C)"
            >
              <Square className="w-3 h-3 fill-current" />
              <span>CANCEL SCAN</span>
            </button>
          ) : (
            <button
              id="start-scan-button"
              type="button"
              onClick={onStartScan}
              disabled={!canStart}
              className={`flex items-center gap-1.5 px-3.5 py-1 rounded font-bold transition-all shadow-sm ${
                canStart
                  ? 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-950/50 cursor-pointer'
                  : 'bg-slate-800 text-slate-500 cursor-not-allowed'
              }`}
              title="Execute Authorized Scan (Enter)"
            >
              <Play className="w-3 h-3 fill-current" />
              <span>START SCAN</span>
            </button>
          )}
        </div>
      </div>

      {/* Terminal Viewport */}
      <div
        ref={terminalRef}
        id="terminal-viewport"
        className="flex-1 p-4 overflow-y-auto font-mono text-xs leading-relaxed space-y-1 select-text bg-[#070b0e] text-slate-300"
      >
        {logs.length === 0 ? (
          <div className="text-slate-600 py-6 text-center space-y-1">
            <p>$ nmap console ready.</p>
            <p>Select target and profile above, then click START SCAN or press Enter.</p>
          </div>
        ) : (
          logs.map((line, idx) => {
            let colorClass = 'text-slate-300';

            if (line.startsWith('[COMMAND]')) {
              colorClass = 'text-cyan-400 font-bold';
            } else if (line.startsWith('[CONSOLE]')) {
              colorClass = 'text-emerald-400';
            } else if (line.startsWith('[NOTICE]') || line.includes('WARNING')) {
              colorClass = 'text-amber-300 font-semibold';
            } else if (line.startsWith('[ERROR]') || line.startsWith('[STDERR]')) {
              colorClass = 'text-red-400 font-semibold';
            } else if (line.includes('open') && (line.includes('/tcp') || line.includes('/udp'))) {
              colorClass = 'text-emerald-300 font-bold bg-emerald-950/30 px-1 py-0.5 rounded';
            } else if (line.includes('Host is up')) {
              colorClass = 'text-emerald-400 font-semibold';
            }

            return (
              <div key={idx} className="font-mono whitespace-pre-wrap break-all">
                <span className={colorClass}>{line}</span>
              </div>
            );
          })
        )}

        {/* Live animated blinking cursor */}
        {isScanning && (
          <div className="flex items-center gap-1 text-emerald-400 font-mono pt-1">
            <span>Scanning in progress...</span>
            <span className="inline-block w-2 h-3.5 bg-emerald-400 animate-pulse" />
          </div>
        )}
      </div>

      {/* Terminal Footer Bar */}
      <div className="bg-[#0b1016] border-t border-slate-800/80 px-4 py-1.5 flex items-center justify-between text-[11px] font-mono text-slate-500">
        <div className="flex items-center gap-4">
          <span>LINES: {logs.length}</span>
          <span>MODE: PURE TELEMETRY</span>
        </div>
        <div className="flex items-center gap-3">
          <span>Enter: Start</span>
          <span>Ctrl+C: Cancel</span>
          <span>/: Search</span>
        </div>
      </div>
    </div>
  );
};
