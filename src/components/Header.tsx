import React from 'react';
import { Terminal, Shield, History, GitCompare, Clock, Info, CheckCircle2, AlertCircle } from 'lucide-react';
import { SystemHealth } from '../types';

interface HeaderProps {
  activeTab: 'scanner' | 'results' | 'history' | 'compare' | 'schedules' | 'audit';
  setActiveTab: (tab: 'scanner' | 'results' | 'history' | 'compare' | 'schedules' | 'audit') => void;
  systemHealth: SystemHealth | null;
  hasActiveScan: boolean;
  hasResults: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  systemHealth,
  hasActiveScan,
  hasResults,
}) => {
  return (
    <header id="app-header" className="border-b border-slate-800/80 bg-[#0e141c]/90 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between py-3 gap-3">
          {/* Title and Branding */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-sm shadow-emerald-950">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold tracking-wider text-slate-100 font-mono uppercase">
                  FIREWALL PORT STATUS CHECKER
                </h1>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  v2.0 PRO
                </span>
              </div>
              <p className="text-xs font-mono text-emerald-400/90 tracking-wide flex items-center gap-1.5">
                <Shield className="w-3 h-3 text-emerald-400" />
                <span>NMAP SECURITY CONSOLE & AUDIT ENGINE</span>
              </p>
            </div>
          </div>

          {/* System Telemetry Badges */}
          <div className="flex items-center flex-wrap gap-2 text-xs font-mono">
            {systemHealth ? (
              <>
                <div
                  id="system-nmap-badge"
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-300"
                  title={`Detected Nmap engine: ${systemHealth.nmap.version}`}
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{systemHealth.nmap.version || 'Nmap Ready'}</span>
                </div>

                <div
                  id="privilege-badge"
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-400"
                  title={
                    systemHealth.nmap.hasRawSocketPrivilege
                      ? 'Running with raw socket privileges'
                      : 'Running in safe standard TCP connect mode (unprivileged container)'
                  }
                >
                  <span
                    className={`w-2 h-2 rounded-full ${
                      systemHealth.nmap.hasRawSocketPrivilege ? 'bg-emerald-400' : 'bg-amber-400'
                    }`}
                  />
                  <span>{systemHealth.nmap.hasRawSocketPrivilege ? 'CAP_RAW: YES' : 'CAP_RAW: SAFE MODE'}</span>
                </div>
              </>
            ) : (
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-400">
                <span className="w-2 h-2 rounded-full bg-slate-500 animate-pulse" />
                <span>Checking Nmap...</span>
              </div>
            )}

            {hasActiveScan && (
              <div id="active-scan-indicator" className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 font-bold animate-pulse">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                <span>SCAN RUNNING</span>
              </div>
            )}
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center space-x-1 overflow-x-auto pb-1 text-xs font-mono border-t border-slate-800/60 pt-2">
          <button
            id="tab-scanner"
            onClick={() => setActiveTab('scanner')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-t-md transition-colors whitespace-nowrap ${
              activeTab === 'scanner'
                ? 'bg-slate-800/90 text-emerald-400 border-b-2 border-emerald-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>CONSOLE & SCANNER</span>
            {hasActiveScan && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />}
          </button>

          <button
            id="tab-results"
            onClick={() => setActiveTab('results')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-t-md transition-colors whitespace-nowrap ${
              activeTab === 'results'
                ? 'bg-slate-800/90 text-emerald-400 border-b-2 border-emerald-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>RESULTS DASHBOARD</span>
            {hasResults && <span className="w-2 h-2 rounded-full bg-emerald-500" />}
          </button>

          <button
            id="tab-history"
            onClick={() => setActiveTab('history')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-t-md transition-colors whitespace-nowrap ${
              activeTab === 'history'
                ? 'bg-slate-800/90 text-emerald-400 border-b-2 border-emerald-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            <span>SCAN HISTORY</span>
          </button>

          <button
            id="tab-compare"
            onClick={() => setActiveTab('compare')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-t-md transition-colors whitespace-nowrap ${
              activeTab === 'compare'
                ? 'bg-slate-800/90 text-emerald-400 border-b-2 border-emerald-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <GitCompare className="w-3.5 h-3.5" />
            <span>SCAN COMPARISON</span>
          </button>

          <button
            id="tab-schedules"
            onClick={() => setActiveTab('schedules')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-t-md transition-colors whitespace-nowrap ${
              activeTab === 'schedules'
                ? 'bg-slate-800/90 text-emerald-400 border-b-2 border-emerald-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>SCHEDULES</span>
          </button>

          <button
            id="tab-audit"
            onClick={() => setActiveTab('audit')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-t-md transition-colors whitespace-nowrap ${
              activeTab === 'audit'
                ? 'bg-slate-800/90 text-emerald-400 border-b-2 border-emerald-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <Info className="w-3.5 h-3.5" />
            <span>AUDIT & CONFIG</span>
          </button>
        </nav>
      </div>
    </header>
  );
};
