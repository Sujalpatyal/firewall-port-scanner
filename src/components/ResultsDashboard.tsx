import React, { useState, useMemo } from 'react';
import {
  Shield,
  Server,
  Activity,
  AlertTriangle,
  FileJson,
  FileSpreadsheet,
  FileText,
  Search,
  CheckCircle2,
  XCircle,
  HelpCircle,
  ChevronRight,
  ChevronDown,
  Clock,
  Layers,
} from 'lucide-react';
import { ScanResultPayload, HostResult, PortResult, ProvenanceSource } from '../types';
import { exportScanResults } from '../services/api';

interface ResultsDashboardProps {
  results: ScanResultPayload | null;
  onSelectScanForCompare?: (scanId: string) => void;
}

export const ResultsDashboard: React.FC<ResultsDashboardProps> = ({ results }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'up' | 'down'>('all');
  const [portStateFilter, setPortStateFilter] = useState<string>('all');
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());

  if (!results) {
    return (
      <div className="bg-[#101720] border border-slate-800 rounded-xl p-12 text-center text-slate-500 font-mono">
        <Server className="w-12 h-12 mx-auto mb-3 text-slate-600" />
        <h3 className="text-base text-slate-300 font-bold mb-1">NO SCAN RESULTS CURRENTLY LOADED</h3>
        <p className="text-xs text-slate-500 max-w-md mx-auto">
          Execute a security scan from the Console & Scanner tab or load a previous scan from Scan History.
        </p>
      </div>
    );
  }

  const toggleHostExpand = (addr: string) => {
    const next = new Set(expandedHosts);
    if (next.has(addr)) next.delete(addr);
    else next.add(addr);
    setExpandedHosts(next);
  };

  // Filtered hosts
  const filteredHosts = useMemo(() => {
    return results.hosts.filter((h) => {
      if (statusFilter !== 'all' && h.status.value !== statusFilter) return false;
      if (!searchTerm) return true;
      const term = searchTerm.toLowerCase();
      const matchAddr = h.address.value.toLowerCase().includes(term);
      const matchHost = h.hostname?.value.toLowerCase().includes(term);
      const matchService = h.ports.some(
        (p) =>
          p.service.value.toLowerCase().includes(term) ||
          p.product?.value.toLowerCase().includes(term) ||
          p.port.toString().includes(term)
      );
      return matchAddr || matchHost || matchService;
    });
  }, [results.hosts, searchTerm, statusFilter]);

  // Aggregated ports for port view
  const allFilteredPorts = useMemo(() => {
    const list: { host: HostResult; port: PortResult }[] = [];
    for (const h of filteredHosts) {
      for (const p of h.ports) {
        if (portStateFilter !== 'all' && p.state.value !== portStateFilter) continue;
        list.push({ host: h, port: p });
      }
    }
    return list;
  }, [filteredHosts, portStateFilter]);

  // Provenance visual badge helper
  const renderProvenanceBadge = (source: ProvenanceSource, confidence?: number) => {
    switch (source) {
      case 'measured':
        return (
          <span
            className="inline-flex items-center gap-1 text-[10px] font-mono font-semibold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-1.5 py-0.5 rounded"
            title="Measured directly by Nmap network probes"
          >
            ● Measured
          </span>
        );
      case 'derived':
        return (
          <span
            className="inline-flex items-center gap-1 text-[10px] font-mono font-semibold text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-1.5 py-0.5 rounded"
            title="Computed algorithmically from genuine scan data"
          >
            ◆ Derived
          </span>
        );
      case 'estimated':
        return (
          <span
            className="inline-flex items-center gap-1 text-[10px] font-mono font-semibold text-amber-400 bg-amber-500/10 border border-amber-500/30 px-1.5 py-0.5 rounded"
            title={`Estimated non-critical metadata (${confidence ? `${confidence}% confidence` : 'inferred'})`}
          >
            ◇ Estimated {confidence ? `(${confidence}%)` : ''}
          </span>
        );
      case 'unknown':
      default:
        return (
          <span
            className="inline-flex items-center gap-1 text-[10px] font-mono font-semibold text-slate-400 bg-slate-800 border border-slate-700 px-1.5 py-0.5 rounded"
            title="Field could not be determined with available probes"
          >
            ? Unknown
          </span>
        );
    }
  };

  const renderPortBadge = (state: string) => {
    const s = state.toLowerCase();
    if (s === 'open') {
      return (
        <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
          OPEN
        </span>
      );
    }
    if (s === 'filtered') {
      return (
        <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40">
          FILTERED
        </span>
      );
    }
    if (s === 'closed') {
      return (
        <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-red-500/20 text-red-300 border border-red-500/40">
          CLOSED
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-slate-800 text-slate-400 border border-slate-700">
        {state.toUpperCase()}
      </span>
    );
  };

  return (
    <div id="scan-results-dashboard" className="space-y-4">
      {/* Top Header: ID, Controls, and Export */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#101720] border border-slate-800 p-4 rounded-xl shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-emerald-400 font-bold">SCAN AUDIT REPORT:</span>
            <span className="text-xs font-mono text-slate-200 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
              {results.scanId}
            </span>
            <span className="text-xs font-mono text-slate-400">
              • {new Date(results.completedAt).toLocaleString()}
            </span>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Executed: <code className="text-cyan-300">{results.summary.commandExecuted}</code>
          </p>
        </div>

        {/* Export Buttons */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-500 text-[11px]">EXPORT:</span>
          <button
            type="button"
            onClick={() => exportScanResults(results, 'json')}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#090d12] hover:bg-slate-800 text-slate-300 hover:text-emerald-300 border border-slate-700/80 transition-colors"
          >
            <FileJson className="w-3.5 h-3.5 text-cyan-400" />
            <span>JSON</span>
          </button>
          <button
            type="button"
            onClick={() => exportScanResults(results, 'csv')}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#090d12] hover:bg-slate-800 text-slate-300 hover:text-emerald-300 border border-slate-700/80 transition-colors"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
            <span>CSV</span>
          </button>
          <button
            type="button"
            onClick={() => exportScanResults(results, 'txt')}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#090d12] hover:bg-slate-800 text-slate-300 hover:text-emerald-300 border border-slate-700/80 transition-colors"
          >
            <FileText className="w-3.5 h-3.5 text-amber-400" />
            <span>TXT</span>
          </button>
        </div>
      </div>

      {/* Privilege Notice if standard TCP fallback was triggered */}
      {results.privilegeNotice && (
        <div className="bg-amber-950/30 border border-amber-500/40 px-4 py-2.5 rounded-xl flex items-center gap-2.5 text-xs font-mono text-amber-300">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>{results.privilegeNotice}</span>
        </div>
      )}

      {/* Summary KPI Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5">
        <div className="bg-[#101720] border border-slate-800 p-3 rounded-xl">
          <span className="text-[10px] font-mono text-slate-500 block uppercase">Hosts Scanned</span>
          <span className="text-xl font-mono font-bold text-slate-200">{results.summary.hostsScanned}</span>
          <span className="text-[10px] font-mono text-slate-400 block mt-0.5">
            Up: {results.summary.hostsUp} | Down: {results.summary.hostsDown}
          </span>
        </div>

        <div className="bg-[#101720] border border-slate-800 p-3 rounded-xl">
          <span className="text-[10px] font-mono text-slate-500 block uppercase">Open Ports</span>
          <span className="text-xl font-mono font-bold text-emerald-400">{results.summary.openPorts}</span>
          <span className="text-[10px] font-mono text-emerald-500/80 block mt-0.5">Accessible</span>
        </div>

        <div className="bg-[#101720] border border-slate-800 p-3 rounded-xl">
          <span className="text-[10px] font-mono text-slate-500 block uppercase">Filtered Ports</span>
          <span className="text-xl font-mono font-bold text-amber-400">{results.summary.filteredPorts}</span>
          <span className="text-[10px] font-mono text-amber-500/80 block mt-0.5">Firewall drop/block</span>
        </div>

        <div className="bg-[#101720] border border-slate-800 p-3 rounded-xl">
          <span className="text-[10px] font-mono text-slate-500 block uppercase">Closed Ports</span>
          <span className="text-xl font-mono font-bold text-slate-400">{results.summary.closedPorts}</span>
          <span className="text-[10px] font-mono text-slate-500 block mt-0.5">RST received</span>
        </div>

        <div className="bg-[#101720] border border-slate-800 p-3 rounded-xl">
          <span className="text-[10px] font-mono text-slate-500 block uppercase">Duration</span>
          <span className="text-xl font-mono font-bold text-cyan-400">{results.summary.elapsedSeconds}s</span>
          <span className="text-[10px] font-mono text-slate-500 block mt-0.5">Execution time</span>
        </div>

        <div className="bg-[#101720] border border-slate-800 p-3 rounded-xl">
          <span className="text-[10px] font-mono text-slate-500 block uppercase">Profile</span>
          <span className="text-sm font-mono font-bold text-slate-300 block truncate mt-1">{results.profile}</span>
          <span className="text-[10px] font-mono text-slate-500 block">{results.summary.nmapVersion}</span>
        </div>

        <div className="bg-[#101720] border border-slate-800 p-3 rounded-xl">
          <span className="text-[10px] font-mono text-slate-500 block uppercase">Risk Findings</span>
          <span
            className={`text-xl font-mono font-bold ${
              results.riskObservations.length > 0 ? 'text-amber-400' : 'text-emerald-400'
            }`}
          >
            {results.riskObservations.length}
          </span>
          <span className="text-[10px] font-mono text-slate-500 block mt-0.5">Observations</span>
        </div>
      </div>

      {/* Provenance Guide Banner */}
      <div className="bg-[#0b1016] border border-slate-800/80 p-3 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-emerald-400" />
          <span className="font-bold text-slate-300">DATA PROVENANCE PIPELINE:</span>
          <span className="text-slate-500 hidden sm:inline">All results labeled by evidence source</span>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5">{renderProvenanceBadge('measured')} <span className="text-[11px] text-slate-400">Actual probe</span></div>
          <div className="flex items-center gap-1.5">{renderProvenanceBadge('derived')} <span className="text-[11px] text-slate-400">Calculated</span></div>
          <div className="flex items-center gap-1.5">{renderProvenanceBadge('estimated', 80)} <span className="text-[11px] text-slate-400">Inferred</span></div>
          <div className="flex items-center gap-1.5">{renderProvenanceBadge('unknown')} <span className="text-[11px] text-slate-400">Not verified</span></div>
        </div>
      </div>

      {/* Risk Observations Section */}
      {results.riskObservations.length > 0 && (
        <div className="bg-[#101720] border border-slate-800 rounded-xl p-4 shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span>POTENTIALLY RISKY EXPOSURES ({results.riskObservations.length})</span>
            </h3>
            <span className="text-[10px] font-mono text-slate-400">SOURCE: ◆ DERIVED RISK RULES</span>
          </div>

          <div className="space-y-2.5">
            {results.riskObservations.map((obs) => {
              const isCrit = obs.severity === 'critical';
              const isHigh = obs.severity === 'high';
              const isMed = obs.severity === 'medium';

              return (
                <div
                  key={obs.id}
                  className={`p-3 rounded-lg border font-mono text-xs ${
                    isCrit
                      ? 'bg-red-950/20 border-red-500/40 text-red-200'
                      : isHigh
                      ? 'bg-amber-950/20 border-amber-500/40 text-amber-200'
                      : isMed
                      ? 'bg-yellow-950/15 border-yellow-500/30 text-yellow-200'
                      : 'bg-blue-950/15 border-blue-500/30 text-blue-200'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                    <div className="flex items-center gap-2 font-bold">
                      <span
                        className={`px-1.5 py-0.2 rounded text-[10px] uppercase font-mono ${
                          isCrit
                            ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                            : isHigh
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {obs.severity}
                      </span>
                      <span>{obs.title}</span>
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Target: <strong className="text-slate-200">{obs.target}</strong>
                      {obs.port && <span> | Port: <strong className="text-slate-200">{obs.port}</strong></span>}
                    </div>
                  </div>

                  <p className="text-slate-300 text-[11px] leading-relaxed mb-1">{obs.description}</p>
                  <div className="text-[11px] text-emerald-300 bg-slate-900/60 p-2 rounded border border-slate-800">
                    <strong className="text-emerald-400">Recommendation:</strong> {obs.recommendation}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Filter and Search Bar for Tables */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-2 bg-[#101720] border border-slate-800 p-3 rounded-xl">
        <div className="relative w-full sm:w-80">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search IP, hostname, port, or service..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#090d12] border border-slate-700/80 rounded-lg pl-9 pr-3 py-1.5 text-xs font-mono text-emerald-300 placeholder-slate-600 outline-none focus:border-emerald-500"
          />
        </div>

        <div className="flex items-center gap-3 font-mono text-xs w-full sm:w-auto justify-between sm:justify-end">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500">HOST STATUS:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as any)}
              className="bg-[#090d12] border border-slate-700 rounded px-2 py-1 text-slate-300 text-xs font-mono outline-none"
            >
              <option value="all">All Hosts</option>
              <option value="up">Hosts Up</option>
              <option value="down">Hosts Down</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-slate-500">PORT STATE:</span>
            <select
              value={portStateFilter}
              onChange={(e) => setPortStateFilter(e.target.value)}
              className="bg-[#090d12] border border-slate-700 rounded px-2 py-1 text-slate-300 text-xs font-mono outline-none"
            >
              <option value="all">All States</option>
              <option value="open">Open Only</option>
              <option value="filtered">Filtered Only</option>
              <option value="closed">Closed Only</option>
            </select>
          </div>
        </div>
      </div>

      {/* Hosts and Ports Table */}
      <div className="bg-[#101720] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-3.5 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Server className="w-3.5 h-3.5 text-emerald-400" />
            <span>SCANNED HOSTS ({filteredHosts.length})</span>
          </h3>
          <span className="text-[11px] font-mono text-slate-500">CLICK ROW TO EXPAND DETAIL</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="bg-[#0b1016] border-b border-slate-800/80 text-slate-400 text-[11px]">
                <th className="py-2.5 px-3 w-8"></th>
                <th className="py-2.5 px-3">HOST IP</th>
                <th className="py-2.5 px-3">STATUS</th>
                <th className="py-2.5 px-3">HOSTNAME</th>
                <th className="py-2.5 px-3">OPERATING SYSTEM</th>
                <th className="py-2.5 px-3 text-center">OPEN PORTS</th>
                <th className="py-2.5 px-3 text-center">RISK LEVEL</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredHosts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No hosts matched the filter criteria.
                  </td>
                </tr>
              ) : (
                filteredHosts.map((host) => {
                  const isExpanded = expandedHosts.has(host.address.value);
                  const openPortsCount = host.ports.filter((p) => p.state.value === 'open').length;

                  return (
                    <React.Fragment key={host.address.value}>
                      <tr
                        onClick={() => toggleHostExpand(host.address.value)}
                        className="hover:bg-slate-800/30 cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 px-3 text-slate-500">
                          {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5" />
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-bold text-slate-200">
                          <div className="flex items-center gap-1.5">
                            <span>{host.address.value}</span>
                            {renderProvenanceBadge(host.address.source)}
                            {!host.isPrivate && (
                              <span className="text-[9px] bg-amber-950/60 text-amber-300 border border-amber-500/30 px-1 rounded">
                                PUBLIC
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold ${
                              host.status.value === 'up'
                                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                                : 'bg-red-500/20 text-red-300 border border-red-500/40'
                            }`}
                          >
                            {host.status.value.toUpperCase()}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {host.hostname?.value ? (
                            <span>{host.hostname.value}</span>
                          ) : (
                            <span className="text-slate-600">None detected</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {host.os.length > 0 ? (
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span>{host.os[0].value}</span>
                              {renderProvenanceBadge(host.os[0].source, host.os[0].confidence)}
                            </div>
                          ) : (
                            <span className="text-slate-600">Unknown</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-center">
                          <span
                            className={`font-bold ${
                              openPortsCount > 0 ? 'text-emerald-400' : 'text-slate-500'
                            }`}
                          >
                            {openPortsCount}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-center">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              host.riskLevel === 'critical'
                                ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                                : host.riskLevel === 'high'
                                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                : host.riskLevel === 'medium'
                                ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40'
                                : 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                            }`}
                          >
                            {host.riskLevel}
                          </span>
                        </td>
                      </tr>

                      {/* Expandable Port Subtable */}
                      {isExpanded && (
                        <tr className="bg-[#090d12]">
                          <td colSpan={7} className="p-4 border-t border-b border-slate-800/80">
                            <div className="space-y-3">
                              <div className="flex items-center justify-between text-xs">
                                <span className="font-bold text-slate-300">
                                  PORT AUDIT RESULTS FOR {host.address.value}:
                                </span>
                                <span className="text-slate-500">
                                  {host.ports.length} probed ports recorded
                                </span>
                              </div>

                              {host.ports.length === 0 ? (
                                <p className="text-slate-500 py-3 text-center">
                                  No open or filtered ports identified on this target.
                                </p>
                              ) : (
                                <table className="w-full text-left font-mono text-xs border border-slate-800 rounded">
                                  <thead>
                                    <tr className="bg-slate-900/80 text-slate-400 text-[11px] border-b border-slate-800">
                                      <th className="py-2 px-3">PORT</th>
                                      <th className="py-2 px-3">STATE</th>
                                      <th className="py-2 px-3">SERVICE</th>
                                      <th className="py-2 px-3">PRODUCT / VERSION</th>
                                      <th className="py-2 px-3">PROVENANCE</th>
                                      <th className="py-2 px-3">RISK NOTE</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-slate-800/50">
                                    {host.ports.map((port) => (
                                      <tr key={`${port.port}-${port.protocol}`} className="hover:bg-slate-800/20">
                                        <td className="py-2 px-3 font-bold text-slate-200">
                                          {port.port}/{port.protocol}
                                        </td>
                                        <td className="py-2 px-3">{renderPortBadge(port.state.value)}</td>
                                        <td className="py-2 px-3 text-cyan-300">{port.service.value}</td>
                                        <td className="py-2 px-3 text-slate-300">
                                          {port.product?.value || port.version?.value ? (
                                            <span>
                                              {port.product?.value} {port.version?.value}
                                            </span>
                                          ) : (
                                            <span className="text-slate-600">-</span>
                                          )}
                                        </td>
                                        <td className="py-2 px-3">{renderProvenanceBadge(port.state.source)}</td>
                                        <td className="py-2 px-3">
                                          {port.risk ? (
                                            <span
                                              className={`text-[10px] px-1.5 py-0.5 rounded ${
                                                port.risk.level === 'critical' || port.risk.level === 'high'
                                                  ? 'text-amber-400 bg-amber-950/40'
                                                  : 'text-slate-400'
                                              }`}
                                            >
                                              {port.risk.summary}
                                            </span>
                                          ) : (
                                            <span className="text-slate-600">-</span>
                                          )}
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
