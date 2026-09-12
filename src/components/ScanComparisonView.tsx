import React, { useState, useEffect } from 'react';
import { GitCompare, ArrowRight, PlusCircle, MinusCircle, RefreshCw, AlertCircle, CheckCircle2 } from 'lucide-react';
import { ScanHistoryItem, ScanComparison } from '../types';
import { fetchHistory, compareScansApi } from '../services/api';

interface ScanComparisonViewProps {
  initialScanAId?: string | null;
}

export const ScanComparisonView: React.FC<ScanComparisonViewProps> = ({ initialScanAId }) => {
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [scanAId, setScanAId] = useState<string>(initialScanAId || '');
  const [scanBId, setScanBId] = useState<string>('');
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchHistory()
      .then((items) => {
        const completed = items.filter((i) => i.status === 'completed');
        setScans(completed);
        if (completed.length >= 2) {
          if (!scanAId) setScanAId(completed[1].id);
          if (!scanBId) setScanBId(completed[0].id);
        } else if (completed.length === 1) {
          if (!scanAId) setScanAId(completed[0].id);
        }
      })
      .catch((err) => setError(err.message));
  }, []);

  const handleRunComparison = async () => {
    if (!scanAId || !scanBId) {
      setError('Please select both Baseline Scan A and Comparison Scan B');
      return;
    }
    if (scanAId === scanBId) {
      setError('Please select two distinct scans to evaluate network diff');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const data = await compareScansApi(scanAId, scanBId);
      setComparison(data);
    } catch (err: any) {
      setError(err?.message || 'Comparison request failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div id="scan-comparison-panel" className="bg-[#101720] border border-slate-800 rounded-xl p-4 shadow-sm space-y-4">
      <div className="border-b border-slate-800 pb-3">
        <h2 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <GitCompare className="w-4 h-4 text-emerald-400" />
          <span>FIREWALL STATE COMPARISON & DELTA ENGINE</span>
        </h2>
        <p className="text-xs font-mono text-slate-400 mt-0.5">
          Detect newly exposed ports, closed services, and software version shifts between two audit snapshots.
        </p>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/40 text-xs font-mono text-red-300 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Selectors for Scan A and Scan B */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-[#090d12] p-3 rounded-xl border border-slate-800">
        <div>
          <label className="block text-xs font-mono text-slate-400 mb-1 font-bold">
            BASELINE AUDIT (SCAN A)
          </label>
          <select
            value={scanAId}
            onChange={(e) => setScanAId(e.target.value)}
            className="w-full bg-[#101720] border border-slate-700 rounded-lg p-2 text-xs font-mono text-slate-200 outline-none"
          >
            <option value="">Select baseline scan...</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id} — {s.target} ({s.profile}, {new Date(s.createdAt).toLocaleDateString()})
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs font-mono text-slate-400 mb-1 font-bold">
            RECENT AUDIT (SCAN B)
          </label>
          <select
            value={scanBId}
            onChange={(e) => setScanBId(e.target.value)}
            className="w-full bg-[#101720] border border-slate-700 rounded-lg p-2 text-xs font-mono text-slate-200 outline-none"
          >
            <option value="">Select comparison scan...</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id} — {s.target} ({s.profile}, {new Date(s.createdAt).toLocaleDateString()})
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="flex justify-end">
        <button
          type="button"
          onClick={handleRunComparison}
          disabled={loading || !scanAId || !scanBId}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold transition-colors disabled:bg-slate-800 disabled:text-slate-500 shadow-sm"
        >
          <GitCompare className="w-4 h-4" />
          <span>{loading ? 'COMPUTING DELTA...' : 'COMPARE SCANS'}</span>
        </button>
      </div>

      {/* Comparison Results View */}
      {comparison && (
        <div className="space-y-4 pt-2 border-t border-slate-800">
          <div className="flex flex-wrap items-center justify-between gap-2 bg-[#090d12] p-3 rounded-lg border border-slate-800 text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="text-slate-400">DIFF SUMMARY:</span>
              <span className="text-emerald-400 font-bold">{comparison.riskChange.delta}</span>
            </div>
            <div className="text-slate-400">
              Risk Observations: {comparison.riskChange.previousRisk} <ArrowRight className="inline w-3 h-3 mx-1" />{' '}
              <strong className="text-slate-200">{comparison.riskChange.currentRisk}</strong>
            </div>
          </div>

          {/* New Open Ports */}
          <div className="bg-[#0e141d] p-3.5 rounded-xl border border-slate-800/80 space-y-2">
            <h4 className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-2">
              <PlusCircle className="w-4 h-4" />
              <span>NEWLY DETECTED OPEN PORTS ({comparison.newOpenPorts.length})</span>
            </h4>

            {comparison.newOpenPorts.length === 0 ? (
              <p className="text-xs font-mono text-slate-500 pl-6">No newly opened ports detected.</p>
            ) : (
              <div className="space-y-1.5 pl-6">
                {comparison.newOpenPorts.map((p, idx) => (
                  <div
                    key={idx}
                    className="p-2 rounded bg-emerald-950/20 border border-emerald-500/30 text-xs font-mono text-emerald-300 flex items-center justify-between"
                  >
                    <div>
                      <strong className="text-emerald-200">
                        {p.port}/{p.protocol}
                      </strong>{' '}
                      — Service: {p.service}
                    </div>
                    <span className="text-slate-400">Host: {p.host}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Closed Ports */}
          <div className="bg-[#0e141d] p-3.5 rounded-xl border border-slate-800/80 space-y-2">
            <h4 className="text-xs font-mono font-bold text-slate-400 flex items-center gap-2">
              <MinusCircle className="w-4 h-4 text-slate-500" />
              <span>PORTS PREVIOUSLY OPEN (NOW CLOSED OR FILTERED) ({comparison.closedPorts.length})</span>
            </h4>

            {comparison.closedPorts.length === 0 ? (
              <p className="text-xs font-mono text-slate-500 pl-6">No previously open ports were closed.</p>
            ) : (
              <div className="space-y-1.5 pl-6">
                {comparison.closedPorts.map((p, idx) => (
                  <div
                    key={idx}
                    className="p-2 rounded bg-slate-900/60 border border-slate-800 text-xs font-mono text-slate-400 flex items-center justify-between"
                  >
                    <div>
                      <strong>
                        {p.port}/{p.protocol}
                      </strong>{' '}
                      — Previous Service: {p.previousService}
                    </div>
                    <span>Host: {p.host}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Service & Version Changes */}
          <div className="bg-[#0e141d] p-3.5 rounded-xl border border-slate-800/80 space-y-2">
            <h4 className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-2">
              <RefreshCw className="w-4 h-4" />
              <span>SERVICE OR VERSION SHIFTS ({comparison.serviceChanges.length})</span>
            </h4>

            {comparison.serviceChanges.length === 0 ? (
              <p className="text-xs font-mono text-slate-500 pl-6">No service version changes detected on active ports.</p>
            ) : (
              <div className="space-y-1.5 pl-6">
                {comparison.serviceChanges.map((c, idx) => (
                  <div
                    key={idx}
                    className="p-2 rounded bg-cyan-950/20 border border-cyan-500/30 text-xs font-mono text-cyan-200 flex items-center justify-between"
                  >
                    <div>
                      <strong>Port {c.port}</strong>: {c.oldService} {c.oldVersion ? `(${c.oldVersion})` : ''}{' '}
                      <ArrowRight className="inline w-3 h-3 mx-1 text-slate-400" /> {c.newService}{' '}
                      {c.newVersion ? `(${c.newVersion})` : ''}
                    </div>
                    <span className="text-slate-400">Host: {c.host}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
