import React, { useState, useEffect } from 'react';
import { History, Eye, Trash2, GitCompare, Download, RefreshCw, AlertCircle, CheckCircle2 } from 'lucide-react';
import { ScanHistoryItem } from '../types';
import { fetchHistory, deleteHistoryScan, fetchHistoryScanDetail, exportScanResults } from '../services/api';

interface ScanHistoryViewProps {
  onLoadScan: (scanDetail: any) => void;
  onCompareWith: (scanId: string) => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({ onLoadScan, onCompareWith }) => {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const loadHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await fetchHistory();
      setHistory(list);
    } catch (err: any) {
      setError(err?.message || 'Failed to load scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm(`Delete historical scan record ${id}?`)) return;
    setDeletingId(id);
    try {
      await deleteHistoryScan(id);
      setHistory((prev) => prev.filter((item) => item.id !== id));
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    } finally {
      setDeletingId(null);
    }
  };

  const handleView = async (id: string) => {
    try {
      const full = await fetchHistoryScanDetail(id);
      if (full && full.results) {
        onLoadScan(full.results);
      } else {
        alert('This historical scan does not contain completed results.');
      }
    } catch (err: any) {
      alert(`Could not load scan: ${err.message}`);
    }
  };

  const handleExportDirect = async (id: string, format: 'json' | 'csv' | 'txt', e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const full = await fetchHistoryScanDetail(id);
      if (full?.results) {
        exportScanResults(full.results, format);
      } else {
        alert('No result payload available for export.');
      }
    } catch (err: any) {
      alert(`Export failed: ${err.message}`);
    }
  };

  return (
    <div id="scan-history-panel" className="bg-[#101720] border border-slate-800 rounded-xl p-4 shadow-sm space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <h2 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <History className="w-4 h-4 text-emerald-400" />
            <span>PERSISTENT SCAN AUDIT HISTORY</span>
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-0.5">
            Historical scans stored in local SQLite database with parameter verification.
          </p>
        </div>

        <button
          type="button"
          onClick={loadHistory}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-emerald-300 border border-slate-700 text-xs font-mono transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>REFRESH</span>
        </button>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/40 text-xs font-mono text-red-300 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading && history.length === 0 ? (
        <div className="text-center py-12 text-slate-500 font-mono text-xs">
          Loading scan records from database...
        </div>
      ) : history.length === 0 ? (
        <div className="text-center py-12 text-slate-500 font-mono text-xs">
          No previous scans found. Run your first scan from the Console tab.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="bg-[#090d12] border-b border-slate-800 text-slate-400 text-[11px]">
                <th className="py-2.5 px-3">SCAN ID</th>
                <th className="py-2.5 px-3">TARGET</th>
                <th className="py-2.5 px-3">PROFILE</th>
                <th className="py-2.5 px-3">STATUS</th>
                <th className="py-2.5 px-3 text-center">OPEN PORTS</th>
                <th className="py-2.5 px-3">TIMESTAMP</th>
                <th className="py-2.5 px-3 text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {history.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-2.5 px-3 font-semibold text-slate-200">
                    <span className="text-cyan-400">{scan.id}</span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 font-bold">{scan.target}</td>
                  <td className="py-2.5 px-3 text-slate-400">
                    <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px]">
                      {scan.profile} ({scan.timing})
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        scan.status === 'completed'
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                          : scan.status === 'cancelled'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          : 'bg-red-500/20 text-red-300 border border-red-500/40'
                      }`}
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-center">
                    <span
                      className={`font-bold ${
                        scan.openPorts > 0 ? 'text-emerald-400' : 'text-slate-500'
                      }`}
                    >
                      {scan.openPorts}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                    {new Date(scan.createdAt).toLocaleString()}
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        type="button"
                        onClick={() => handleView(scan.id)}
                        className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-emerald-300 border border-slate-700/80 transition-colors"
                        title="Load into Results Dashboard"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>

                      <button
                        type="button"
                        onClick={() => onCompareWith(scan.id)}
                        className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 border border-slate-700/80 transition-colors"
                        title="Compare with another scan"
                      >
                        <GitCompare className="w-3.5 h-3.5" />
                      </button>

                      <button
                        type="button"
                        onClick={(e) => handleExportDirect(scan.id, 'json', e)}
                        className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-amber-300 border border-slate-700/80 transition-colors"
                        title="Export JSON"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>

                      <button
                        type="button"
                        onClick={(e) => handleDelete(scan.id, e)}
                        disabled={deletingId === scan.id}
                        className="px-2 py-1 rounded bg-slate-900 hover:bg-red-950/60 text-slate-400 hover:text-red-400 border border-slate-700/80 transition-colors"
                        title="Delete scan record"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
