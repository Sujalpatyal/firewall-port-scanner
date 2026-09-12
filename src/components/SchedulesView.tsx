import React, { useState, useEffect } from 'react';
import { Clock, Plus, Trash2, Calendar, AlertCircle, CheckCircle2 } from 'lucide-react';
import { ScheduleItem } from '../types';
import { fetchSchedules, createSchedule, deleteSchedule } from '../services/api';

export const SchedulesView: React.FC = () => {
  const [schedules, setSchedules] = useState<ScheduleItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // New schedule form state
  const [target, setTarget] = useState('127.0.0.1');
  const [profile, setProfile] = useState('Standard');
  const [timing, setTiming] = useState('T3');
  const [cronExpression, setCronExpression] = useState('0 0 * * *');
  const [submitting, setSubmitting] = useState(false);

  const loadSchedules = async () => {
    setLoading(true);
    try {
      const list = await fetchSchedules();
      setSchedules(list);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSchedules();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      const created = await createSchedule({
        target: target.trim(),
        profile,
        timing,
        cronExpression,
      });
      setSchedules((prev) => [...prev, created]);
      setTarget('127.0.0.1');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm('Delete this scheduled scan?')) return;
    try {
      await deleteSchedule(id);
      setSchedules((prev) => prev.filter((s) => s.id !== id));
    } catch (err: any) {
      alert(err.message);
    }
  };

  return (
    <div id="schedules-panel" className="space-y-4">
      {/* Create Schedule Card */}
      <div className="bg-[#101720] border border-slate-800 rounded-xl p-4 shadow-sm">
        <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2 mb-3">
          <Clock className="w-4 h-4 text-emerald-400" />
          <span>NEW AUTOMATED SCAN SCHEDULE</span>
        </h3>

        {error && (
          <div className="p-3 mb-3 rounded-lg bg-red-950/30 border border-red-500/40 text-xs font-mono text-red-300 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleCreate} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 text-xs font-mono">
          <div>
            <label className="block text-slate-400 mb-1">TARGET IP / SUBNET</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. 192.168.1.0/24"
              className="w-full bg-[#090d12] border border-slate-700 rounded px-2.5 py-1.5 text-emerald-300 outline-none"
              required
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">PROFILE</label>
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              className="w-full bg-[#090d12] border border-slate-700 rounded px-2.5 py-1.5 text-emerald-300 outline-none"
            >
              <option value="Quick">Quick (Top 100)</option>
              <option value="Standard">Standard (Top 1000)</option>
              <option value="Comprehensive">Comprehensive (Full)</option>
              <option value="Stealth">Stealth (T1)</option>
              <option value="UDP Focus">UDP Focus</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">TIMING</label>
            <select
              value={timing}
              onChange={(e) => setTiming(e.target.value)}
              className="w-full bg-[#090d12] border border-slate-700 rounded px-2.5 py-1.5 text-emerald-300 outline-none"
            >
              <option value="T1">T1 Sneaky</option>
              <option value="T2">T2 Polite</option>
              <option value="T3">T3 Normal</option>
              <option value="T4">T4 Aggressive</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">CRON CADENCE</label>
            <select
              value={cronExpression}
              onChange={(e) => setCronExpression(e.target.value)}
              className="w-full bg-[#090d12] border border-slate-700 rounded px-2.5 py-1.5 text-emerald-300 outline-none"
            >
              <option value="0 0 * * *">Daily at Midnight (0 0 * * *)</option>
              <option value="0 */6 * * *">Every 6 Hours (0 */6 * * *)</option>
              <option value="0 0 * * 0">Weekly on Sunday (0 0 * * 0)</option>
              <option value="*/30 * * * *">Every 30 Minutes (Dev)</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={submitting}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold transition-colors shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{submitting ? 'SAVING...' : 'ADD SCHEDULE'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Active Schedules Table */}
      <div className="bg-[#101720] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-3.5 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Calendar className="w-3.5 h-3.5 text-emerald-400" />
            <span>CONFIGURED SCAN SCHEDULES ({schedules.length})</span>
          </h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="bg-[#090d12] border-b border-slate-800 text-slate-400 text-[11px]">
                <th className="py-2.5 px-3">SCHEDULE ID</th>
                <th className="py-2.5 px-3">TARGET</th>
                <th className="py-2.5 px-3">PROFILE</th>
                <th className="py-2.5 px-3">CADENCE</th>
                <th className="py-2.5 px-3">STATUS</th>
                <th className="py-2.5 px-3 text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {schedules.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No automated schedules active.
                  </td>
                </tr>
              ) : (
                schedules.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2.5 px-3 text-cyan-400 font-bold">{item.id}</td>
                    <td className="py-2.5 px-3 text-slate-200 font-semibold">{item.target}</td>
                    <td className="py-2.5 px-3 text-slate-400">
                      {item.profile} ({item.timing})
                    </td>
                    <td className="py-2.5 px-3 text-emerald-400">{item.cronExpression}</td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                        ENABLED
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        type="button"
                        onClick={() => handleDelete(item.id)}
                        className="px-2 py-1 rounded bg-slate-900 hover:bg-red-950/60 text-slate-400 hover:text-red-400 border border-slate-800 transition-colors"
                        title="Delete schedule"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
