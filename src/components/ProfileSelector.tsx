import React, { useState } from 'react';
import { Sliders, Zap, Shield, Search, EyeOff, Radio, HelpCircle, ChevronDown, ChevronUp } from 'lucide-react';
import { CustomScanOptions } from '../types';

interface ProfileSelectorProps {
  profile: string;
  setProfile: (p: string) => void;
  timing: string;
  setTiming: (t: string) => void;
  customOptions: CustomScanOptions;
  setCustomOptions: React.Dispatch<React.SetStateAction<CustomScanOptions>>;
  disabled?: boolean;
}

const PROFILES = [
  {
    id: 'Quick',
    label: 'QUICK',
    icon: Zap,
    description: 'Fast discovery of top 100 common ports using aggressive T4 timing.',
    scope: '--top-ports 100',
    technique: '-sT TCP Connect',
    timing: 'T4',
    intensity: 'High / Low Port Count',
    limitations: 'Only checks top 100 ports, does not banner-probe versions.',
  },
  {
    id: 'Standard',
    label: 'STANDARD',
    icon: Shield,
    description: 'Balanced general scan across top 1000 ports with standard T3 timing.',
    scope: '--top-ports 1000',
    technique: '-sT TCP Connect',
    timing: 'T3',
    intensity: 'Balanced',
    limitations: 'Does not execute full service version probes.',
  },
  {
    id: 'Comprehensive',
    label: 'COMPREHENSIVE',
    icon: Search,
    description: 'Full TCP port range (1-65535) with active service version detection (-sV).',
    scope: '-p- (All 65535 ports)',
    technique: '-sT + -sV Version Probe',
    timing: 'T2 (Polite)',
    intensity: 'High / Extended Duration',
    limitations: 'Takes significantly longer due to probing all 65k ports.',
  },
  {
    id: 'Stealth',
    label: 'STEALTH',
    icon: EyeOff,
    description: 'Low-noise scan using T1 timing and SYN stealth where container permits.',
    scope: '--top-ports 1000',
    technique: '-sS / -sT Fallback',
    timing: 'T1 (Sneaky)',
    intensity: 'Very Slow / Low Noise',
    limitations: 'Requires raw socket privileges; falls back to polite TCP connect if non-root.',
  },
  {
    id: 'UDP Focus',
    label: 'UDP FOCUS',
    icon: Radio,
    description: 'UDP port discovery across top 100 UDP services (DNS, SNMP, NTP, DHCP).',
    scope: '--top-ports 100 (UDP)',
    technique: '-sU',
    timing: 'T3',
    intensity: 'High Packet Loss Sensitivity',
    limitations: 'UDP scanning is inherently slower due to OS rate limiting on ICMP unreachable.',
  },
  {
    id: 'Custom',
    label: 'CUSTOM BUILDER',
    icon: Sliders,
    description: 'Build custom scan arguments: specify exact ports, techniques, and probes.',
    scope: 'User-defined',
    technique: 'Configurable',
    timing: 'User-defined',
    intensity: 'Variable',
    limitations: 'Restricted to safe, non-arbitrary validated parameters.',
  },
];

const TIMINGS = [
  { id: 'T0', label: 'T0 Paranoid', desc: 'Extremely slow scanning to evade IDS detection. Serializes packets with long delays.' },
  { id: 'T1', label: 'T1 Sneaky', desc: 'Very slow scanning. Introduces substantial delays between probe transmissions.' },
  { id: 'T2', label: 'T2 Polite', desc: 'Slows down the scan to use less bandwidth and minimize target machine load.' },
  { id: 'T3', label: 'T3 Normal', desc: 'Balanced default scanning template. Responsive and reliable for general networks.' },
  { id: 'T4', label: 'T4 Aggressive', desc: 'Faster scanning for fast, reliable modern networks. Assumes low latency.' },
  { id: 'T5', label: 'T5 Insane', desc: 'Very aggressive scanning. Potential for dropped packets or less accurate results.' },
];

export const ProfileSelector: React.FC<ProfileSelectorProps> = ({
  profile,
  setProfile,
  timing,
  setTiming,
  customOptions,
  setCustomOptions,
  disabled = false,
}) => {
  const [showCustomDetails, setShowCustomDetails] = useState(false);
  const activeProfileData = PROFILES.find((p) => p.id === profile) || PROFILES[1];

  return (
    <div id="profile-selector-module" className="bg-[#101720] border border-slate-800 rounded-xl p-4 shadow-sm">
      <div className="flex items-center justify-between mb-3">
        <label className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
          <Sliders className="w-3.5 h-3.5 text-emerald-400" />
          <span>PREDEFINED SCAN PROFILES</span>
        </label>
        <span className="text-[11px] font-mono text-slate-400">SELECT INTENSITY TEMPLATE</span>
      </div>

      {/* Profile selector cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
        {PROFILES.map((p) => {
          const Icon = p.icon;
          const isSelected = profile === p.id;
          return (
            <button
              key={p.id}
              type="button"
              disabled={disabled}
              onClick={() => {
                setProfile(p.id);
                if (p.id !== 'Custom') {
                  setTiming(p.timing.split(' ')[0]);
                }
              }}
              className={`p-2.5 rounded-lg border text-left flex flex-col justify-between transition-all ${
                isSelected
                  ? 'bg-emerald-500/10 border-emerald-500 text-emerald-300 shadow-sm'
                  : 'bg-[#090d12] border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <Icon className={`w-4 h-4 ${isSelected ? 'text-emerald-400' : 'text-slate-500'}`} />
                {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />}
              </div>
              <div>
                <span className="text-xs font-mono font-bold block">{p.label}</span>
                <span className="text-[10px] font-mono text-slate-500 block truncate">{p.scope}</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Profile Details Tooltip / Info Card */}
      <div className="mt-3 p-3 rounded-lg bg-[#090d12] border border-slate-800/80 text-xs font-mono">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2 mb-2">
          <div className="flex items-center gap-2">
            <span className="font-bold text-emerald-400">{activeProfileData.label}:</span>
            <span className="text-slate-300">{activeProfileData.description}</span>
          </div>
          <div className="flex items-center gap-3 text-[11px] text-slate-400">
            <span>SCOPE: <strong className="text-slate-200">{activeProfileData.scope}</strong></span>
            <span>TECHNIQUE: <strong className="text-slate-200">{activeProfileData.technique}</strong></span>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
          <div className="text-slate-400">
            <span className="text-amber-400 mr-1">LIMITATION NOTE:</span>
            <span>{activeProfileData.limitations}</span>
          </div>

          {/* Timing selector with explanations */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">TIMING:</span>
            <select
              value={timing}
              onChange={(e) => setTiming(e.target.value)}
              disabled={disabled}
              className="bg-slate-900 border border-slate-700 text-emerald-300 text-xs rounded px-2 py-0.5 outline-none font-mono"
            >
              {TIMINGS.map((t) => (
                <option key={t.id} value={t.id} title={t.desc}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Custom Profile Builder (Accordion or when Custom selected) */}
      {(profile === 'Custom' || showCustomDetails) && (
        <div id="custom-scan-builder-panel" className="mt-3 p-4 rounded-lg bg-[#0d131b] border border-emerald-500/30 text-xs font-mono space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <h4 className="font-bold text-emerald-300 flex items-center gap-1.5">
              <Sliders className="w-4 h-4" />
              <span>CUSTOM SCAN PROFILE BUILDER</span>
            </h4>
            <span className="text-[10px] text-slate-400">SAFE ARGUMENT ENGINE</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {/* Scan Technique */}
            <div>
              <label className="block text-slate-400 mb-1">SCAN TECHNIQUE</label>
              <select
                value={customOptions.technique || 'sT'}
                onChange={(e) => setCustomOptions((prev) => ({ ...prev, technique: e.target.value as any }))}
                disabled={disabled}
                className="w-full bg-[#090d12] border border-slate-700 rounded px-2.5 py-1.5 text-emerald-300 outline-none"
              >
                <option value="sT">-sT TCP Connect (Unprivileged Safe)</option>
                <option value="sS">-sS SYN Stealth (Requires Root)</option>
                <option value="sU">-sU UDP Scanning (Top Services)</option>
                <option value="sA">-sA TCP ACK (Firewall Ruleset)</option>
              </select>
            </div>

            {/* Ports Specification */}
            <div>
              <label className="block text-slate-400 mb-1">PORTS SPECIFICATION</label>
              <input
                type="text"
                value={customOptions.ports || ''}
                onChange={(e) => setCustomOptions((prev) => ({ ...prev, ports: e.target.value }))}
                disabled={disabled}
                placeholder="e.g. 22,80,443, 1-1000, or -p-"
                className="w-full bg-[#090d12] border border-slate-700 rounded px-2.5 py-1.5 text-emerald-300 placeholder-slate-600 outline-none"
              />
            </div>

            {/* Top Ports Preset */}
            <div>
              <label className="block text-slate-400 mb-1">OR TOP PORTS COUNT</label>
              <select
                value={customOptions.topPorts || ''}
                onChange={(e) =>
                  setCustomOptions((prev) => ({
                    ...prev,
                    topPorts: e.target.value ? parseInt(e.target.value, 10) : undefined,
                  }))
                }
                disabled={disabled}
                className="w-full bg-[#090d12] border border-slate-700 rounded px-2.5 py-1.5 text-emerald-300 outline-none"
              >
                <option value="">Default (Specified above)</option>
                <option value="50">Top 50 common ports</option>
                <option value="100">Top 100 common ports</option>
                <option value="1000">Top 1000 common ports</option>
                <option value="2000">Top 2000 ports</option>
              </select>
            </div>
          </div>

          {/* Toggle Flags */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
            <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={customOptions.serviceDetection ?? true}
                onChange={(e) => setCustomOptions((prev) => ({ ...prev, serviceDetection: e.target.checked }))}
                disabled={disabled}
                className="rounded bg-slate-900 border-slate-700 text-emerald-500"
              />
              <span>-sV Service Version</span>
            </label>

            <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={customOptions.osDetection ?? false}
                onChange={(e) => setCustomOptions((prev) => ({ ...prev, osDetection: e.target.checked }))}
                disabled={disabled}
                className="rounded bg-slate-900 border-slate-700 text-emerald-500"
              />
              <span>-O OS Detection</span>
            </label>

            <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={customOptions.dontPing ?? false}
                onChange={(e) => setCustomOptions((prev) => ({ ...prev, dontPing: e.target.checked }))}
                disabled={disabled}
                className="rounded bg-slate-900 border-slate-700 text-emerald-500"
              />
              <span>-Pn Treat as Online</span>
            </label>

            <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={customOptions.fastScan ?? false}
                onChange={(e) => setCustomOptions((prev) => ({ ...prev, fastScan: e.target.checked }))}
                disabled={disabled}
                className="rounded bg-slate-900 border-slate-700 text-emerald-500"
              />
              <span>-F Fast Scan (100)</span>
            </label>
          </div>
        </div>
      )}
    </div>
  );
};
