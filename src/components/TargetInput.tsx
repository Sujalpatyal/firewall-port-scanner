import React, { useState, useRef } from 'react';
import { Globe, Server, Upload, AlertTriangle, ShieldCheck, CheckCircle2 } from 'lucide-react';

interface TargetInputProps {
  target: string;
  setTarget: (target: string) => void;
  isPublicTargetConfirmed: boolean;
  setIsPublicTargetConfirmed: (confirmed: boolean) => void;
  disabled?: boolean;
}

export const TargetInput: React.FC<TargetInputProps> = ({
  target,
  setTarget,
  isPublicTargetConfirmed,
  setIsPublicTargetConfirmed,
  disabled = false,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [fileNotice, setFileNotice] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Simple client-side classification helper for instant feedback
  const classifyClientTarget = (input: string) => {
    const trimmed = input.trim();
    if (!trimmed) return null;

    if (trimmed.startsWith('127.') || trimmed === '::1' || trimmed.toLowerCase() === 'localhost') {
      return { type: 'Loopback', isExternal: false, color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' };
    }
    if (
      trimmed.startsWith('10.') ||
      trimmed.startsWith('192.168.') ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(trimmed) ||
      trimmed.endsWith('.local') ||
      trimmed.endsWith('.internal')
    ) {
      return { type: 'Private RFC 1918', isExternal: false, color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30' };
    }
    if (trimmed.startsWith('169.254.')) {
      return { type: 'Link-Local', isExternal: false, color: 'text-blue-400 bg-blue-500/10 border-blue-500/30' };
    }
    return { type: 'Public / External', isExternal: true, color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' };
  };

  const currentClassification = classifyClientTarget(target);

  const handleFileUpload = (file: File) => {
    if (!file.name.endsWith('.txt') && !file.name.endsWith('.csv')) {
      setFileNotice('Error: Only .txt and .csv target lists are supported.');
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      setFileNotice('Error: Target file exceeds 2MB limit.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = (e.target?.result as string) || '';
      // Parse targets by newline or comma
      const targets = content
        .split(/[\r\n,]+/)
        .map((t) => t.trim())
        .filter((t) => t.length > 0 && !t.startsWith('#'));

      if (targets.length === 0) {
        setFileNotice('No valid targets found in uploaded file.');
        return;
      }

      const capped = targets.slice(0, 16);
      setTarget(capped.join(', '));
      setFileNotice(`Loaded ${capped.length} target(s) from ${file.name}${targets.length > 16 ? ' (capped at max 16)' : ''}.`);
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    if (disabled) return;
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  return (
    <div id="target-input-module" className="bg-[#101720] border border-slate-800 rounded-xl p-4 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
        <label htmlFor="target-field" className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
          <Server className="w-3.5 h-3.5 text-emerald-400" />
          <span>TARGET SPECIFICATION</span>
        </label>

        {/* Live Classification Tag */}
        {currentClassification && (
          <div className={`text-[11px] font-mono px-2 py-0.5 rounded border flex items-center gap-1.5 ${currentClassification.color}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
            <span>CLASSIFICATION: {currentClassification.type}</span>
          </div>
        )}
      </div>

      {/* Target input field */}
      <div className="relative">
        <input
          id="target-field"
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          disabled={disabled}
          placeholder="e.g., 127.0.0.1, 192.168.1.1, 10.0.0.0/24, or scanme.nmap.org"
          className="w-full bg-[#090d12] border border-slate-700/80 focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/50 rounded-lg px-3.5 py-2.5 text-sm font-mono text-emerald-200 placeholder-slate-600 transition-all outline-none"
        />

        {/* Quick presets */}
        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs font-mono">
          <span className="text-slate-500 text-[11px] mr-1">QUICK TEST PRESETS:</span>
          <button
            type="button"
            onClick={() => setTarget('127.0.0.1')}
            disabled={disabled}
            className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-emerald-300 transition-colors border border-slate-700/60"
          >
            127.0.0.1 (Loopback)
          </button>
          <button
            type="button"
            onClick={() => setTarget('localhost')}
            disabled={disabled}
            className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-emerald-300 transition-colors border border-slate-700/60"
          >
            localhost
          </button>
          <button
            type="button"
            onClick={() => setTarget('scanme.nmap.org')}
            disabled={disabled}
            className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-amber-300 transition-colors border border-slate-700/60"
          >
            scanme.nmap.org (Authorized)
          </button>
        </div>
      </div>

      {/* External Target Warning and Confirmation */}
      {currentClassification?.isExternal && (
        <div
          id="public-target-authorization-box"
          className="mt-3 p-3 rounded-lg bg-amber-950/30 border border-amber-500/40 text-xs font-mono"
        >
          <div className="flex items-start gap-2.5 text-amber-300">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-2 flex-1">
              <p className="leading-relaxed">
                <strong className="text-amber-200">EXTERNAL TARGET DETECTED:</strong> This target appears to be outside your local/private network. Continue only if you have explicit authorization to perform security testing against it.
              </p>
              <label className="flex items-center gap-2 cursor-pointer select-none text-slate-200 hover:text-white pt-1">
                <input
                  id="confirm-public-auth-checkbox"
                  type="checkbox"
                  checked={isPublicTargetConfirmed}
                  onChange={(e) => setIsPublicTargetConfirmed(e.target.checked)}
                  disabled={disabled}
                  className="w-4 h-4 rounded bg-slate-900 border-amber-500/60 text-emerald-500 focus:ring-emerald-500"
                />
                <span className="font-semibold text-[11px] text-amber-200">
                  I confirm I have explicit written permission & legal authority to scan this target.
                </span>
              </label>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Upload Dropzone */}
      <div className="mt-3 pt-3 border-t border-slate-800/60 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div
          onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleDrop}
          onClick={() => !disabled && fileInputRef.current?.click()}
          className={`w-full sm:w-auto flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-lg border border-dashed cursor-pointer text-xs font-mono transition-colors ${
            dragActive
              ? 'border-emerald-500 bg-emerald-500/10 text-emerald-300'
              : 'border-slate-700/80 hover:border-slate-600 bg-slate-900/40 text-slate-400 hover:text-slate-300'
          }`}
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Upload target list (.txt / .csv, max 16 targets)</span>
          <input
            ref={fileInputRef}
            type="file"
            accept=".txt,.csv"
            onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
            className="hidden"
          />
        </div>

        {fileNotice && (
          <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/40 px-2 py-1 rounded border border-emerald-500/30">
            {fileNotice}
          </span>
        )}
      </div>
    </div>
  );
};
