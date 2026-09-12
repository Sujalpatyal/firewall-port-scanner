import React from 'react';
import { ShieldAlert, AlertTriangle } from 'lucide-react';

export const WarningBanner: React.FC = () => {
  return (
    <div
      id="permanent-security-warning-banner"
      className="bg-amber-950/40 border-b border-amber-500/30 px-4 py-2 text-xs font-mono text-amber-300 flex items-center justify-between shadow-inner"
    >
      <div className="flex items-center gap-2 max-w-5xl mx-auto">
        <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 animate-pulse" />
        <p className="leading-relaxed tracking-wide">
          <span className="font-bold text-amber-200 uppercase mr-1.5">[AUTHORIZED TESTING NOTICE]</span>
          This tool is for authorized security testing only. Users must have explicit written permission to scan any target.
          Unauthorized scanning may violate computer fraud and cybersecurity laws.
        </p>
      </div>
      <div className="hidden lg:flex items-center gap-1.5 text-[11px] text-amber-400/80 shrink-0 font-medium pl-4">
        <AlertTriangle className="w-3.5 h-3.5" />
        <span>AUDIT LOGS ACTIVE</span>
      </div>
    </div>
  );
};
