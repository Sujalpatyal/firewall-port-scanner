import React from 'react';
import { Shield, Lock, FileCode, CheckCircle2, AlertTriangle, X } from 'lucide-react';

interface AuditPolicyModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AuditPolicyModal: React.FC<AuditPolicyModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#101720] border border-slate-700 rounded-xl w-full max-w-3xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden font-mono text-xs">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-[#0e141c]">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            <span className="font-bold text-slate-100 uppercase tracking-wide">
              SECURITY GOVERNANCE & ARCHITECTURE AUDIT
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-slate-300 leading-relaxed">
          {/* Section 1: Legal & Compliance */}
          <section className="space-y-2">
            <h4 className="font-bold text-amber-300 flex items-center gap-1.5 uppercase">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>1. Authorization & Legal Framework</span>
            </h4>
            <p className="text-slate-400 text-[11px]">
              Port scanning without authorization is considered unauthorized access or transmission under statutes such
              as the Computer Fraud and Abuse Act (CFAA 18 U.S.C. § 1030) and international cybersecurity conventions.
              All operators must maintain verified written authorization prior to executing scans against any network address.
            </p>
          </section>

          {/* Section 2: Input Sanitization & Injection Prevention */}
          <section className="space-y-2">
            <h4 className="font-bold text-emerald-400 flex items-center gap-1.5 uppercase">
              <Lock className="w-3.5 h-3.5" />
              <span>2. Parameter Safety & Injection Immunity</span>
            </h4>
            <ul className="list-disc pl-5 space-y-1 text-slate-400 text-[11px]">
              <li>
                <strong className="text-slate-200">Zero Shell Execution:</strong> Nmap is spawned directly via <code>execFile</code> with an array of arguments, bypassing shell interpreters completely.
              </li>
              <li>
                <strong className="text-slate-200">Strict Character Whitelisting:</strong> Metacharacters such as <code>;</code>, <code>&</code>, <code>|</code>, <code>`</code>, <code>$(...)</code>, and newline characters are strictly rejected at the API validation boundary.
              </li>
              <li>
                <strong className="text-slate-200">Subnet Safety Caps:</strong> CIDR blocks are bounded to maximum <code>/24</code> (256 hosts) to prevent accidental scanning of entire internet blocks.
              </li>
            </ul>
          </section>

          {/* Section 3: Data Provenance Tracking */}
          <section className="space-y-2">
            <h4 className="font-bold text-cyan-400 flex items-center gap-1.5 uppercase">
              <FileCode className="w-3.5 h-3.5" />
              <span>3. Data Provenance Pipeline</span>
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
                <span className="text-emerald-400 font-bold block mb-1">● MEASURED</span>
                <p className="text-slate-400">
                  Data sourced directly from live network probe responses (e.g. TCP SYN-ACK, TCP RST, ICMP).
                </p>
              </div>
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
                <span className="text-cyan-400 font-bold block mb-1">◆ DERIVED</span>
                <p className="text-slate-400">
                  Algorithmically computed values based exclusively on real scanner evidence (e.g. risk scores).
                </p>
              </div>
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
                <span className="text-amber-400 font-bold block mb-1">◇ ESTIMATED</span>
                <p className="text-slate-400">
                  Non-critical metadata inferred when explicit flags were omitted (e.g. OS inference from OpenSSH banner).
                </p>
              </div>
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
                <span className="text-slate-400 font-bold block mb-1">? UNKNOWN</span>
                <p className="text-slate-500">
                  Never synthesized or fabricated. Labeled as unknown whenever probe data was inconclusive.
                </p>
              </div>
            </div>
          </section>

          {/* Section 4: Privilege Isolation */}
          <section className="space-y-2">
            <h4 className="font-bold text-slate-200 uppercase">
              4. Container & Privilege Isolation
            </h4>
            <p className="text-slate-400 text-[11px]">
              The scanner automatically inspects container capabilities upon startup. When running without root/raw-socket
              privileges (<code>CAP_NET_RAW</code>), the engine automatically substitutes SYN stealth scans with standard
              unprivileged TCP connect scans (<code>-sT</code>) and attaches a transparent privilege notice to the scan report.
            </p>
          </section>
        </div>

        {/* Modal Footer */}
        <div className="p-3 bg-[#0e141c] border-t border-slate-800 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold transition-colors"
          >
            DISMISS
          </button>
        </div>
      </div>
    </div>
  );
};
