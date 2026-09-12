import {
  ScanResultPayload,
  ScanHistoryItem,
  ScanComparison,
  ScheduleItem,
  CustomScanOptions,
  SystemHealth,
} from '../types';

// Support VITE_API_BASE_URL for decoupled deployments, default to same-origin
const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

export async function fetchHealth(): Promise<SystemHealth> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function launchScan(payload: {
  target: string;
  profile: string;
  timing?: string;
  customOptions?: CustomScanOptions;
  isPublicTargetConfirmed: boolean;
}): Promise<{ scanId: string; status: string; commandDisplay: string }> {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to start scan');
  }
  return data;
}

export async function fetchScan(scanId: string) {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
  if (!res.ok) throw new Error('Failed to fetch scan details');
  return res.json();
}

export async function fetchScanResults(scanId: string): Promise<ScanResultPayload> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/results`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Failed to fetch scan results' }));
    throw new Error(err.error || 'Failed to fetch results');
  }
  return res.json();
}

export async function requestCancelScan(scanId: string): Promise<boolean> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/cancel`, {
    method: 'POST',
  });
  return res.ok;
}

export async function fetchHistory(): Promise<ScanHistoryItem[]> {
  const res = await fetch(`${API_BASE}/api/history`);
  if (!res.ok) throw new Error('Failed to load history');
  const data = await res.json();
  return data.scans || [];
}

export async function fetchHistoryScanDetail(id: string) {
  const res = await fetch(`${API_BASE}/api/history/${id}`);
  if (!res.ok) throw new Error('Failed to load historical scan detail');
  return res.json();
}

export async function deleteHistoryScan(id: string): Promise<boolean> {
  const res = await fetch(`${API_BASE}/api/history/${id}`, {
    method: 'DELETE',
  });
  return res.ok;
}

export async function compareScansApi(scanAId: string, scanBId: string): Promise<ScanComparison> {
  const res = await fetch(`${API_BASE}/api/compare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scanAId, scanBId }),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Comparison failed');
  }
  return data;
}

export async function fetchSchedules(): Promise<ScheduleItem[]> {
  const res = await fetch(`${API_BASE}/api/schedules`);
  if (!res.ok) throw new Error('Failed to load schedules');
  const data = await res.json();
  return data.schedules || [];
}

export async function createSchedule(item: {
  target: string;
  profile: string;
  timing: string;
  cronExpression: string;
}): Promise<ScheduleItem> {
  const res = await fetch(`${API_BASE}/api/schedules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(item),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to create schedule');
  return data.schedule;
}

export async function deleteSchedule(id: string): Promise<boolean> {
  const res = await fetch(`${API_BASE}/api/schedules/${id}`, {
    method: 'DELETE',
  });
  return res.ok;
}

export function exportScanResults(results: ScanResultPayload, format: 'json' | 'csv' | 'txt') {
  let content = '';
  let mimeType = 'text/plain';
  let filename = `scan_${results.scanId}_${Date.now()}`;

  if (format === 'json') {
    content = JSON.stringify(results, null, 2);
    mimeType = 'application/json';
    filename += '.json';
  } else if (format === 'csv') {
    mimeType = 'text/csv';
    filename += '.csv';
    const rows = [
      ['Host', 'Status', 'Port', 'Protocol', 'State', 'Service', 'Product', 'Version', 'Source', 'Risk Level'],
    ];

    for (const h of results.hosts) {
      if (h.ports.length === 0) {
        rows.push([h.address.value, h.status.value, 'None', '', '', '', '', '', h.address.source, h.riskLevel]);
      } else {
        for (const p of h.ports) {
          rows.push([
            h.address.value,
            h.status.value,
            p.port.toString(),
            p.protocol,
            p.state.value,
            p.service.value || '',
            p.product?.value || '',
            p.version?.value || '',
            p.state.source,
            p.risk?.level || 'info',
          ]);
        }
      }
    }
    content = rows.map((r) => r.map((cell) => `"${(cell || '').replace(/"/g, '""')}"`).join(',')).join('\n');
  } else if (format === 'txt') {
    mimeType = 'text/plain';
    filename += '.txt';
    const lines = [
      '================================================================================',
      'FIREWALL PORT STATUS CHECKER - NMAP SECURITY AUDIT REPORT',
      '================================================================================',
      `Scan ID:          ${results.scanId}`,
      `Generated At:     ${new Date().toUTCString()}`,
      `Profile:          ${results.profile}`,
      `Command:          ${results.summary.commandExecuted}`,
      `Duration:         ${results.summary.elapsedSeconds}s`,
      `Hosts Scanned:    ${results.summary.hostsScanned} (Up: ${results.summary.hostsUp}, Down: ${results.summary.hostsDown})`,
      `Open Ports:       ${results.summary.openPorts} (Closed: ${results.summary.closedPorts}, Filtered: ${results.summary.filteredPorts})`,
      '--------------------------------------------------------------------------------',
      'TARGET HOST DETAILS & OPEN PORTS',
      '--------------------------------------------------------------------------------',
    ];

    for (const h of results.hosts) {
      lines.push(`\n[HOST] ${h.address.value} (${h.hostname?.value || 'no hostname'}) - STATUS: ${h.status.value.toUpperCase()} [${h.address.source.toUpperCase()}]`);
      lines.push(`  Risk Level: ${h.riskLevel.toUpperCase()} (Score: ${h.riskScore.value}/100)`);
      if (h.os.length > 0) {
        lines.push(`  OS: ${h.os[0].value} [Provenance: ${h.os[0].source.toUpperCase()}${h.os[0].confidence ? ` (${h.os[0].confidence}% conf)` : ''}]`);
      }
      lines.push('  PORT      STATE     SERVICE              PRODUCT & VERSION             PROVENANCE');
      lines.push('  --------------------------------------------------------------------------------');
      for (const p of h.ports) {
        const portStr = `${p.port}/${p.protocol}`.padEnd(10);
        const stateStr = p.state.value.toUpperCase().padEnd(10);
        const srvStr = (p.service.value || 'unknown').padEnd(21);
        const prodStr = `${p.product?.value || ''} ${p.version?.value || ''}`.trim() || '-';
        lines.push(`  ${portStr}${stateStr}${srvStr}${prodStr.padEnd(30)}[${p.state.source.toUpperCase()}]`);
      }
    }

    if (results.riskObservations.length > 0) {
      lines.push('\n--------------------------------------------------------------------------------');
      lines.push('RISK OBSERVATIONS & EXPOSURES');
      lines.push('--------------------------------------------------------------------------------');
      for (const o of results.riskObservations) {
        lines.push(`[${o.severity.toUpperCase()}] ${o.title}`);
        lines.push(`  Target: ${o.target} ${o.port ? `(Port ${o.port})` : ''}`);
        lines.push(`  Detail: ${o.description}`);
        lines.push(`  Action: ${o.recommendation}\n`);
      }
    }

    lines.push('================================================================================');
    lines.push('END OF REPORT - This document contains authorized technical audit findings.');
    lines.push('================================================================================');
    content = lines.join('\n');
  }

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
