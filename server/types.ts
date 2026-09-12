export type ProvenanceSource = 'measured' | 'derived' | 'estimated' | 'unknown';

export interface ProvenanceValue<T> {
  value: T;
  source: ProvenanceSource;
  confidence?: number; // 0 - 100 percentage
}

export type PortState = 'open' | 'closed' | 'filtered' | 'unfiltered' | 'open|filtered' | 'closed|filtered' | 'unknown';
export type ScanProtocol = 'tcp' | 'udp';

export interface PortResult {
  port: number;
  protocol: ScanProtocol;
  state: ProvenanceValue<PortState>;
  service: ProvenanceValue<string>;
  product?: ProvenanceValue<string>;
  version?: ProvenanceValue<string>;
  extrainfo?: string;
  reason?: string;
  risk?: {
    level: 'critical' | 'high' | 'medium' | 'low' | 'info';
    summary: string;
    recommendation: string;
  };
}

export interface HostResult {
  address: ProvenanceValue<string>;
  ipType: 'ipv4' | 'ipv6';
  isPrivate: boolean;
  status: ProvenanceValue<'up' | 'down' | 'unknown'>;
  statusReason?: string;
  hostname?: ProvenanceValue<string>;
  macAddress?: ProvenanceValue<string>;
  vendor?: ProvenanceValue<string>;
  ports: PortResult[];
  os: ProvenanceValue<string>[];
  latencyMs?: number;
  riskScore: ProvenanceValue<number>; // 0 - 100
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface ScanSummary {
  hostsScanned: number;
  hostsUp: number;
  hostsDown: number;
  openPorts: number;
  closedPorts: number;
  filteredPorts: number;
  unknownPorts: number;
  elapsedSeconds: number;
  startTime: string;
  finishTime: string;
  nmapVersion: string;
  commandExecuted: string;
}

export interface ScanResultPayload {
  scanId: string;
  status: 'completed' | 'failed' | 'cancelled' | 'timeout';
  startedAt: string;
  completedAt: string;
  profile: string;
  targets: string[];
  summary: ScanSummary;
  hosts: HostResult[];
  riskObservations: RiskObservation[];
  rawXml?: string;
  privilegeNotice?: string;
}

export interface RiskObservation {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  target: string;
  port?: number;
  service?: string;
  description: string;
  recommendation: string;
  source: 'derived';
  cveReferences?: string[];
}

export type ScanStatus = 'queued' | 'starting' | 'running' | 'completed' | 'failed' | 'cancelled' | 'timeout';

export interface ScanJob {
  id: string;
  status: ScanStatus;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  targetRaw: string;
  validatedTargets: string[];
  isPublicTargetConfirmed: boolean;
  profile: string;
  timing: string; // T0 - T5
  customOptions?: CustomScanOptions;
  nmapArgs: string[];
  commandDisplay: string;
  logs: string[];
  summary?: ScanSummary;
  results?: ScanResultPayload;
  errorMessage?: string;
}

export interface CustomScanOptions {
  technique?: 'sT' | 'sS' | 'sU' | 'sA';
  timing?: 'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'T5';
  ports?: string; // e.g. "22,80,443" or "1-1000" or "-p-"
  topPorts?: number; // e.g. 100 or 1000
  serviceDetection?: boolean; // -sV
  osDetection?: boolean; // -O
  fastScan?: boolean; // -F
  dontPing?: boolean; // -Pn
  traceroute?: boolean; // --traceroute
}

export interface ScanComparison {
  scanA: { id: string; target: string; date: string };
  scanB: { id: string; target: string; date: string };
  newHosts: string[];
  removedHosts: string[];
  newOpenPorts: { host: string; port: number; protocol: string; service: string }[];
  closedPorts: { host: string; port: number; protocol: string; previousService: string }[];
  serviceChanges: { host: string; port: number; oldService: string; newService: string; oldVersion?: string; newVersion?: string }[];
  riskChange: {
    previousRisk: string;
    currentRisk: string;
    delta: string;
  };
}

export interface ScheduleItem {
  id: string;
  target: string;
  profile: string;
  timing: string;
  cronExpression: string;
  enabled: boolean;
  lastRunAt?: string;
  nextRunAt?: string;
  createdAt: string;
}
