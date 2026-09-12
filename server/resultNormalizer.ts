import {
  ProvenanceValue,
  PortResult,
  HostResult,
  ScanSummary,
  ScanResultPayload,
  PortState,
} from './types';
import { RawXmlNmapRun, RawXmlNmapHost, RawXmlNmapPort } from './xmlParser';
import { classifySingleTarget } from './targetValidator';
import { analyzeRisk } from './riskAnalyzer';

/**
 * Normalizes raw Nmap XML data into standardized payload with explicit data provenance
 */
export function normalizeScanResults(
  scanId: string,
  rawRun: RawXmlNmapRun,
  targets: string[],
  profile: string,
  commandDisplay: string,
  startTime: string,
  finishTime: string,
  privilegeNotice?: string
): ScanResultPayload {
  const hosts: HostResult[] = [];
  let totalOpenPorts = 0;
  let totalClosedPorts = 0;
  let totalFilteredPorts = 0;
  let totalUnknownPorts = 0;

  for (const rawHost of rawRun.hosts) {
    const classification = classifySingleTarget(rawHost.address);

    // Host status provenance
    const hostStatusVal = rawHost.status === 'up' ? 'up' : rawHost.status === 'down' ? 'down' : 'unknown';
    const status: ProvenanceValue<'up' | 'down' | 'unknown'> = {
      value: hostStatusVal,
      source: 'measured',
    };

    // Address provenance
    const address: ProvenanceValue<string> = {
      value: rawHost.address,
      source: 'measured',
    };

    // Hostname provenance
    const hostname: ProvenanceValue<string> | undefined = rawHost.hostname
      ? {
          value: rawHost.hostname,
          source: 'measured',
        }
      : undefined;

    // Vendor / MAC provenance
    const vendor: ProvenanceValue<string> | undefined = rawHost.vendor
      ? {
          value: rawHost.vendor,
          source: 'measured',
        }
      : undefined;

    // Process Ports
    const ports: PortResult[] = [];

    // Accumulate extraports counts if provided
    if (rawHost.extraPorts) {
      for (const ep of rawHost.extraPorts) {
        if (ep.state === 'closed') totalClosedPorts += ep.count;
        else if (ep.state === 'filtered') totalFilteredPorts += ep.count;
      }
    }

    for (const rawPort of rawHost.ports) {
      const portStateLower = rawPort.state.toLowerCase();
      let stateVal: PortState = 'unknown';

      if (['open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered'].includes(portStateLower)) {
        stateVal = portStateLower as PortState;
      }

      if (stateVal === 'open') totalOpenPorts++;
      else if (stateVal === 'closed') totalClosedPorts++;
      else if (stateVal === 'filtered') totalFilteredPorts++;
      else totalUnknownPorts++;

      // Service & product provenance
      const serviceVal = rawPort.serviceName || 'unknown';
      const service: ProvenanceValue<string> = {
        value: serviceVal,
        source: rawPort.serviceName ? 'measured' : 'unknown',
      };

      const product: ProvenanceValue<string> | undefined = rawPort.product
        ? {
            value: rawPort.product,
            source: 'measured',
          }
        : undefined;

      const version: ProvenanceValue<string> | undefined = rawPort.version
        ? {
            value: rawPort.version,
            source: 'measured',
          }
        : undefined;

      const portResult: PortResult = {
        port: rawPort.portId,
        protocol: (rawPort.protocol === 'udp' ? 'udp' : 'tcp'),
        state: {
          value: stateVal,
          source: 'measured',
        },
        service,
        product,
        version,
        extrainfo: rawPort.extrainfo,
        reason: rawPort.reason,
      };

      ports.push(portResult);
    }

    // Sort ports numerically
    ports.sort((a, b) => a.port - b.port);

    // OS evaluation with strict provenance
    const osList: ProvenanceValue<string>[] = [];

    if (rawHost.osMatches && rawHost.osMatches.length > 0) {
      for (const match of rawHost.osMatches) {
        osList.push({
          value: match.name,
          source: 'measured',
          confidence: match.accuracy,
        });
      }
    } else {
      // If OS detection was not requested or was not permitted (e.g. unprivileged container),
      // we derive or estimate only non-critical metadata from banners if strong indicators exist.
      const bannerEvidence = deriveOsFromBanners(ports);
      if (bannerEvidence) {
        osList.push({
          value: bannerEvidence.name,
          source: 'estimated',
          confidence: bannerEvidence.confidence,
        });
      } else {
        osList.push({
          value: 'Unknown / Not detected',
          source: 'unknown',
        });
      }
    }

    // Calculate preliminary host risk
    const openCount = ports.filter((p) => p.state.value === 'open').length;
    let initialScore = Math.min(openCount * 12, 60);

    // If external public target, base exposure risk is higher
    if (classification.isExternal) {
      initialScore += 15;
    }

    const hostResult: HostResult = {
      address,
      ipType: classification.type === 'ipv6' ? 'ipv6' : 'ipv4',
      isPrivate: !classification.isExternal,
      status,
      statusReason: rawHost.statusReason,
      hostname,
      vendor,
      ports,
      os: osList,
      latencyMs: rawHost.srtt,
      riskScore: {
        value: Math.min(initialScore, 100),
        source: 'derived',
      },
      riskLevel: initialScore >= 75 ? 'high' : initialScore >= 45 ? 'medium' : initialScore >= 20 ? 'low' : 'info',
    };

    hosts.push(hostResult);
  }

  // Calculate scan duration
  const startMs = new Date(startTime).getTime();
  const finishMs = new Date(finishTime).getTime();
  const elapsed = rawRun.stats?.elapsedSeconds || Math.max(Math.round((finishMs - startMs) / 1000), 1);

  const summary: ScanSummary = {
    hostsScanned: rawRun.stats?.hostsTotal || hosts.length,
    hostsUp: rawRun.stats?.hostsUp || hosts.filter((h) => h.status.value === 'up').length,
    hostsDown: rawRun.stats?.hostsDown || hosts.filter((h) => h.status.value === 'down').length,
    openPorts: totalOpenPorts,
    closedPorts: totalClosedPorts,
    filteredPorts: totalFilteredPorts,
    unknownPorts: totalUnknownPorts,
    elapsedSeconds: elapsed,
    startTime,
    finishTime,
    nmapVersion: rawRun.version || 'Nmap',
    commandExecuted: commandDisplay,
  };

  // Run rule-based risk analyzer to generate actionable observations
  const riskObservations = analyzeRisk(hosts);

  // Update host risk levels based on risk observations
  for (const host of hosts) {
    const hostObs = riskObservations.filter((o) => o.target === host.address.value);
    const hasCritical = hostObs.some((o) => o.severity === 'critical');
    const hasHigh = hostObs.some((o) => o.severity === 'high');
    const hasMed = hostObs.some((o) => o.severity === 'medium');

    if (hasCritical) {
      host.riskLevel = 'critical';
      host.riskScore = { value: 95, source: 'derived' };
    } else if (hasHigh) {
      host.riskLevel = 'high';
      host.riskScore = { value: 75, source: 'derived' };
    } else if (hasMed) {
      host.riskLevel = 'medium';
      host.riskScore = { value: 50, source: 'derived' };
    }
  }

  return {
    scanId,
    status: 'completed',
    startedAt: startTime,
    completedAt: finishTime,
    profile,
    targets,
    summary,
    hosts,
    riskObservations,
    privilegeNotice,
  };
}

/**
 * Estimates OS from service product banners when direct OS fingerprinting was not run
 */
function deriveOsFromBanners(ports: PortResult[]): { name: string; confidence: number } | null {
  for (const p of ports) {
    const banner = `${p.product?.value || ''} ${p.version?.value || ''} ${p.extrainfo || ''}`.toLowerCase();
    if (banner.includes('ubuntu')) {
      return { name: 'Linux (Ubuntu distribution inferred from banner)', confidence: 85 };
    }
    if (banner.includes('debian')) {
      return { name: 'Linux (Debian distribution inferred from banner)', confidence: 85 };
    }
    if (banner.includes('centos') || banner.includes('red hat') || banner.includes('rhel')) {
      return { name: 'Linux (Enterprise Linux inferred from banner)', confidence: 80 };
    }
    if (banner.includes('windows') || banner.includes('microsoft')) {
      return { name: 'Microsoft Windows (Inferred from service banner)', confidence: 80 };
    }
    if (banner.includes('freebsd') || banner.includes('openbsd')) {
      return { name: 'BSD (Inferred from service banner)', confidence: 80 };
    }
    if (banner.includes('linux')) {
      return { name: 'Linux kernel (Inferred from service banner)', confidence: 75 };
    }
  }
  return null;
}
