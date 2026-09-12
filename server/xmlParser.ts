import { XMLParser } from 'fast-xml-parser';

export interface RawXmlNmapPort {
  protocol: string;
  portId: number;
  state: string;
  reason?: string;
  serviceName?: string;
  product?: string;
  version?: string;
  extrainfo?: string;
  conf?: number;
  method?: string;
}

export interface RawXmlNmapHost {
  address: string;
  addrType: string;
  vendor?: string;
  status: string;
  statusReason?: string;
  hostname?: string;
  ports: RawXmlNmapPort[];
  extraPorts?: { state: string; count: number }[];
  osMatches: { name: string; accuracy: number }[];
  srtt?: number;
}

export interface RawXmlNmapRun {
  scanner: string;
  args: string;
  version: string;
  startStr?: string;
  hosts: RawXmlNmapHost[];
  stats?: {
    hostsUp: number;
    hostsDown: number;
    hostsTotal: number;
    elapsedSeconds: number;
    exitStatus?: string;
  };
}

/**
 * Normalizes an item or array into an array
 */
function ensureArray<T>(item: T | T[] | undefined): T[] {
  if (item === undefined || item === null) return [];
  return Array.isArray(item) ? item : [item];
}

/**
 * Parses Nmap XML output into structured intermediate objects
 */
export function parseNmapXml(xmlContent: string): RawXmlNmapRun {
  if (!xmlContent || xmlContent.trim().length === 0) {
    throw new Error('Nmap XML content is empty');
  }

  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    parseAttributeValue: true,
    textNodeName: '#text',
  });

  const parsed = parser.parse(xmlContent);
  const nmaprun = parsed?.nmaprun;

  if (!nmaprun) {
    throw new Error('Invalid Nmap XML: Missing root <nmaprun> element');
  }

  const result: RawXmlNmapRun = {
    scanner: nmaprun['@_scanner'] || 'nmap',
    args: nmaprun['@_args'] || '',
    version: nmaprun['@_version'] || 'Nmap',
    startStr: nmaprun['@_startstr'],
    hosts: [],
  };

  // Parse runstats
  if (nmaprun.runstats) {
    const rs = nmaprun.runstats;
    const hostsStat = rs.hosts;
    const finishedStat = rs.finished;

    result.stats = {
      hostsUp: hostsStat ? parseInt(hostsStat['@_up'] || '0', 10) : 0,
      hostsDown: hostsStat ? parseInt(hostsStat['@_down'] || '0', 10) : 0,
      hostsTotal: hostsStat ? parseInt(hostsStat['@_total'] || '0', 10) : 0,
      elapsedSeconds: finishedStat ? parseFloat(finishedStat['@_elapsed'] || '0') : 0,
      exitStatus: finishedStat ? finishedStat['@_exit'] : undefined,
    };
  }

  // Parse hosts
  const hostElements = ensureArray(nmaprun.host);

  for (const h of hostElements) {
    // Address
    const addressElements = ensureArray(h.address);
    let primaryAddr = '';
    let addrType = 'ipv4';
    let vendor: string | undefined;

    for (const a of addressElements) {
      const type = a['@_addrtype'];
      if (type === 'ipv4' || type === 'ipv6') {
        primaryAddr = a['@_addr'] || '';
        addrType = type;
      } else if (type === 'mac') {
        vendor = a['@_vendor'];
        if (!primaryAddr) {
          primaryAddr = a['@_addr'] || '';
          addrType = 'mac';
        }
      }
    }

    if (!primaryAddr && addressElements.length > 0) {
      primaryAddr = addressElements[0]['@_addr'] || 'unknown';
    }

    // Status
    const statusObj = h.status || {};
    const hostStatus = statusObj['@_state'] || 'unknown';
    const statusReason = statusObj['@_reason'];

    // Hostname
    let hostname: string | undefined;
    if (h.hostnames && h.hostnames.hostname) {
      const hnList = ensureArray(h.hostnames.hostname);
      if (hnList.length > 0 && hnList[0]['@_name']) {
        hostname = hnList[0]['@_name'];
      }
    }

    // Ports
    const portsList: RawXmlNmapPort[] = [];
    const extraPortsList: { state: string; count: number }[] = [];

    if (h.ports) {
      // Extraports (e.g. 997 closed ports)
      const epElements = ensureArray(h.ports.extraports);
      for (const ep of epElements) {
        extraPortsList.push({
          state: ep['@_state'] || 'closed',
          count: parseInt(ep['@_count'] || '0', 10),
        });
      }

      // Explicit ports
      const portElements = ensureArray(h.ports.port);
      for (const p of portElements) {
        const portId = parseInt(p['@_portid'], 10);
        const protocol = p['@_protocol'] || 'tcp';
        const stateObj = p.state || {};
        const state = stateObj['@_state'] || 'unknown';
        const reason = stateObj['@_reason'];

        const serviceObj = p.service || {};
        const serviceName = serviceObj['@_name'];
        const product = serviceObj['@_product'];
        const version = serviceObj['@_version'];
        const extrainfo = serviceObj['@_extrainfo'];
        const conf = serviceObj['@_conf'] ? parseInt(serviceObj['@_conf'], 10) : undefined;
        const method = serviceObj['@_method'];

        portsList.push({
          protocol,
          portId,
          state,
          reason,
          serviceName,
          product,
          version,
          extrainfo,
          conf,
          method,
        });
      }
    }

    // OS matches
    const osMatchesList: { name: string; accuracy: number }[] = [];
    if (h.os && h.os.osmatch) {
      const osList = ensureArray(h.os.osmatch);
      for (const om of osList) {
        if (om['@_name']) {
          osMatchesList.push({
            name: om['@_name'],
            accuracy: parseInt(om['@_accuracy'] || '0', 10),
          });
        }
      }
    }

    // Latency
    let srtt: number | undefined;
    if (h.times && h.times['@_srtt']) {
      // Nmap srtt is in microseconds
      srtt = Math.round(parseInt(h.times['@_srtt'], 10) / 1000);
    }

    result.hosts.push({
      address: primaryAddr,
      addrType,
      vendor,
      status: hostStatus,
      statusReason,
      hostname,
      ports: portsList,
      extraPorts: extraPortsList,
      osMatches: osMatchesList,
      srtt,
    });
  }

  return result;
}
