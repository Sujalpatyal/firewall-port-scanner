import { HostResult, RiskObservation, PortResult } from './types';

interface ServiceRiskRule {
  ports: number[];
  serviceNames?: string[];
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  recommendation: string;
  appliesToPublicOnly?: boolean;
}

const RISK_RULES: ServiceRiskRule[] = [
  {
    ports: [23],
    serviceNames: ['telnet'],
    severity: 'critical',
    title: 'Potentially risky exposure: Unencrypted Telnet Administration Service',
    description: 'Telnet transmits credentials and command sessions in cleartext. Any intermediary network device can capture usernames and passwords.',
    recommendation: 'Immediately disable Telnet and migrate to SSH (Port 22) using key-based authentication.',
  },
  {
    ports: [21],
    serviceNames: ['ftp'],
    severity: 'high',
    title: 'Potentially risky exposure: Plaintext FTP Protocol',
    description: 'Standard File Transfer Protocol (FTP) sends authentication and data packets unencrypted across the network.',
    recommendation: 'Restrict FTP to internal authorized interfaces, or transition to SFTP (SSH File Transfer) or FTPS (FTP over TLS).',
  },
  {
    ports: [3389],
    serviceNames: ['ms-wbt-server', 'rdp'],
    severity: 'high',
    title: 'Potentially risky exposure: Remote Desktop Protocol (RDP)',
    description: 'Direct exposure of RDP is a frequent target for credential stuffing, brute force, and known protocol exploits.',
    recommendation: 'Place RDP behind an encrypted VPN, Zero Trust network access (ZTNA), or enable Network Level Authentication (NLA) with IP restriction.',
  },
  {
    ports: [5900, 5901],
    serviceNames: ['vnc'],
    severity: 'high',
    title: 'Potentially risky exposure: Virtual Network Computing (VNC)',
    description: 'VNC services are often poorly encrypted and vulnerable to authentication bypass or brute-force scanning.',
    recommendation: 'Tunnel VNC connections over SSH or VPN. Do not leave Port 5900 directly exposed.',
  },
  {
    ports: [445, 139],
    serviceNames: ['microsoft-ds', 'netbios-ssn', 'smb'],
    severity: 'high',
    title: 'Potentially risky exposure: Server Message Block (SMB/CIFS)',
    description: 'Exposing SMB services externally or across untrusted network boundaries introduces severe risks (e.g. ransomware propagation, wormable exploits).',
    recommendation: 'Filter ports 139/445 at firewall boundaries. SMB should never be accessible from the public internet.',
  },
  {
    ports: [6379],
    serviceNames: ['redis'],
    severity: 'critical',
    title: 'Potentially risky exposure: Redis In-Memory Datastore',
    description: 'Redis instances are frequently configured without authentication or with weak default settings, allowing arbitrary command execution or data extraction.',
    recommendation: 'Bind Redis to 127.0.0.1 or an isolated private VPC subnet. Enforce strong requirepass and TLS encryption.',
  },
  {
    ports: [27017, 27018],
    serviceNames: ['mongodb'],
    severity: 'high',
    title: 'Potentially risky exposure: MongoDB Database Port',
    description: 'Database listeners exposed without strict network segmentation risk unauthorized querying, automated ransomware scraping, and data exfiltration.',
    recommendation: 'Enforce authentication, bind to internal addresses only, and employ firewall drop rules for untrusted IP ranges.',
  },
  {
    ports: [3306],
    serviceNames: ['mysql'],
    severity: 'medium',
    title: 'Potentially risky exposure: MySQL Database Listener',
    description: 'Direct internet exposure of SQL databases invites targeted password brute-forcing and denial-of-service attempts.',
    recommendation: 'Place database servers inside an internal application subnet and connect application servers over private VPNs.',
  },
  {
    ports: [5432],
    serviceNames: ['postgresql'],
    severity: 'medium',
    title: 'Potentially risky exposure: PostgreSQL Database Listener',
    description: 'Relational database port is visible on the network interface.',
    recommendation: 'Ensure pg_hba.conf enforces client certificate/TLS verification and restricts access to specific trusted application IP addresses.',
  },
  {
    ports: [9200, 9300],
    serviceNames: ['elasticsearch'],
    severity: 'high',
    title: 'Potentially risky exposure: Elasticsearch HTTP/Node API',
    description: 'Elasticsearch REST endpoints exposed without authentication allow unprivileged search, deletion, and index dumping.',
    recommendation: 'Enable X-Pack security features with username/password authentication, TLS, and bind strictly to private network interfaces.',
  },
  {
    ports: [11211],
    serviceNames: ['memcached'],
    severity: 'high',
    title: 'Potentially risky exposure: Memcached Service',
    description: 'Exposed Memcached instances can be exploited for UDP reflection DDoS amplification attacks and sensitive cache exposure.',
    recommendation: 'Disable UDP support (-U 0) and bind Memcached exclusively to localhost or a private internal socket.',
  },
  {
    ports: [161, 162],
    serviceNames: ['snmp'],
    severity: 'medium',
    title: 'Potentially risky exposure: SNMP Management Protocol',
    description: 'SNMP v1 and v2c use cleartext community strings (e.g. "public", "private") allowing attackers to gather detailed internal system reconnaissance.',
    recommendation: 'Upgrade to SNMPv3 with cryptographic authentication and privacy (authPriv), or restrict via access control lists.',
  },
  {
    ports: [22],
    serviceNames: ['ssh'],
    severity: 'low',
    title: 'Observation: Secure Shell (SSH) Administration Interface',
    description: 'Port 22 is open. While SSH is an encrypted standard protocol, public-facing instances receive constant automated brute-force attacks.',
    recommendation: 'Enforce public-key authentication, disable root password login (PermitRootLogin prohibit-password), and consider rate-limiting tools (fail2ban).',
  },
  {
    ports: [80, 8080],
    serviceNames: ['http'],
    severity: 'low',
    title: 'Observation: Plaintext HTTP Web Server',
    description: 'Unencrypted web services transmit sensitive cookies, tokens, and form data in cleartext.',
    recommendation: 'Configure an automatic 301 redirect to HTTPS (port 443) with valid TLS certificates and HTTP Strict Transport Security (HSTS).',
  },
];

/**
 * Evaluates host port states and produces structured risk observations
 */
export function analyzeRisk(hosts: HostResult[]): RiskObservation[] {
  const observations: RiskObservation[] = [];
  let obsCounter = 1;

  for (const host of hosts) {
    const targetAddr = host.address.value;
    const isPublic = !host.isPrivate;

    for (const port of host.ports) {
      if (port.state.value !== 'open') continue;

      const portNum = port.port;
      const sName = (port.service.value || '').toLowerCase();

      // Find matching rule
      for (const rule of RISK_RULES) {
        const matchesPort = rule.ports.includes(portNum);
        const matchesService = rule.serviceNames?.some((sn) => sName.includes(sn));

        if (matchesPort || matchesService) {
          // Check public constraint if specified
          if (rule.appliesToPublicOnly && !isPublic) {
            continue;
          }

          let severity = rule.severity;
          // Escalate severity if public target
          if (isPublic && (severity === 'medium' || severity === 'high')) {
            if (rule.ports.includes(3306) || rule.ports.includes(5432)) {
              severity = 'high';
            }
          }

          const obs: RiskObservation = {
            id: `risk_${obsCounter++}`,
            severity,
            title: rule.title,
            target: targetAddr,
            port: portNum,
            service: port.service.value,
            description: rule.description,
            recommendation: rule.recommendation,
            source: 'derived',
          };

          observations.push(obs);

          // Attach risk info directly onto port
          port.risk = {
            level: severity,
            summary: rule.title.replace('Potentially risky exposure: ', ''),
            recommendation: rule.recommendation,
          };

          break; // Avoid double matching same port
        }
      }
    }
  }

  return observations;
}
