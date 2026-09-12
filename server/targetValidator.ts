import net from 'net';

export interface TargetClassification {
  target: string;
  type: 'ipv4' | 'ipv6' | 'cidr' | 'hostname';
  category: 'loopback' | 'private' | 'link-local' | 'multicast' | 'public' | 'invalid';
  isExternal: boolean;
  isValid: boolean;
  error?: string;
}

export interface ValidationResult {
  isValid: boolean;
  targets: string[];
  classifications: TargetClassification[];
  hasExternalTarget: boolean;
  error?: string;
}

// Shell metacharacters regex strictly forbidden
const FORBIDDEN_SHELL_CHARS = /[;&|`$()<>\n\r\t\0!^~{}\[\]]/;

// Regex for valid hostname/FQDN (RFC 1123)
const HOSTNAME_REGEX = /^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/;

// IPv4 CIDR regex
const IPV4_CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/(\d{1,2})$/;

/**
 * Checks if an IPv4 integer falls inside a CIDR range represented as [baseInt, maskInt]
 */
function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isIpv4InCidr(ip: string, cidr: string): boolean {
  try {
    const [rangeIp, prefixStr] = cidr.split('/');
    const prefix = parseInt(prefixStr, 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    const ipInt = ipv4ToInt(ip);
    const rangeInt = ipv4ToInt(rangeIp);
    return (ipInt & mask) === (rangeInt & mask);
  } catch {
    return false;
  }
}

/**
 * Classifies an IPv4 address
 */
function classifyIpv4(ip: string): 'loopback' | 'private' | 'link-local' | 'multicast' | 'public' {
  if (isIpv4InCidr(ip, '127.0.0.0/8')) return 'loopback';
  if (isIpv4InCidr(ip, '10.0.0.0/8')) return 'private';
  if (isIpv4InCidr(ip, '172.16.0.0/12')) return 'private';
  if (isIpv4InCidr(ip, '192.168.0.0/16')) return 'private';
  if (isIpv4InCidr(ip, '169.254.0.0/16')) return 'link-local';
  if (isIpv4InCidr(ip, '224.0.0.0/4')) return 'multicast';
  return 'public';
}

/**
 * Validates and classifies a single target string
 */
export function classifySingleTarget(rawTarget: string): TargetClassification {
  const target = rawTarget.trim();

  if (!target) {
    return {
      target,
      type: 'hostname',
      category: 'invalid',
      isExternal: false,
      isValid: false,
      error: 'Target cannot be empty',
    };
  }

  // Check for shell metacharacters or dangerous syntax
  if (FORBIDDEN_SHELL_CHARS.test(target)) {
    return {
      target,
      type: 'hostname',
      category: 'invalid',
      isExternal: false,
      isValid: false,
      error: 'Target contains forbidden shell metacharacters or command delimiters',
    };
  }

  // Check for CIDR notation
  if (target.includes('/')) {
    const match = target.match(IPV4_CIDR_REGEX);
    if (!match) {
      return {
        target,
        type: 'cidr',
        category: 'invalid',
        isExternal: false,
        isValid: false,
        error: 'Invalid CIDR notation format',
      };
    }

    const ipPart = target.split('/')[0];
    const prefix = parseInt(match[2], 10);

    if (!net.isIPv4(ipPart)) {
      return {
        target,
        type: 'cidr',
        category: 'invalid',
        isExternal: false,
        isValid: false,
        error: 'Invalid IPv4 address in CIDR prefix',
      };
    }

    // Safety boundary: prevent scans wider than /24 to stop accidental network flooding
    if (prefix < 24 || prefix > 32) {
      return {
        target,
        type: 'cidr',
        category: 'invalid',
        isExternal: false,
        isValid: false,
        error: 'CIDR prefix must be between /24 and /32 to prevent network exhaustion',
      };
    }

    const category = classifyIpv4(ipPart);
    return {
      target,
      type: 'cidr',
      category,
      isExternal: category === 'public',
      isValid: true,
    };
  }

  // Check if IPv4
  if (net.isIPv4(target)) {
    const category = classifyIpv4(target);
    return {
      target,
      type: 'ipv4',
      category,
      isExternal: category === 'public',
      isValid: true,
    };
  }

  // Check if IPv6
  if (net.isIPv6(target)) {
    const isLoopback = target === '::1' || target === '0:0:0:0:0:0:0:1';
    const isLinkLocal = target.toLowerCase().startsWith('fe80:');
    const isUniqueLocal = target.toLowerCase().startsWith('fc') || target.toLowerCase().startsWith('fd');
    const isExternal = !isLoopback && !isLinkLocal && !isUniqueLocal;

    let category: TargetClassification['category'] = 'public';
    if (isLoopback) category = 'loopback';
    else if (isLinkLocal) category = 'link-local';
    else if (isUniqueLocal) category = 'private';

    return {
      target,
      type: 'ipv6',
      category,
      isExternal,
      isValid: true,
    };
  }

  // Check if valid Hostname / FQDN
  if (HOSTNAME_REGEX.test(target) && !target.startsWith('-')) {
    const lower = target.toLowerCase();
    const isLocal = lower === 'localhost' || lower.endsWith('.local') || lower.endsWith('.internal');
    return {
      target,
      type: 'hostname',
      category: isLocal ? 'private' : 'public',
      isExternal: !isLocal,
      isValid: true,
    };
  }

  return {
    target,
    type: 'hostname',
    category: 'invalid',
    isExternal: false,
    isValid: false,
    error: 'Malformed target: not a valid IPv4, IPv6, CIDR (/24-/32), or Hostname',
  };
}

/**
 * Validates a list or string of targets against allowlists, max limits, and safety rules
 */
export function validateTargets(
  input: string | string[],
  options: {
    maxTargets?: number;
    allowlistRanges?: string[];
  } = {}
): ValidationResult {
  const maxTargets = options.maxTargets || parseInt(process.env.MAX_TARGETS_PER_SCAN || '16', 10);
  
  // Extract allowlist from env if not provided
  let allowlist = options.allowlistRanges;
  if (!allowlist && process.env.ALLOWED_TARGET_RANGES) {
    allowlist = process.env.ALLOWED_TARGET_RANGES.split(',').map((s) => s.trim()).filter(Boolean);
  }

  // Split input if string
  let rawList: string[] = [];
  if (Array.isArray(input)) {
    rawList = input;
  } else if (typeof input === 'string') {
    rawList = input
      .split(/[\r\n, ]+/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);
  }

  if (rawList.length === 0) {
    return {
      isValid: false,
      targets: [],
      classifications: [],
      hasExternalTarget: false,
      error: 'No target specified. Please enter at least one IP or hostname.',
    };
  }

  if (rawList.length > maxTargets) {
    return {
      isValid: false,
      targets: [],
      classifications: [],
      hasExternalTarget: false,
      error: `Too many targets (${rawList.length}). Maximum allowed per scan is ${maxTargets}.`,
    };
  }

  const classifications: TargetClassification[] = [];
  const validTargets: string[] = [];
  let hasExternal = false;

  for (const item of rawList) {
    const classification = classifySingleTarget(item);
    classifications.push(classification);

    if (!classification.isValid) {
      return {
        isValid: false,
        targets: [],
        classifications,
        hasExternalTarget: hasExternal,
        error: `Invalid target "${item}": ${classification.error}`,
      };
    }

    // Check allowlist if configured
    if (allowlist && allowlist.length > 0) {
      const allowed = isTargetInAllowlist(classification.target, allowlist);
      if (!allowed) {
        return {
          isValid: false,
          targets: [],
          classifications,
          hasExternalTarget: hasExternal,
          error: `Target "${item}" is not in the configured ALLOWED_TARGET_RANGES allowlist.`,
        };
      }
    }

    if (classification.isExternal) {
      hasExternal = true;
    }

    validTargets.push(classification.target);
  }

  return {
    isValid: true,
    targets: validTargets,
    classifications,
    hasExternalTarget: hasExternal,
  };
}

/**
 * Checks if a target is matched by any allowlist entry
 */
function isTargetInAllowlist(target: string, allowlist: string[]): boolean {
  for (const entry of allowlist) {
    const trimmed = entry.trim();
    if (!trimmed) continue;

    // Exact match
    if (target.toLowerCase() === trimmed.toLowerCase()) return true;

    // CIDR check for IPv4
    if (trimmed.includes('/') && net.isIPv4(target)) {
      if (isIpv4InCidr(target, trimmed)) return true;
    }
  }
  return false;
}
