import { spawn, execFile, ChildProcess } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { CustomScanOptions } from './types';

export interface NmapCheckResult {
  available: boolean;
  version: string;
  hasRawSocketPrivilege: boolean;
  error?: string;
}

export interface NmapExecutionResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  xmlPath: string;
  xmlContent?: string;
  durationMs: number;
}

const TEMP_DIR = path.join(os.tmpdir(), 'firewall_scans');
const WINDOWS_NMAP_PATHS = [
  'C:\\Program Files (x86)\\Nmap\\nmap.exe',
  'C:\\Program Files\\Nmap\\nmap.exe',
];
const NMAP_BINARY = process.env.NMAP_PATH
  || (process.platform === 'win32'
    ? WINDOWS_NMAP_PATHS.find(candidate => fs.existsSync(candidate)) || 'nmap'
    : 'nmap');

// Ensure temp directory exists
try {
  if (!fs.existsSync(TEMP_DIR)) {
    fs.mkdirSync(TEMP_DIR, { recursive: true });
  }
} catch (err) {
  console.error('Failed to create scan temp dir:', err);
}

// Track running processes for cancellation
const activeProcesses = new Map<string, { process: ChildProcess; xmlPath: string; startedAt: number }>();

let rawSocketSupportCache: boolean | null = null;

/**
 * Checks whether raw socket packet injection is supported in current container network
 */
export function checkRawSocketSupport(): Promise<boolean> {
  // Windows Nmap needs a working Npcap driver for raw-packet scans. Avoid a
  // SYN probe here: an outdated driver can emit a misleading warning while
  // Nmap silently falls back to TCP connect mode.
  if (process.platform === 'win32') {
    rawSocketSupportCache = false;
    return Promise.resolve(false);
  }

  if (rawSocketSupportCache !== null) {
    return Promise.resolve(rawSocketSupportCache);
  }
  return new Promise((resolve) => {
    execFile(NMAP_BINARY, ['-sS', '-p', '3000', '127.0.0.1'], { timeout: 2000 }, (error, _stdout, stderr) => {
      if (error || (stderr && (stderr.includes('Error') || stderr.includes('QUITTING') || stderr.includes('requires root')))) {
        rawSocketSupportCache = false;
        return resolve(false);
      }
      rawSocketSupportCache = true;
      resolve(true);
    });
  });
}

/**
 * Checks if Nmap is installed and queries its version
 */
export async function checkNmapAvailability(): Promise<NmapCheckResult> {
  const isRaw = await checkRawSocketSupport();
  return new Promise((resolve) => {
    execFile(NMAP_BINARY, ['--version'], { timeout: 5000 }, (error, stdout, stderr) => {
      if (error) {
        return resolve({
          available: false,
          version: 'Not detected',
          hasRawSocketPrivilege: false,
          error: error.message,
        });
      }

      const match = stdout.match(/Nmap version ([0-9.]+)/i);
      const version = match ? `Nmap ${match[1]}` : stdout.split('\n')[0].trim();

      resolve({
        available: true,
        version,
        hasRawSocketPrivilege: isRaw,
      });
    });
  });
}

/**
 * Validate port string format strictly: e.g. "22", "80,443,8080", "1-1000", "-p-"
 */
export function validatePortSpecification(portSpec: string): { isValid: boolean; sanitized: string; error?: string } {
  const trimmed = portSpec.trim();
  if (!trimmed) {
    return { isValid: false, sanitized: '', error: 'Port specification cannot be empty' };
  }

  if (trimmed === '-p-') {
    return { isValid: true, sanitized: '-p-' };
  }

  // Allow numbers, commas, and hyphens only
  if (!/^[0-9,-]+$/.test(trimmed)) {
    return { isValid: false, sanitized: '', error: 'Invalid characters in port specification. Use numbers, commas, or hyphens (e.g. 80,443 or 1-1024)' };
  }

  // Validate port numbers within 1-65535
  const parts = trimmed.split(',');
  for (const part of parts) {
    if (part.includes('-')) {
      const [startStr, endStr] = part.split('-');
      const start = parseInt(startStr, 10);
      const end = parseInt(endStr, 10);
      if (isNaN(start) || isNaN(end) || start < 1 || end > 65535 || start > end) {
        return { isValid: false, sanitized: '', error: `Invalid port range: ${part}. Ports must be 1-65535.` };
      }
    } else {
      const p = parseInt(part, 10);
      if (isNaN(p) || p < 1 || p > 65535) {
        return { isValid: false, sanitized: '', error: `Invalid port number: ${part}. Ports must be 1-65535.` };
      }
    }
  }

  return { isValid: true, sanitized: trimmed };
}

/**
 * Builds safe argument list for Nmap based on requested profile and custom options
 */
export function buildNmapArgs(
  targets: string[],
  profile: string,
  timing: string = 'T3',
  customOptions?: CustomScanOptions,
  xmlOutputPath: string = ''
): { args: string[]; commandDisplay: string; privilegeNotice?: string } {
  const args: string[] = [];
  let privilegeNotice: string | undefined;

  const validTimings = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
  const timingFlag = validTimings.includes(timing) ? `-${timing}` : '-T3';

  // Standard non-privileged safe options
  const isRawSupported = rawSocketSupportCache !== false && (typeof process.getuid === 'function' ? process.getuid() === 0 : false);

  if (!isRawSupported) {
    args.push('--unprivileged');
  }

  // Loopback targets are a built-in quick-test preset. Force them to be
  // treated as online so Windows firewall/driver ICMP behavior cannot make a
  // local scan incorrectly report "Host seems down".
  const hasLoopbackTarget = targets.some(target =>
    target === 'localhost' || target === '::1' || target.startsWith('127.')
  );
  if (hasLoopbackTarget) {
    args.push('-Pn');
  }

  args.push(timingFlag);
  args.push('-v'); // verbose output for real-time console feedback
  args.push('--stats-every', '5s'); // regular progress telemetry

  const isRoot = isRawSupported;

  const profileLower = profile.toLowerCase();

  if (profileLower === 'quick') {
    args.push('-sT'); // TCP Connect (unprivileged)
    args.push('--top-ports', '100');
  } else if (profileLower === 'standard') {
    args.push('-sT');
    args.push('--top-ports', '1000');
  } else if (profileLower === 'comprehensive') {
    args.push('-sT');
    args.push('-sV'); // Version detection
    args.push('--version-intensity', '5');
    args.push('-p-'); // Full range
  } else if (profileLower === 'stealth') {
    if (!isRoot) {
      // In unprivileged containers, SYN scan (-sS) will fail or require root
      privilegeNotice = 'SYN Stealth scan (-sS) requires raw socket/root privileges. Running with standard TCP Connect (-sT) fallback.';
      args.push('-sT');
    } else {
      args.push('-sS');
    }
    args.push('--top-ports', '1000');
  } else if (profileLower === 'udp focus' || profileLower === 'udp') {
    if (!isRoot) {
      privilegeNotice = 'UDP scanning (-sU) requires raw packet privileges. Unprivileged execution may be restricted by the container environment.';
    }
    args.push('-sU');
    args.push('--top-ports', '100');
  } else if (profileLower === 'custom' && customOptions) {
    // Custom profile builder
    if (customOptions.technique === 'sS') {
      if (!isRoot) {
        privilegeNotice = 'SYN Stealth (-sS) requested without root privileges. Falling back to TCP Connect (-sT).';
        args.push('-sT');
      } else {
        args.push('-sS');
      }
    } else if (customOptions.technique === 'sU') {
      if (!isRoot) {
        privilegeNotice = 'UDP scan (-sU) requires elevated container privileges.';
      }
      args.push('-sU');
    } else if (customOptions.technique === 'sA') {
      args.push(isRoot ? '-sA' : '-sT');
    } else {
      args.push('-sT'); // Default safe TCP connect
    }

    if (customOptions.ports) {
      const portValidation = validatePortSpecification(customOptions.ports);
      if (portValidation.isValid) {
        if (portValidation.sanitized === '-p-') {
          args.push('-p-');
        } else {
          args.push('-p', portValidation.sanitized);
        }
      }
    } else if (customOptions.topPorts) {
      const safeTop = Math.min(Math.max(customOptions.topPorts, 1), 5000);
      args.push('--top-ports', safeTop.toString());
    } else if (customOptions.fastScan) {
      args.push('-F');
    }

    if (customOptions.serviceDetection) {
      args.push('-sV');
    }

    if (customOptions.osDetection) {
      if (!isRoot) {
        privilegeNotice = (privilegeNotice ? privilegeNotice + ' ' : '') + 'OS detection (-O) requires raw socket root privileges. Estimated OS will be derived from service banners.';
      } else {
        args.push('-O');
      }
    }

    if (customOptions.dontPing && !hasLoopbackTarget) {
      args.push('-Pn');
    }

    if (customOptions.traceroute && isRoot) {
      args.push('--traceroute');
    }
  } else {
    // Default fallback
    args.push('-sT');
    args.push('--top-ports', '1000');
  }

  // XML output for structured parsing
  if (xmlOutputPath) {
    args.push('-oX', xmlOutputPath);
  }

  // Append validated targets
  args.push(...targets);

  const commandDisplay = `nmap ${args.filter(a => a !== xmlOutputPath && a !== '-oX').join(' ')}`;

  return { args, commandDisplay, privilegeNotice };
}

/**
 * Spawns the Nmap subprocess safely with streaming output and timeout enforcement
 */
export function executeNmapScan(
  scanId: string,
  args: string[],
  xmlPath: string,
  onStdoutLine: (line: string) => void,
  onStderrLine: (line: string) => void,
  timeoutSeconds: number = 900
): Promise<NmapExecutionResult> {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    let stdoutBuffer = '';
    let stderrBuffer = '';
    let isTerminated = false;

    // Launch Nmap without shell
    const child = spawn(NMAP_BINARY, args, {
      shell: false,
      env: {
        ...process.env,
        PATH: process.env.PATH || '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      },
    });

    activeProcesses.set(scanId, { process: child, xmlPath, startedAt });

    // Stream stdout line by line
    let partialStdout = '';
    child.stdout.on('data', (chunk: Buffer) => {
      const text = chunk.toString();
      stdoutBuffer += text;
      partialStdout += text;
      const lines = partialStdout.split('\n');
      partialStdout = lines.pop() || '';
      for (const line of lines) {
        if (line.trim().length > 0) {
          onStdoutLine(line);
        }
      }
    });

    // Stream stderr
    let partialStderr = '';
    child.stderr.on('data', (chunk: Buffer) => {
      const text = chunk.toString();
      stderrBuffer += text;
      partialStderr += text;
      const lines = partialStderr.split('\n');
      partialStderr = lines.pop() || '';
      for (const line of lines) {
        if (line.trim().length > 0) {
          onStderrLine(line);
        }
      }
    });

    // Timeout watchdog
    const timeoutHandle = setTimeout(() => {
      if (!isTerminated) {
        isTerminated = true;
        onStderrLine(`[SECURITY SCANNER] Execution exceeded maximum timeout of ${timeoutSeconds}s. Terminating scan.`);
        try {
          child.kill('SIGTERM');
          setTimeout(() => {
            try { child.kill('SIGKILL'); } catch {}
          }, 2000);
        } catch {}
      }
    }, timeoutSeconds * 1000);

    // Error on spawn
    child.on('error', (err) => {
      clearTimeout(timeoutHandle);
      activeProcesses.delete(scanId);
      reject(new Error(`Failed to start Nmap process: ${err.message}`));
    });

    // Process close
    child.on('close', (code, signal) => {
      clearTimeout(timeoutHandle);
      activeProcesses.delete(scanId);

      // Flush remaining lines
      if (partialStdout.trim().length > 0) onStdoutLine(partialStdout);
      if (partialStderr.trim().length > 0) onStderrLine(partialStderr);

      const durationMs = Date.now() - startedAt;

      // Read XML if generated
      let xmlContent: string | undefined;
      try {
        if (fs.existsSync(xmlPath)) {
          xmlContent = fs.readFileSync(xmlPath, 'utf-8');
        }
      } catch (err) {
        console.warn(`Could not read XML result at ${xmlPath}:`, err);
      }

      resolve({
        code,
        signal,
        stdout: stdoutBuffer,
        stderr: stderrBuffer,
        xmlPath,
        xmlContent,
        durationMs,
      });
    });
  });
}

/**
 * Cancels a running scan by ID
 */
export function cancelNmapScan(scanId: string): boolean {
  const entry = activeProcesses.get(scanId);
  if (!entry) return false;

  try {
    entry.process.kill('SIGTERM');
    setTimeout(() => {
      try {
        entry.process.kill('SIGKILL');
      } catch {}
    }, 1500);
    return true;
  } catch (err) {
    console.error(`Error terminating scan ${scanId}:`, err);
    return false;
  }
}

/**
 * Generates a clean temporary XML file path
 */
export function createScanTempXmlPath(scanId: string): string {
  return path.join(TEMP_DIR, `${scanId}.xml`);
}

/**
 * Safely removes temporary scan files
 */
export function cleanupScanFiles(xmlPath: string): void {
  try {
    if (fs.existsSync(xmlPath)) {
      fs.unlinkSync(xmlPath);
    }
  } catch (err) {
    console.warn(`Failed to remove temporary file ${xmlPath}:`, err);
  }
}
