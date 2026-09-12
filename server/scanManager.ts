import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { Response } from 'express';
import {
  ScanJob,
  ScanStatus,
  CustomScanOptions,
  ScanResultPayload,
  ScanComparison,
} from './types';
import { validateTargets } from './targetValidator';
import {
  buildNmapArgs,
  executeNmapScan,
  cancelNmapScan,
  createScanTempXmlPath,
  cleanupScanFiles,
} from './nmapService';
import { parseNmapXml } from './xmlParser';
import { normalizeScanResults } from './resultNormalizer';
import { dbSaveScan, dbGetScan } from './database';

const MAX_CONCURRENT_SCANS = parseInt(process.env.MAX_CONCURRENT_SCANS || '2', 10);
const SCAN_TIMEOUT_SECONDS = parseInt(process.env.SCAN_TIMEOUT_SECONDS || '900', 10);

class ScanManager extends EventEmitter {
  private queue: ScanJob[] = [];
  private activeJobs = new Map<string, ScanJob>();
  private completedJobsCache = new Map<string, ScanJob>();
  private sseClients = new Map<string, Set<Response>>();

  constructor() {
    super();
  }

  /**
   * Enqueues a new scan job
   */
  public async createScan(params: {
    target: string;
    profile: string;
    timing?: string;
    customOptions?: CustomScanOptions;
    isPublicTargetConfirmed: boolean;
  }): Promise<{ job?: ScanJob; error?: string }> {
    // 1. Validate targets
    const validation = validateTargets(params.target);
    if (!validation.isValid) {
      return { error: validation.error || 'Invalid target specifications' };
    }

    // 2. Enforce authorization confirmation for public/external targets
    if (validation.hasExternalTarget && !params.isPublicTargetConfirmed) {
      return {
        error:
          'Target appears to be external/public. You must confirm you have explicit written authorization before proceeding.',
      };
    }

    const scanId = `scan_${Date.now()}_${uuidv4().substring(0, 8)}`;
    const timing = params.timing || params.customOptions?.timing || 'T3';
    const xmlPath = createScanTempXmlPath(scanId);

    // 3. Build safe arguments without passing shell strings
    const { args, commandDisplay, privilegeNotice } = buildNmapArgs(
      validation.targets,
      params.profile,
      timing,
      params.customOptions,
      xmlPath
    );

    const job: ScanJob = {
      id: scanId,
      status: 'queued',
      createdAt: new Date().toISOString(),
      targetRaw: params.target,
      validatedTargets: validation.targets,
      isPublicTargetConfirmed: params.isPublicTargetConfirmed,
      profile: params.profile,
      timing,
      customOptions: params.customOptions,
      nmapArgs: args,
      commandDisplay,
      logs: [
        `[CONSOLE] Initialized security scan job ${scanId}`,
        `[CONSOLE] Targets: ${validation.targets.join(', ')}`,
        `[CONSOLE] Profile: ${params.profile} | Timing: ${timing}`,
        `[COMMAND] $ ${commandDisplay}`,
      ],
    };

    if (privilegeNotice) {
      job.logs.push(`[NOTICE] ${privilegeNotice}`);
    }

    this.queue.push(job);
    await dbSaveScan(job);

    // Trigger queue processor
    this.processQueue();

    return { job };
  }

  /**
   * Returns a scan job by ID from active memory or database
   */
  public async getScan(scanId: string): Promise<ScanJob | null> {
    if (this.activeJobs.has(scanId)) {
      return this.activeJobs.get(scanId)!;
    }
    const inQueue = this.queue.find((j) => j.id === scanId);
    if (inQueue) return inQueue;

    if (this.completedJobsCache.has(scanId)) {
      return this.completedJobsCache.get(scanId)!;
    }

    // Fetch from SQLite database
    const dbJob = await dbGetScan(scanId);
    if (dbJob) {
      this.completedJobsCache.set(scanId, dbJob);
      return dbJob;
    }

    return null;
  }

  /**
   * Cancels a running or queued scan
   */
  public async cancelScan(scanId: string): Promise<boolean> {
    // If in queue, mark cancelled and remove
    const qIndex = this.queue.findIndex((j) => j.id === scanId);
    if (qIndex !== -1) {
      const [queuedJob] = this.queue.splice(qIndex, 1);
      queuedJob.status = 'cancelled';
      queuedJob.completedAt = new Date().toISOString();
      queuedJob.logs.push('[CONSOLE] Scan cancelled by user while queued.');
      this.emitScanEvent(scanId, 'status', { status: 'cancelled' });
      await dbSaveScan(queuedJob);
      return true;
    }

    // If currently running, cancel process
    const active = this.activeJobs.get(scanId);
    if (active) {
      active.logs.push('[CONSOLE] Termination signal sent. Cancelling scan...');
      this.emitScanEvent(scanId, 'log', { line: '[CONSOLE] Cancellation requested by operator.' });
      const killed = cancelNmapScan(scanId);
      return killed;
    }

    return false;
  }

  /**
   * Subscribes an SSE client to a scan stream
   */
  public subscribeSse(scanId: string, res: Response): void {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    if (!this.sseClients.has(scanId)) {
      this.sseClients.set(scanId, new Set());
    }
    this.sseClients.get(scanId)!.add(res);

    // Send initial ping and historical logs
    res.write(`event: init\ndata: ${JSON.stringify({ scanId })}\n\n`);

    const currentJob = this.activeJobs.get(scanId) || this.queue.find((j) => j.id === scanId) || this.completedJobsCache.get(scanId);
    if (currentJob) {
      res.write(`event: status\ndata: ${JSON.stringify({ status: currentJob.status })}\n\n`);
      for (const line of currentJob.logs) {
        res.write(`event: log\ndata: ${JSON.stringify({ line })}\n\n`);
      }
      if (currentJob.results) {
        res.write(`event: complete\ndata: ${JSON.stringify({ results: currentJob.results })}\n\n`);
      }
    }

    res.on('close', () => {
      const set = this.sseClients.get(scanId);
      if (set) {
        set.delete(res);
        if (set.size === 0) {
          this.sseClients.delete(scanId);
        }
      }
    });
  }

  /**
   * Broadcasts an SSE event to all connected subscribers for a scan
   */
  private emitScanEvent(scanId: string, eventName: string, data: any): void {
    const clients = this.sseClients.get(scanId);
    if (clients && clients.size > 0) {
      const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
      for (const client of clients) {
        try {
          client.write(payload);
        } catch {
          clients.delete(client);
        }
      }
    }
  }

  /**
   * Internal queue processing loop
   */
  private async processQueue(): Promise<void> {
    if (this.activeJobs.size >= MAX_CONCURRENT_SCANS || this.queue.length === 0) {
      return;
    }

    const job = this.queue.shift();
    if (!job) return;

    job.status = 'running';
    job.startedAt = new Date().toISOString();
    this.activeJobs.set(job.id, job);

    this.emitScanEvent(job.id, 'status', { status: 'running' });
    this.emitScanEvent(job.id, 'log', { line: `[CONSOLE] Scan started at ${job.startedAt}` });
    await dbSaveScan(job);

    const xmlPath = createScanTempXmlPath(job.id);

    try {
      const execResult = await executeNmapScan(
        job.id,
        job.nmapArgs,
        xmlPath,
        (stdoutLine) => {
          job.logs.push(stdoutLine);
          this.emitScanEvent(job.id, 'log', { line: stdoutLine });
        },
        (stderrLine) => {
          job.logs.push(`[STDERR] ${stderrLine}`);
          this.emitScanEvent(job.id, 'log', { line: `[STDERR] ${stderrLine}` });
        },
        SCAN_TIMEOUT_SECONDS
      );

      job.completedAt = new Date().toISOString();

      if (execResult.signal === 'SIGTERM' || execResult.signal === 'SIGKILL') {
        job.status = 'cancelled';
        job.logs.push('[CONSOLE] Scan process was cancelled.');
        this.emitScanEvent(job.id, 'status', { status: 'cancelled' });
      } else if (execResult.code === 0 || execResult.xmlContent) {
        // Success or usable XML obtained
        try {
          if (execResult.xmlContent) {
            const rawRun = parseNmapXml(execResult.xmlContent);
            const normalized = normalizeScanResults(
              job.id,
              rawRun,
              job.validatedTargets,
              job.profile,
              job.commandDisplay,
              job.startedAt!,
              job.completedAt!,
              job.logs.find((l) => l.startsWith('[NOTICE]'))?.replace('[NOTICE] ', '')
            );

            job.results = normalized;
            job.summary = normalized.summary;
            job.status = 'completed';
            job.logs.push(`[CONSOLE] Scan completed successfully. Hosts up: ${normalized.summary.hostsUp}, Open ports: ${normalized.summary.openPorts}`);

            this.emitScanEvent(job.id, 'status', { status: 'completed' });
            this.emitScanEvent(job.id, 'complete', { results: normalized });

            // Send webhook if configured
            this.sendWebhookNotification(job, normalized);
          } else {
            job.status = 'completed';
            job.logs.push('[CONSOLE] Scan completed, but XML result file was empty.');
            this.emitScanEvent(job.id, 'status', { status: 'completed' });
          }
        } catch (parseErr: any) {
          console.error(`XML parse error for ${job.id}:`, parseErr);
          job.status = 'failed';
          job.errorMessage = `Result parsing error: ${parseErr.message}`;
          job.logs.push(`[ERROR] Failed to parse scan output: ${parseErr.message}`);
          this.emitScanEvent(job.id, 'status', { status: 'failed', error: job.errorMessage });
        }
      } else {
        job.status = 'failed';
        job.errorMessage = `Nmap exited with code ${execResult.code}`;
        job.logs.push(`[ERROR] Nmap process failed (code ${execResult.code})`);
        this.emitScanEvent(job.id, 'status', { status: 'failed', error: job.errorMessage });
      }
    } catch (err: any) {
      job.status = 'failed';
      job.completedAt = new Date().toISOString();
      job.errorMessage = err?.message || 'Execution error';
      job.logs.push(`[ERROR] Scan execution exception: ${job.errorMessage}`);
      this.emitScanEvent(job.id, 'status', { status: 'failed', error: job.errorMessage });
    } finally {
      // Clean up XML temp file safely
      cleanupScanFiles(xmlPath);

      this.activeJobs.delete(job.id);
      this.completedJobsCache.set(job.id, job);
      await dbSaveScan(job);

      // Process next job in queue
      setTimeout(() => this.processQueue(), 50);
    }
  }

  /**
   * Dispatches webhook notification if configured
   */
  private async sendWebhookNotification(job: ScanJob, results: ScanResultPayload): Promise<void> {
    const webhookUrl = process.env.NOTIFICATION_WEBHOOK_URL;
    if (!webhookUrl || !webhookUrl.startsWith('http')) return;

    try {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event: 'scan_completed',
          scanId: job.id,
          target: job.targetRaw,
          profile: job.profile,
          hostsScanned: results.summary.hostsScanned,
          hostsUp: results.summary.hostsUp,
          openPorts: results.summary.openPorts,
          elapsedSeconds: results.summary.elapsedSeconds,
          completedAt: results.completedAt,
        }),
        signal: AbortSignal.timeout(4000),
      });
    } catch (err) {
      console.warn('Webhook notification delivery failed:', err);
    }
  }

  /**
   * Compares two scan results and calculates diff
   */
  public async compareScans(scanAId: string, scanBId: string): Promise<ScanComparison | null> {
    const scanA = await this.getScan(scanAId);
    const scanB = await this.getScan(scanBId);

    if (!scanA?.results || !scanB?.results) return null;

    const resA = scanA.results;
    const resB = scanB.results;

    const hostsA = new Set(resA.hosts.map((h) => h.address.value));
    const hostsB = new Set(resB.hosts.map((h) => h.address.value));

    const newHosts = Array.from(hostsB).filter((h) => !hostsA.has(h));
    const removedHosts = Array.from(hostsA).filter((h) => !hostsB.has(h));

    const newOpenPorts: ScanComparison['newOpenPorts'] = [];
    const closedPorts: ScanComparison['closedPorts'] = [];
    const serviceChanges: ScanComparison['serviceChanges'] = [];

    // Map open ports in scan A: "host:port" -> PortResult
    const portsMapA = new Map<string, { host: string; port: number; service: string; version?: string }>();
    for (const h of resA.hosts) {
      for (const p of h.ports) {
        if (p.state.value === 'open') {
          portsMapA.set(`${h.address.value}:${p.port}/${p.protocol}`, {
            host: h.address.value,
            port: p.port,
            service: p.service.value,
            version: p.version?.value,
          });
        }
      }
    }

    // Map open ports in scan B
    const portsMapB = new Map<string, { host: string; port: number; service: string; version?: string }>();
    for (const h of resB.hosts) {
      for (const p of h.ports) {
        if (p.state.value === 'open') {
          portsMapB.set(`${h.address.value}:${p.port}/${p.protocol}`, {
            host: h.address.value,
            port: p.port,
            service: p.service.value,
            version: p.version?.value,
          });
        }
      }
    }

    // Check for newly opened ports or changed services
    for (const [key, bData] of portsMapB.entries()) {
      const aData = portsMapA.get(key);
      const [host, protoPart] = key.split(':');
      const [portStr, protocol] = protoPart.split('/');

      if (!aData) {
        newOpenPorts.push({
          host: bData.host,
          port: bData.port,
          protocol,
          service: bData.service,
        });
      } else {
        // Check for service or version differences
        const serviceChanged = aData.service !== bData.service;
        const versionChanged = aData.version !== bData.version && (aData.version || bData.version);

        if (serviceChanged || versionChanged) {
          serviceChanges.push({
            host: bData.host,
            port: bData.port,
            oldService: aData.service,
            newService: bData.service,
            oldVersion: aData.version,
            newVersion: bData.version,
          });
        }
      }
    }

    // Check for closed ports
    for (const [key, aData] of portsMapA.entries()) {
      if (!portsMapB.has(key)) {
        const [, protoPart] = key.split(':');
        const [, protocol] = protoPart.split('/');
        closedPorts.push({
          host: aData.host,
          port: aData.port,
          protocol,
          previousService: aData.service,
        });
      }
    }

    const openCountA = resA.summary.openPorts;
    const openCountB = resB.summary.openPorts;
    const delta = openCountB > openCountA ? `+${openCountB - openCountA} open ports` : openCountB < openCountA ? `-${openCountA - openCountB} open ports` : 'No net port count change';

    return {
      scanA: { id: scanA.id, target: scanA.targetRaw, date: scanA.createdAt },
      scanB: { id: scanB.id, target: scanB.targetRaw, date: scanB.createdAt },
      newHosts,
      removedHosts,
      newOpenPorts,
      closedPorts,
      serviceChanges,
      riskChange: {
        previousRisk: `${resA.riskObservations.length} observations`,
        currentRisk: `${resB.riskObservations.length} observations`,
        delta,
      },
    };
  }

  public getQueueStatus() {
    return {
      activeCount: this.activeJobs.size,
      queuedCount: this.queue.length,
      maxConcurrent: MAX_CONCURRENT_SCANS,
    };
  }
}

export const scanManager = new ScanManager();
