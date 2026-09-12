import { Router, Request, Response } from 'express';
import { scanManager } from '../scanManager';

export const scansRouter = Router();

/**
 * POST /api/scans
 * Initiates a new scan job
 */
scansRouter.post('/', async (req: Request, res: Response) => {
  try {
    const { target, profile, timing, customOptions, isPublicTargetConfirmed } = req.body;

    if (!target || typeof target !== 'string' || target.trim().length === 0) {
      return res.status(400).json({ error: 'Target IP, CIDR, or hostname is required.' });
    }

    const validProfiles = ['quick', 'standard', 'comprehensive', 'stealth', 'udp focus', 'custom'];
    const chosenProfile = (profile || 'standard').toLowerCase();
    if (!validProfiles.includes(chosenProfile)) {
      return res.status(400).json({ error: `Invalid scan profile: ${profile}` });
    }

    const result = await scanManager.createScan({
      target: target.trim(),
      profile: profile || 'Standard',
      timing: timing || 'T3',
      customOptions,
      isPublicTargetConfirmed: Boolean(isPublicTargetConfirmed),
    });

    if (result.error) {
      return res.status(400).json({ error: result.error });
    }

    return res.status(201).json({
      scanId: result.job?.id,
      status: result.job?.status,
      commandDisplay: result.job?.commandDisplay,
      createdAt: result.job?.createdAt,
    });
  } catch (err: any) {
    console.error('Error creating scan:', err);
    return res.status(500).json({ error: err?.message || 'Failed to initiate scan' });
  }
});

/**
 * GET /api/scans/:id
 * Retrieves current scan status and progress
 */
scansRouter.get('/:id', async (req: Request, res: Response) => {
  try {
    const job = await scanManager.getScan(req.params.id);
    if (!job) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    return res.json({
      scanId: job.id,
      status: job.status,
      createdAt: job.createdAt,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
      commandDisplay: job.commandDisplay,
      target: job.targetRaw,
      profile: job.profile,
      timing: job.timing,
      summary: job.summary,
      hasResults: Boolean(job.results),
      logsCount: job.logs.length,
      errorMessage: job.errorMessage,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/scans/:id/results
 * Returns the normalized results payload with provenance data
 */
scansRouter.get('/:id/results', async (req: Request, res: Response) => {
  try {
    const job = await scanManager.getScan(req.params.id);
    if (!job) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    if (!job.results && job.status === 'running') {
      return res.status(202).json({ status: 'running', message: 'Scan in progress' });
    }

    if (!job.results) {
      return res.status(404).json({ error: 'Scan has no results yet or ended without results', status: job.status });
    }

    return res.json(job.results);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/scans/:id/stream
 * Server-Sent Events (SSE) stream for real-time terminal stdout/stderr lines
 */
scansRouter.get('/:id/stream', async (req: Request, res: Response) => {
  try {
    const scanId = req.params.id;
    scanManager.subscribeSse(scanId, res);
  } catch (err: any) {
    res.status(500).end();
  }
});

/**
 * POST /api/scans/:id/cancel
 * Cancels an active or queued scan
 */
scansRouter.post('/:id/cancel', async (req: Request, res: Response) => {
  try {
    const scanId = req.params.id;
    const success = await scanManager.cancelScan(scanId);

    if (success) {
      return res.json({ status: 'cancelled', message: `Scan ${scanId} cancellation requested.` });
    } else {
      return res.status(404).json({ error: 'Active scan not found or already terminated' });
    }
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
