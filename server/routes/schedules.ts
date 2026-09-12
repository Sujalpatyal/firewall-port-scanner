import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { dbListSchedules, dbSaveSchedule, dbDeleteSchedule } from '../database';
import { validateTargets } from '../targetValidator';

export const schedulesRouter = Router();

/**
 * GET /api/schedules
 */
schedulesRouter.get('/', async (_req: Request, res: Response) => {
  try {
    const schedules = await dbListSchedules();
    return res.json({ schedules });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/schedules
 */
schedulesRouter.post('/', async (req: Request, res: Response) => {
  try {
    const { target, profile, timing, cronExpression, enabled } = req.body;

    if (!target || !cronExpression) {
      return res.status(400).json({ error: 'Target and cronExpression are required' });
    }

    const validation = validateTargets(target);
    if (!validation.isValid) {
      return res.status(400).json({ error: validation.error });
    }

    // Safety rule from prompt: Do not automatically scan arbitrary public networks
    if (validation.hasExternalTarget) {
      return res.status(400).json({
        error: 'Automated recurring schedules are restricted to private/internal networks (RFC 1918 / loopback) for safety policy compliance.',
      });
    }

    const item = {
      id: `sched_${uuidv4().substring(0, 8)}`,
      target,
      profile: profile || 'Standard',
      timing: timing || 'T3',
      cronExpression,
      enabled: enabled !== false,
      createdAt: new Date().toISOString(),
      nextRunAt: new Date(Date.now() + 86400000).toISOString(),
    };

    await dbSaveSchedule(item);
    return res.status(201).json({ schedule: item });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/schedules/:id
 */
schedulesRouter.delete('/:id', async (req: Request, res: Response) => {
  try {
    await dbDeleteSchedule(req.params.id);
    return res.json({ success: true, id: req.params.id });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
