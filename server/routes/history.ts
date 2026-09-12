import { Router, Request, Response } from 'express';
import { dbListScans, dbGetScan, dbDeleteScan } from '../database';

export const historyRouter = Router();

/**
 * GET /api/history
 * Returns recent scans
 */
historyRouter.get('/', async (req: Request, res: Response) => {
  try {
    const limit = parseInt((req.query.limit as string) || '50', 10);
    const scans = await dbListScans(limit);
    return res.json({ scans });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/history/:id
 * Returns full scan record including results
 */
historyRouter.get('/:id', async (req: Request, res: Response) => {
  try {
    const scan = await dbGetScan(req.params.id);
    if (!scan) {
      return res.status(404).json({ error: 'Historical scan not found' });
    }
    return res.json(scan);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/history/:id
 * Removes a scan record from history
 */
historyRouter.delete('/:id', async (req: Request, res: Response) => {
  try {
    const success = await dbDeleteScan(req.params.id);
    return res.json({ success, id: req.params.id });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
