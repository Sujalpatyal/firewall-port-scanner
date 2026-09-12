import { Router, Request, Response } from 'express';
import { scanManager } from '../scanManager';

export const compareRouter = Router();

/**
 * POST /api/compare
 * Body: { scanAId: string, scanBId: string }
 */
compareRouter.post('/', async (req: Request, res: Response) => {
  try {
    const { scanAId, scanBId } = req.body;

    if (!scanAId || !scanBId) {
      return res.status(400).json({ error: 'Both scanAId and scanBId are required for comparison' });
    }

    const comparison = await scanManager.compareScans(scanAId, scanBId);

    if (!comparison) {
      return res.status(404).json({ error: 'One or both scans could not be found or have no completed results.' });
    }

    return res.json(comparison);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
