import { Router, Request, Response } from 'express';
import { lookupVulnerabilities } from '../vulnerabilityService';

export const vulnerabilitiesRouter = Router();

/**
 * GET /api/vulnerabilities?product=OpenSSH&version=8.9p1
 */
vulnerabilitiesRouter.get('/', async (req: Request, res: Response) => {
  try {
    const product = req.query.product as string;
    const version = req.query.version as string;

    const data = await lookupVulnerabilities(product, version);
    return res.json(data);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
