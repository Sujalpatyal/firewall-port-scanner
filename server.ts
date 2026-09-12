import express from 'express';
import path from 'path';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { createServer as createViteServer } from 'vite';
import { checkNmapAvailability } from './server/nmapService';
import { scansRouter } from './server/routes/scans';
import { historyRouter } from './server/routes/history';
import { compareRouter } from './server/routes/compare';
import { vulnerabilitiesRouter } from './server/routes/vulnerabilities';
import { schedulesRouter } from './server/routes/schedules';
import { scanManager } from './server/scanManager';
import { initDatabase } from './server/database';

async function startServer() {
  const app = express();
  const PORT = parseInt(process.env.PORT || '3000', 10);

  // Initialize SQLite database
  await initDatabase();

  // Security Middleware
  app.use(
    helmet({
      contentSecurityPolicy: false, // Allow Vite scripts, fonts, and inline styles in dev
      crossOriginEmbedderPolicy: false,
    })
  );

  app.use(cors());
  app.use(express.json({ limit: '5mb' }));

  // Global Rate Limiting
  const globalLimit = parseInt(process.env.GLOBAL_RATE_LIMIT || '60', 10);
  const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: globalLimit * 6, // 60 requests per minute
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Rate limit exceeded. Please wait before issuing further scan requests.' },
  });
  app.use('/api/', limiter);

  // Health endpoint
  app.get('/health', async (_req, res) => {
    const nmapStatus = await checkNmapAvailability();
    const queueStatus = scanManager.getQueueStatus();

    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      nmap: {
        available: nmapStatus.available,
        version: nmapStatus.version,
        hasRawSocketPrivilege: nmapStatus.hasRawSocketPrivilege,
        error: nmapStatus.error,
      },
      queue: queueStatus,
      environment: {
        nodeVersion: process.version,
        nodeEnv: process.env.NODE_ENV || 'development',
      },
    });
  });

  // API Routes
  app.use('/api/scans', scansRouter);
  app.use('/api/history', historyRouter);
  app.use('/api/compare', compareRouter);
  app.use('/api/vulnerabilities', vulnerabilitiesRouter);
  app.use('/api/schedules', schedulesRouter);

  // Startup verification of Nmap
  const nmapCheck = await checkNmapAvailability();
  if (nmapCheck.available) {
    console.log(`[STARTUP] Nmap binary verified: ${nmapCheck.version}`);
    console.log(`[STARTUP] Raw socket privilege (root): ${nmapCheck.hasRawSocketPrivilege ? 'YES' : 'NO (fallback safe mode enabled)'}`);
  } else {
    console.warn(`[STARTUP] WARNING: Nmap is not detected in system PATH (${nmapCheck.error})`);
  }

  // Vite Middleware for development vs static build for production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Firewall Port Status Checker running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
