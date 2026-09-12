import initSqlJs, { Database } from 'sql.js';
import fs from 'fs';
import path from 'path';
import { ScanJob, ScanResultPayload, ScheduleItem } from './types';

export interface ScanHistoryItem {
  id: string;
  target: string;
  profile: string;
  timing: string;
  status: string;
  createdAt: string;
  completedAt?: string;
  command: string;
  openPorts: number;
  hostsUp: number;
  elapsedSeconds: number;
}

let dbInstance: Database | null = null;
const DATA_DIR = path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'scans.sqlite');

/**
 * Initializes the SQLite database via sql.js with on-disk persistence
 */
export async function initDatabase(): Promise<Database> {
  if (dbInstance) return dbInstance;

  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  } catch (err) {
    console.error('Error creating data directory for sqlite:', err);
  }

  const SQL = await initSqlJs();

  if (fs.existsSync(DB_FILE)) {
    try {
      const fileBuffer = fs.readFileSync(DB_FILE);
      dbInstance = new SQL.Database(fileBuffer);
    } catch (err) {
      console.warn('Failed to load existing SQLite file, creating fresh database:', err);
      dbInstance = new SQL.Database();
    }
  } else {
    dbInstance = new SQL.Database();
  }

  // Create tables with parameterized statements
  dbInstance.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      target TEXT NOT NULL,
      profile TEXT NOT NULL,
      timing TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      started_at TEXT,
      completed_at TEXT,
      command TEXT,
      summary_json TEXT,
      results_json TEXT,
      raw_logs TEXT
    );

    CREATE TABLE IF NOT EXISTS schedules (
      id TEXT PRIMARY KEY,
      target TEXT NOT NULL,
      profile TEXT NOT NULL,
      timing TEXT NOT NULL,
      cron_expression TEXT NOT NULL,
      enabled INTEGER DEFAULT 1,
      last_run_at TEXT,
      next_run_at TEXT,
      created_at TEXT NOT NULL
    );
  `);

  persistDatabase();
  return dbInstance;
}

/**
 * Writes current SQLite in-memory state to disk safely
 */
function persistDatabase(): void {
  if (!dbInstance) return;
  try {
    const data = dbInstance.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_FILE, buffer);
  } catch (err) {
    console.error('Failed to persist SQLite database to disk:', err);
  }
}

/**
 * Saves or updates a scan job record in the database
 */
export async function dbSaveScan(job: ScanJob): Promise<void> {
  const db = await initDatabase();

  const summaryJson = job.summary ? JSON.stringify(job.summary) : (job.results?.summary ? JSON.stringify(job.results.summary) : null);
  const resultsJson = job.results ? JSON.stringify(job.results) : null;
  const rawLogs = job.logs.slice(-200).join('\n');

  const stmt = db.prepare(`
    INSERT OR REPLACE INTO scans (
      id, target, profile, timing, status, created_at, started_at, completed_at, command, summary_json, results_json, raw_logs
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run([
    job.id,
    job.targetRaw,
    job.profile,
    job.timing,
    job.status,
    job.createdAt,
    job.startedAt || null,
    job.completedAt || null,
    job.commandDisplay,
    summaryJson,
    resultsJson,
    rawLogs,
  ]);

  stmt.free();
  persistDatabase();
}

/**
 * Retrieves a single scan by ID
 */
export async function dbGetScan(scanId: string): Promise<ScanJob | null> {
  const db = await initDatabase();
  const stmt = db.prepare('SELECT * FROM scans WHERE id = ?');
  stmt.bind([scanId]);

  if (!stmt.step()) {
    stmt.free();
    return null;
  }

  const row = stmt.getAsObject();
  stmt.free();

  const summary = row.summary_json ? JSON.parse(row.summary_json as string) : undefined;
  const results = row.results_json ? (JSON.parse(row.results_json as string) as ScanResultPayload) : undefined;
  const logs = row.raw_logs ? (row.raw_logs as string).split('\n') : [];

  return {
    id: row.id as string,
    targetRaw: row.target as string,
    validatedTargets: [row.target as string],
    isPublicTargetConfirmed: true,
    profile: row.profile as string,
    timing: row.timing as string,
    status: row.status as any,
    createdAt: row.created_at as string,
    startedAt: (row.started_at as string) || undefined,
    completedAt: (row.completed_at as string) || undefined,
    commandDisplay: (row.command as string) || '',
    nmapArgs: [],
    logs,
    summary,
    results,
  };
}

/**
 * Lists scans for the scan history view
 */
export async function dbListScans(limit: number = 50): Promise<ScanHistoryItem[]> {
  const db = await initDatabase();
  const stmt = db.prepare(`
    SELECT id, target, profile, timing, status, created_at, completed_at, command, summary_json
    FROM scans
    ORDER BY created_at DESC
    LIMIT ?
  `);

  stmt.bind([limit]);
  const results: ScanHistoryItem[] = [];

  while (stmt.step()) {
    const row = stmt.getAsObject();
    let openPorts = 0;
    let hostsUp = 0;
    let elapsedSeconds = 0;

    if (row.summary_json) {
      try {
        const sum = JSON.parse(row.summary_json as string);
        openPorts = sum.openPorts || 0;
        hostsUp = sum.hostsUp || 0;
        elapsedSeconds = sum.elapsedSeconds || 0;
      } catch {}
    }

    results.push({
      id: row.id as string,
      target: row.target as string,
      profile: row.profile as string,
      timing: row.timing as string,
      status: row.status as string,
      createdAt: row.created_at as string,
      completedAt: (row.completed_at as string) || undefined,
      command: (row.command as string) || '',
      openPorts,
      hostsUp,
      elapsedSeconds,
    });
  }

  stmt.free();
  return results;
}

/**
 * Deletes a scan from history
 */
export async function dbDeleteScan(scanId: string): Promise<boolean> {
  const db = await initDatabase();
  const stmt = db.prepare('DELETE FROM scans WHERE id = ?');
  stmt.run([scanId]);
  stmt.free();
  persistDatabase();
  return true;
}

/**
 * Schedules management
 */
export async function dbListSchedules(): Promise<ScheduleItem[]> {
  const db = await initDatabase();
  const stmt = db.prepare('SELECT * FROM schedules ORDER BY created_at DESC');
  const items: ScheduleItem[] = [];

  while (stmt.step()) {
    const row = stmt.getAsObject();
    items.push({
      id: row.id as string,
      target: row.target as string,
      profile: row.profile as string,
      timing: row.timing as string,
      cronExpression: row.cron_expression as string,
      enabled: row.enabled === 1,
      lastRunAt: (row.last_run_at as string) || undefined,
      nextRunAt: (row.next_run_at as string) || undefined,
      createdAt: row.created_at as string,
    });
  }

  stmt.free();
  return items;
}

export async function dbSaveSchedule(item: ScheduleItem): Promise<void> {
  const db = await initDatabase();
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO schedules (
      id, target, profile, timing, cron_expression, enabled, last_run_at, next_run_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run([
    item.id,
    item.target,
    item.profile,
    item.timing,
    item.cronExpression,
    item.enabled ? 1 : 0,
    item.lastRunAt || null,
    item.nextRunAt || null,
    item.createdAt,
  ]);

  stmt.free();
  persistDatabase();
}

export async function dbDeleteSchedule(id: string): Promise<boolean> {
  const db = await initDatabase();
  const stmt = db.prepare('DELETE FROM schedules WHERE id = ?');
  stmt.run([id]);
  stmt.free();
  persistDatabase();
  return true;
}
