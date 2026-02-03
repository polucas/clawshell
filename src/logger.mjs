import { appendFileSync, readFileSync, renameSync, statSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_ROTATIONS = 5;

export class Logger {
  #logPath;
  #level;
  #levels = { debug: 0, info: 1, warn: 2, error: 3 };

  constructor(opts = {}) {
    const logDir = process.env.CLAWSHELL_LOG_DIR || opts.logDir || join(process.cwd(), 'logs');
    this.#logPath = join(logDir, 'clawshell.jsonl');
    this.#level = process.env.CLAWSHELL_LOG_LEVEL || opts.level || 'info';

    if (!existsSync(logDir)) {
      mkdirSync(logDir, { recursive: true });
    }
  }

  get logPath() {
    return this.#logPath;
  }

  log(entry) {
    if (this.#levels[entry.risk_level] === undefined && entry.risk_level) {
      // risk_level isn't a log level, always log
    }

    const record = {
      timestamp: new Date().toISOString(),
      ...entry,
    };

    this.#rotateIfNeeded();
    appendFileSync(this.#logPath, JSON.stringify(record) + '\n', 'utf-8');
    return record;
  }

  info(message, data = {}) {
    if (this.#levels[this.#level] > this.#levels.info) return;
    return this.log({ level: 'info', message, ...data });
  }

  warn(message, data = {}) {
    if (this.#levels[this.#level] > this.#levels.warn) return;
    return this.log({ level: 'warn', message, ...data });
  }

  error(message, data = {}) {
    return this.log({ level: 'error', message, ...data });
  }

  debug(message, data = {}) {
    if (this.#levels[this.#level] > this.#levels.debug) return;
    return this.log({ level: 'debug', message, ...data });
  }

  getRecent(count = 20) {
    if (!existsSync(this.#logPath)) return [];

    const content = readFileSync(this.#logPath, 'utf-8').trim();
    if (!content) return [];

    const lines = content.split('\n');
    const recent = lines.slice(-count);

    return recent.map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    }).filter(Boolean);
  }

  search(filter = {}) {
    const entries = this.getRecent(1000);

    return entries.filter((entry) => {
      if (filter.risk_level && entry.risk_level !== filter.risk_level) return false;
      if (filter.decision && entry.decision !== filter.decision) return false;
      if (filter.from && new Date(entry.timestamp) < new Date(filter.from)) return false;
      if (filter.to && new Date(entry.timestamp) > new Date(filter.to)) return false;
      return true;
    });
  }

  #rotateIfNeeded() {
    if (!existsSync(this.#logPath)) return;

    try {
      const stats = statSync(this.#logPath);
      if (stats.size < MAX_FILE_SIZE) return;
    } catch {
      return;
    }

    // Shift existing rotations
    for (let i = MAX_ROTATIONS - 1; i >= 1; i--) {
      const from = `${this.#logPath}.${i}`;
      const to = `${this.#logPath}.${i + 1}`;
      if (existsSync(from)) {
        try { renameSync(from, to); } catch { /* ignore */ }
      }
    }

    try {
      renameSync(this.#logPath, `${this.#logPath}.1`);
    } catch { /* ignore */ }
  }
}

// Singleton for convenience
let _defaultLogger;
export function getLogger(opts) {
  if (!_defaultLogger) {
    _defaultLogger = new Logger(opts);
  }
  return _defaultLogger;
}
