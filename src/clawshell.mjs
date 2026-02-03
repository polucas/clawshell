import { exec } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { RiskAnalyzer } from './risk-analyzer.mjs';
import { getNotifier } from './notifier.mjs';
import { getLogger } from './logger.mjs';

// --- Pending Approvals Store ---

export class PendingApprovals {
  #store = new Map();
  #timeoutMs;
  #cleanupInterval;

  constructor(opts = {}) {
    this.#timeoutMs = (
      parseInt(process.env.CLAWSHELL_TIMEOUT_SECONDS, 10) || opts.timeoutSeconds || 300
    ) * 1000;

    // Periodic cleanup every 60s
    this.#cleanupInterval = setInterval(() => this.cleanup(), 60_000);
    this.#cleanupInterval.unref(); // Don't keep process alive
  }

  add(request) {
    const id = request.id || randomUUID().slice(0, 8);
    let resolver;
    let timer;

    const promise = new Promise((resolve) => {
      resolver = resolve;

      // Auto-timeout
      timer = setTimeout(() => {
        if (this.#store.has(id) && this.#store.get(id).status === 'pending') {
          this.#store.get(id).status = 'timeout';
          resolve({ approved: false, reason: 'timeout', decidedBy: 'timeout' });
        }
      }, this.#timeoutMs);
      timer.unref();
    });

    this.#store.set(id, {
      id,
      command: request.command,
      workingDir: request.workingDir,
      riskLevel: request.riskLevel,
      riskReasons: request.riskReasons || [],
      timestamp: new Date(),
      status: 'pending',
      resolver,
      timer,
    });

    return { id, promise };
  }

  approve(id) {
    const entry = this.#store.get(id);
    if (!entry || entry.status !== 'pending') return false;

    entry.status = 'approved';
    clearTimeout(entry.timer);
    entry.resolver({ approved: true, decidedBy: 'user' });
    return true;
  }

  reject(id) {
    const entry = this.#store.get(id);
    if (!entry || entry.status !== 'pending') return false;

    entry.status = 'rejected';
    clearTimeout(entry.timer);
    entry.resolver({ approved: false, decidedBy: 'user' });
    return true;
  }

  get(id) {
    const entry = this.#store.get(id);
    if (!entry) return null;
    // Return a copy without internals
    const { resolver, timer, ...rest } = entry;
    return rest;
  }

  list() {
    const results = [];
    for (const [, entry] of this.#store) {
      if (entry.status === 'pending') {
        const { resolver, timer, ...rest } = entry;
        results.push(rest);
      }
    }
    return results;
  }

  cleanup() {
    const now = Date.now();
    for (const [id, entry] of this.#store) {
      if (entry.status !== 'pending' && (now - entry.timestamp.getTime()) > this.#timeoutMs * 2) {
        this.#store.delete(id);
      }
    }
  }

  destroy() {
    clearInterval(this.#cleanupInterval);
    for (const [, entry] of this.#store) {
      clearTimeout(entry.timer);
    }
    this.#store.clear();
  }
}

// --- Shared instances ---

const analyzer = new RiskAnalyzer();
const logger = getLogger();
const pending = new PendingApprovals();
let notifier;

function getNotifierInstance() {
  if (!notifier) {
    notifier = getNotifier();
  }
  return notifier;
}

// --- Tool: clawshell_bash ---

export async function clawshell_bash(command, workingDir = process.cwd()) {
  const startTime = Date.now();
  const analysis = analyzer.analyzeCommand(command, workingDir);
  const requestId = randomUUID().slice(0, 8);

  // CRITICAL: auto-block
  if (analysis.level === 'critical') {
    const entry = {
      request_id: requestId,
      tool: 'bash',
      command,
      working_dir: workingDir,
      risk_level: 'critical',
      risk_reasons: analysis.reasons,
      decision: 'auto-blocked',
      decided_by: 'auto',
      latency_ms: Date.now() - startTime,
    };
    logger.log(entry);

    return {
      exitCode: 1,
      stdout: '',
      stderr: `BLOCKED by ClawShell: ${analysis.reasons.join(', ')}. This command was classified as critical risk and automatically rejected.`,
    };
  }

  // HIGH: require approval
  if (analysis.level === 'high') {
    const { id, promise } = pending.add({
      id: requestId,
      command,
      workingDir,
      riskLevel: 'high',
      riskReasons: analysis.reasons,
    });

    // Send notification
    try {
      const notification = await getNotifierInstance().sendApprovalRequest({
        id,
        command,
        workingDir,
        riskLevel: 'high',
        riskReasons: analysis.reasons,
      });

      // If we got a receipt, start background polling that resolves the pending approval
      if (notification.receipt) {
        getNotifierInstance().pollForResponse(notification.receipt).then((result) => {
          if (result.approved) {
            pending.approve(id);
          } else {
            pending.reject(id);
          }
        }).catch(() => {
          // Polling failed; timeout will handle it
        });
      }
    } catch (err) {
      logger.warn('Notification send failed', { error: err.message, request_id: id });
    }

    // Wait for decision
    const decision = await promise;

    const entry = {
      request_id: id,
      tool: 'bash',
      command,
      working_dir: workingDir,
      risk_level: 'high',
      risk_reasons: analysis.reasons,
      decision: decision.approved ? 'approved' : 'rejected',
      decided_by: decision.decidedBy || 'unknown',
      latency_ms: Date.now() - startTime,
    };
    logger.log(entry);

    if (!decision.approved) {
      const reason = decision.reason || 'rejected by user';
      return {
        exitCode: 1,
        stdout: '',
        stderr: `REJECTED by ClawShell: ${reason}. The command was not executed.`,
      };
    }

    // Approved — fall through to execute
  }

  // MEDIUM: log and allow
  if (analysis.level === 'medium') {
    logger.log({
      request_id: requestId,
      tool: 'bash',
      command,
      working_dir: workingDir,
      risk_level: 'medium',
      risk_reasons: analysis.reasons,
      decision: 'auto-allowed',
      decided_by: 'auto',
      latency_ms: Date.now() - startTime,
    });
  }

  // LOW or approved HIGH or MEDIUM: execute
  return executeCommand(command, workingDir);
}

// --- Tool: clawshell_status ---

export function clawshell_status() {
  const pendingList = pending.list();
  const recentLogs = logger.getRecent(5);

  const lines = ['=== ClawShell Status ===', ''];

  if (pendingList.length === 0) {
    lines.push('No pending approvals.');
  } else {
    lines.push(`Pending approvals (${pendingList.length}):`);
    for (const req of pendingList) {
      const age = Math.round((Date.now() - req.timestamp.getTime()) / 1000);
      const cmdPreview = req.command.length > 60 ? req.command.slice(0, 57) + '...' : req.command;
      lines.push(`  [${req.id}] ${cmdPreview} (${age}s ago, ${req.riskLevel})`);
    }
  }

  lines.push('');
  lines.push('Recent decisions:');
  if (recentLogs.length === 0) {
    lines.push('  No recent activity.');
  } else {
    for (const log of recentLogs) {
      const cmd = (log.command || '').slice(0, 50);
      lines.push(`  ${log.timestamp} | ${log.risk_level?.toUpperCase() || '?'} | ${log.decision || '?'} | ${cmd}`);
    }
  }

  return lines.join('\n');
}

// --- Tool: clawshell_logs ---

export function clawshell_logs(count = 20) {
  const entries = logger.getRecent(count);

  if (entries.length === 0) {
    return 'No log entries found.';
  }

  return entries.map((e) => {
    const cmd = (e.command || e.message || '').slice(0, 80);
    return `${e.timestamp} | ${(e.risk_level || e.level || '').toUpperCase().padEnd(8)} | ${(e.decision || '').padEnd(12)} | ${cmd}`;
  }).join('\n');
}

// --- Tool: clawshell_config ---

export function clawshell_config() {
  const config = {
    enabled: process.env.CLAWSHELL_ENABLED !== 'false',
    timeout_seconds: parseInt(process.env.CLAWSHELL_TIMEOUT_SECONDS, 10) || 300,
    notification_method: process.env.CLAWSHELL_PUSHOVER_USER ? 'pushover' :
      process.env.CLAWSHELL_TELEGRAM_BOT_TOKEN ? 'telegram' : 'mock',
    log_level: process.env.CLAWSHELL_LOG_LEVEL || 'info',
    log_dir: process.env.CLAWSHELL_LOG_DIR || 'logs/',
    blocklist_env: process.env.CLAWSHELL_BLOCKLIST ? 'set' : 'not set',
    allowlist_env: process.env.CLAWSHELL_ALLOWLIST ? 'set' : 'not set',
  };

  return JSON.stringify(config, null, 2);
}

// --- Manual approve/reject (CLI use, not agent tools) ---

export function clawshell_approve(id) {
  const success = pending.approve(id);
  return success ? `Approved request ${id}` : `No pending request found with id ${id}`;
}

export function clawshell_reject(id) {
  const success = pending.reject(id);
  return success ? `Rejected request ${id}` : `No pending request found with id ${id}`;
}

// --- Command execution helper ---

function executeCommand(command, workingDir) {
  return new Promise((resolve) => {
    exec(command, { cwd: workingDir, timeout: 60_000, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
      resolve({
        exitCode: error ? error.code || 1 : 0,
        stdout: stdout || '',
        stderr: stderr || '',
      });
    });
  });
}

// --- Exports for testing ---

export { analyzer, logger, pending };
