import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Logger } from '../src/logger.mjs';

const TEST_LOG_DIR = join(process.cwd(), 'test-logs-' + process.pid);

function makeLogger(opts = {}) {
  return new Logger({ logDir: TEST_LOG_DIR, ...opts });
}

function cleanup() {
  if (existsSync(TEST_LOG_DIR)) {
    rmSync(TEST_LOG_DIR, { recursive: true, force: true });
  }
}

beforeEach(cleanup);
afterEach(cleanup);

describe('Logger', () => {

  it('creates log directory if missing', () => {
    makeLogger();
    assert.ok(existsSync(TEST_LOG_DIR));
  });

  it('writes JSONL entries with timestamp', () => {
    const logger = makeLogger();
    const record = logger.log({
      request_id: 'abc123',
      tool: 'bash',
      command: 'rm -rf /',
      working_dir: '/app/workspace',
      risk_level: 'critical',
      risk_reasons: ['destructive_root_delete'],
      decision: 'auto-blocked',
      decided_by: 'auto',
      latency_ms: 3,
    });

    assert.ok(record.timestamp, 'should have ISO timestamp');
    assert.equal(record.request_id, 'abc123');
    assert.equal(record.risk_level, 'critical');
    assert.deepEqual(record.risk_reasons, ['destructive_root_delete']);
    assert.equal(record.decision, 'auto-blocked');
    assert.equal(record.decided_by, 'auto');
    assert.equal(record.latency_ms, 3);
  });

  it('getRecent returns last N entries', () => {
    const logger = makeLogger();
    for (let i = 0; i < 30; i++) {
      logger.log({ request_id: `req-${i}`, command: `cmd-${i}` });
    }

    const recent = logger.getRecent(5);
    assert.equal(recent.length, 5);
    assert.equal(recent[0].request_id, 'req-25');
    assert.equal(recent[4].request_id, 'req-29');
  });

  it('getRecent defaults to 20', () => {
    const logger = makeLogger();
    for (let i = 0; i < 30; i++) {
      logger.log({ request_id: `req-${i}` });
    }

    const recent = logger.getRecent();
    assert.equal(recent.length, 20);
  });

  it('getRecent returns [] for empty/missing log', () => {
    const logger = makeLogger();
    assert.deepEqual(logger.getRecent(), []);
  });

  it('search filters by risk_level', () => {
    const logger = makeLogger();
    logger.log({ risk_level: 'high', command: 'a' });
    logger.log({ risk_level: 'low', command: 'b' });
    logger.log({ risk_level: 'high', command: 'c' });

    const results = logger.search({ risk_level: 'high' });
    assert.equal(results.length, 2);
    assert.ok(results.every(r => r.risk_level === 'high'));
  });

  it('search filters by decision', () => {
    const logger = makeLogger();
    logger.log({ decision: 'approved', command: 'a' });
    logger.log({ decision: 'auto-blocked', command: 'b' });
    logger.log({ decision: 'approved', command: 'c' });

    const results = logger.search({ decision: 'auto-blocked' });
    assert.equal(results.length, 1);
    assert.equal(results[0].command, 'b');
  });

  it('search filters by date range', () => {
    const logger = makeLogger();

    // Write entries with known timestamps
    const logPath = logger.logPath;
    const entries = [
      { timestamp: '2025-01-01T00:00:00Z', command: 'old' },
      { timestamp: '2025-06-15T00:00:00Z', command: 'mid' },
      { timestamp: '2025-12-31T00:00:00Z', command: 'new' },
    ];
    writeFileSync(logPath, entries.map(e => JSON.stringify(e)).join('\n') + '\n');

    const results = logger.search({ from: '2025-03-01', to: '2025-09-01' });
    assert.equal(results.length, 1);
    assert.equal(results[0].command, 'mid');
  });

  it('search with no filter returns all', () => {
    const logger = makeLogger();
    logger.log({ command: 'a' });
    logger.log({ command: 'b' });

    const results = logger.search();
    assert.equal(results.length, 2);
  });

  it('logPath points to clawshell.jsonl', () => {
    const logger = makeLogger();
    assert.ok(logger.logPath.endsWith('clawshell.jsonl'));
  });

  it('reads CLAWSHELL_LOG_DIR from env', () => {
    const original = process.env.CLAWSHELL_LOG_DIR;
    process.env.CLAWSHELL_LOG_DIR = TEST_LOG_DIR;
    try {
      const logger = new Logger();
      assert.ok(logger.logPath.startsWith(TEST_LOG_DIR));
    } finally {
      if (original) process.env.CLAWSHELL_LOG_DIR = original;
      else delete process.env.CLAWSHELL_LOG_DIR;
    }
  });
});
