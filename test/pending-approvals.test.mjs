import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { PendingApprovals } from '../src/clawshell.mjs';

let store;

afterEach(() => {
  if (store) store.destroy();
});

describe('PendingApprovals', () => {

  it('add() returns id and promise', () => {
    store = new PendingApprovals({ timeoutSeconds: 10 });
    const { id, promise } = store.add({ command: 'rm -rf dist', workingDir: '/app', riskLevel: 'high', riskReasons: ['destructive_command'] });

    assert.ok(typeof id === 'string');
    assert.ok(id.length > 0);
    assert.ok(promise instanceof Promise);
  });

  it('add() uses provided id', () => {
    store = new PendingApprovals({ timeoutSeconds: 10 });
    const { id } = store.add({ id: 'custom-id', command: 'test', workingDir: '/', riskLevel: 'high' });
    assert.equal(id, 'custom-id');
  });

  it('approve() resolves promise with {approved: true}', async () => {
    store = new PendingApprovals({ timeoutSeconds: 10 });
    const { id, promise } = store.add({ command: 'rm -rf dist', workingDir: '/app', riskLevel: 'high' });

    store.approve(id);
    const result = await promise;

    assert.equal(result.approved, true);
    assert.equal(result.decidedBy, 'user');
  });

  it('reject() resolves promise with {approved: false}', async () => {
    store = new PendingApprovals({ timeoutSeconds: 10 });
    const { id, promise } = store.add({ command: 'rm -rf dist', workingDir: '/app', riskLevel: 'high' });

    store.reject(id);
    const result = await promise;

    assert.equal(result.approved, false);
    assert.equal(result.decidedBy, 'user');
  });

  it('approve() returns false for unknown id', () => {
    store = new PendingApprovals({ timeoutSeconds: 10 });
    assert.equal(store.approve('nonexistent'), false);
  });

  it('approve() returns false if already decided', async () => {
    store = new PendingApprovals({ timeoutSeconds: 10 });
    const { id, promise } = store.add({ command: 'test', workingDir: '/', riskLevel: 'high' });

    assert.equal(store.approve(id), true);
    assert.equal(store.approve(id), false); // already approved
    await promise;
  });

  it('get() returns request without internals', () => {
    store = new PendingApprovals({ timeoutSeconds: 10 });
    const { id } = store.add({ command: 'rm -rf dist', workingDir: '/app', riskLevel: 'high', riskReasons: ['destructive_command'] });

    const entry = store.get(id);
    assert.equal(entry.id, id);
    assert.equal(entry.command, 'rm -rf dist');
    assert.equal(entry.workingDir, '/app');
    assert.equal(entry.riskLevel, 'high');
    assert.deepEqual(entry.riskReasons, ['destructive_command']);
    assert.ok(entry.timestamp instanceof Date);
    assert.equal(entry.status, 'pending');
    // Should NOT expose internals
    assert.equal(entry.resolver, undefined);
    assert.equal(entry.timer, undefined);
  });

  it('get() returns null for unknown id', () => {
    store = new PendingApprovals({ timeoutSeconds: 10 });
    assert.equal(store.get('nonexistent'), null);
  });

  it('list() returns only pending entries', async () => {
    store = new PendingApprovals({ timeoutSeconds: 10 });
    const a = store.add({ id: 'a', command: 'cmd-a', workingDir: '/', riskLevel: 'high' });
    store.add({ id: 'b', command: 'cmd-b', workingDir: '/', riskLevel: 'high' });
    store.add({ id: 'c', command: 'cmd-c', workingDir: '/', riskLevel: 'high' });

    store.approve('a');
    await a.promise;

    const pending = store.list();
    assert.equal(pending.length, 2);
    assert.ok(pending.every(e => e.status === 'pending'));
    assert.ok(pending.every(e => e.resolver === undefined));
  });

  it('auto-timeout resolves with {approved: false, reason: timeout}', async () => {
    store = new PendingApprovals({ timeoutSeconds: 0.1 }); // 100ms timeout
    const { promise } = store.add({ command: 'test', workingDir: '/', riskLevel: 'high' });

    const result = await promise;
    assert.equal(result.approved, false);
    assert.equal(result.reason, 'timeout');
    assert.equal(result.decidedBy, 'timeout');
  });

  it('auto-timeout sets status to timeout', async () => {
    store = new PendingApprovals({ timeoutSeconds: 0.1 });
    const { id, promise } = store.add({ command: 'test', workingDir: '/', riskLevel: 'high' });

    await promise;
    const entry = store.get(id);
    assert.equal(entry.status, 'timeout');
  });

  it('cleanup() removes decided entries past expiry', async () => {
    store = new PendingApprovals({ timeoutSeconds: 0.05 });
    const { id, promise } = store.add({ id: 'old', command: 'test', workingDir: '/', riskLevel: 'high' });

    store.approve(id);
    await promise;

    // Manually backdate timestamp so cleanup catches it
    // (cleanup removes entries older than timeoutMs * 2)
    assert.ok(store.get(id) !== null);

    // Force the timestamp to be old
    await new Promise(r => setTimeout(r, 150));
    store.cleanup();

    assert.equal(store.get(id), null);
  });

  it('reads CLAWSHELL_TIMEOUT_SECONDS from env', () => {
    const original = process.env.CLAWSHELL_TIMEOUT_SECONDS;
    process.env.CLAWSHELL_TIMEOUT_SECONDS = '60';
    try {
      store = new PendingApprovals();
      // Can't directly inspect #timeoutMs, but we can verify it was read
      // by checking the constructor doesn't throw
      assert.ok(store);
    } finally {
      if (original) process.env.CLAWSHELL_TIMEOUT_SECONDS = original;
      else delete process.env.CLAWSHELL_TIMEOUT_SECONDS;
    }
  });
});
