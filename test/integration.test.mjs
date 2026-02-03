import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { clawshell_bash, clawshell_status, clawshell_logs, pending } from '../src/clawshell.mjs';
import { getNotifier } from '../src/notifier.mjs';

const SKIP = !process.env.CLAWSHELL_TEST_REAL_NOTIFICATIONS;
const PUSHOVER_OK = !!(process.env.CLAWSHELL_PUSHOVER_USER && process.env.CLAWSHELL_PUSHOVER_TOKEN);

describe('Integration: Pushover approval flow', { skip: SKIP || !PUSHOVER_OK }, () => {
  const APPROVAL_TIMEOUT_MS = 60_000;

  it('sends notification for high-risk command and waits for decision', async () => {
    console.log('\n--- INTEGRATION TEST ---');
    console.log('A Pushover notification will be sent for: rm -rf ./integration-test');
    console.log(`You have ${APPROVAL_TIMEOUT_MS / 1000}s to APPROVE or REJECT on your phone.`);
    console.log('Acknowledge the notification to APPROVE, or let it expire to REJECT.\n');

    const startTime = Date.now();

    // Run a high-risk command — this will send a real notification and block
    const resultPromise = clawshell_bash('rm -rf ./integration-test', '/app/workspace');

    // Give the notification a moment to be sent
    await sleep(2000);

    // Check that a pending approval exists
    const statusOutput = clawshell_status();
    console.log('Status while waiting:\n', statusOutput);
    assert.ok(statusOutput.includes('Pending approvals'), 'Should have pending approvals');
    assert.ok(statusOutput.includes('rm -rf ./integration-test'), 'Should show the command');

    // Wait for the actual decision (user approves/rejects on phone, or timeout)
    const result = await Promise.race([
      resultPromise,
      sleep(APPROVAL_TIMEOUT_MS).then(() => null),
    ]);

    const elapsed = Date.now() - startTime;
    console.log(`\nDecision received in ${(elapsed / 1000).toFixed(1)}s`);
    console.log('Result:', JSON.stringify(result, null, 2));

    // Verify we got a result (not timed out at test level)
    assert.ok(result !== null, 'Should have received a decision before test timeout');
    assert.ok(typeof result.exitCode === 'number', 'Should have exitCode');
    assert.ok(typeof result.stdout === 'string', 'Should have stdout');
    assert.ok(typeof result.stderr === 'string', 'Should have stderr');

    // Check logs were written
    const logs = clawshell_logs(5);
    console.log('\nRecent logs:\n', logs);
    assert.ok(logs.includes('rm -rf ./integration-test'), 'Logs should contain the command');
    assert.ok(logs.includes('HIGH'), 'Logs should show HIGH risk level');

    if (result.exitCode === 0) {
      console.log('Command was APPROVED and executed (or would have been).');
      assert.ok(!result.stderr.includes('REJECTED'), 'Should not contain rejection message');
    } else {
      console.log('Command was REJECTED or timed out.');
      assert.ok(result.stderr.includes('REJECTED') || result.stderr.includes('BLOCKED'),
        'stderr should indicate rejection');
    }
  });
});

describe('Integration: low-risk command executes directly', () => {
  it('echo command runs without notification', async () => {
    const result = await clawshell_bash('echo hello-integration', '/app/workspace');

    assert.equal(result.exitCode, 0);
    assert.ok(result.stdout.includes('hello-integration'), 'Should see echo output');
    assert.equal(result.stderr, '');
  });
});

describe('Integration: critical command is blocked', () => {
  it('rm -rf / is auto-blocked', async () => {
    const result = await clawshell_bash('rm -rf /', '/app/workspace');

    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes('BLOCKED'), 'Should be blocked');
    assert.equal(result.stdout, '');
  });
});

describe('Integration: clawshell_status and clawshell_logs', () => {
  it('status returns formatted string', () => {
    const output = clawshell_status();
    assert.ok(typeof output === 'string');
    assert.ok(output.includes('ClawShell Status'));
  });

  it('logs returns formatted string', () => {
    const output = clawshell_logs(5);
    assert.ok(typeof output === 'string');
  });
});

describe('Integration: Pushover notification send (no polling)', { skip: !PUSHOVER_OK }, () => {
  it('can send a notification directly', async () => {
    const notifier = getNotifier();
    assert.equal(notifier.type, 'pushover');

    const result = await notifier.sendApprovalRequest({
      id: 'integ-test-' + Date.now(),
      command: 'echo integration-test-ping',
      workingDir: '/app/workspace',
      riskLevel: 'high',
      riskReasons: ['integration_test'],
    });

    assert.ok(result.notificationId, 'Should have notificationId');
    assert.ok(result.timestamp, 'Should have timestamp');
    console.log('Pushover notification sent successfully:', result.notificationId);
  });
});

after(() => {
  pending.destroy();
});

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
