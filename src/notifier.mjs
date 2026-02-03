import axios from 'axios';

export class PushoverNotifier {
  #userKey;
  #apiToken;

  constructor(opts = {}) {
    this.#userKey = opts.userKey || process.env.CLAWSHELL_PUSHOVER_USER;
    this.#apiToken = opts.apiToken || process.env.CLAWSHELL_PUSHOVER_TOKEN;

    if (!this.#userKey || !this.#apiToken) {
      throw new Error('Pushover credentials missing. Set CLAWSHELL_PUSHOVER_USER and CLAWSHELL_PUSHOVER_TOKEN.');
    }
  }

  get type() { return 'pushover'; }

  async sendApprovalRequest(request) {
    const { id, command, workingDir, riskLevel, riskReasons } = request;
    const truncatedCmd = command.length > 100 ? command.slice(0, 97) + '...' : command;
    const priority = riskLevel === 'high' ? 1 : 0;

    const message = [
      `Command: ${truncatedCmd}`,
      `Directory: ${workingDir}`,
      `Risk: ${riskLevel.toUpperCase()}`,
      `Reason: ${(riskReasons || []).join(', ')}`,
      '',
      `Request ID: ${id}`,
    ].join('\n');

    const payload = {
      token: this.#apiToken,
      user: this.#userKey,
      title: `CLAWSHELL: ${riskLevel.toUpperCase()}`,
      message,
      priority,
      url: `clawshell://approve/${id}`,
      url_title: 'Approve',
    };

    // Priority 1 requires retry/expire for Pushover receipt polling
    if (priority === 1) {
      payload.retry = 30;
      payload.expire = 300;
    }

    try {
      const response = await axios.post('https://api.pushover.net/1/messages.json', payload);
      return {
        notificationId: response.data.request,
        receipt: response.data.receipt || null,
        timestamp: new Date().toISOString(),
      };
    } catch (err) {
      const msg = err.response?.data?.errors?.join(', ') || err.message;
      throw new Error(`Pushover send failed: ${msg}`);
    }
  }

  async pollForResponse(receipt, timeoutMs = 300_000) {
    if (!receipt) {
      // No receipt means priority 0 — can't poll, wait for timeout
      return this.#waitForManualResponse(timeoutMs);
    }

    const deadline = Date.now() + timeoutMs;
    const pollInterval = 5_000;

    while (Date.now() < deadline) {
      try {
        const res = await axios.get(
          `https://api.pushover.net/1/receipts/${receipt}.json?token=${this.#apiToken}`
        );

        if (res.data.acknowledged === 1) {
          return { approved: true, decidedBy: 'user_pushover' };
        }

        if (res.data.expired === 1) {
          return { approved: false, decidedBy: 'timeout' };
        }
      } catch {
        // Network error — keep trying
      }

      await sleep(pollInterval);
    }

    return { approved: false, decidedBy: 'timeout' };
  }

  #waitForManualResponse(timeoutMs) {
    // For priority 0 messages, we can't poll receipts.
    // The pending-approvals system handles resolution via approve/reject calls.
    return new Promise((resolve) => {
      setTimeout(() => resolve({ approved: false, decidedBy: 'timeout' }), timeoutMs);
    });
  }
}

export class TelegramNotifier {
  #botToken;
  #chatId;

  constructor(opts = {}) {
    this.#botToken = opts.botToken || process.env.CLAWSHELL_TELEGRAM_BOT_TOKEN;
    this.#chatId = opts.chatId || process.env.CLAWSHELL_TELEGRAM_CHAT_ID;

    if (!this.#botToken || !this.#chatId) {
      throw new Error('Telegram credentials missing. Set CLAWSHELL_TELEGRAM_BOT_TOKEN and CLAWSHELL_TELEGRAM_CHAT_ID.');
    }
  }

  get type() { return 'telegram'; }

  async sendApprovalRequest(request) {
    const { id, command, workingDir, riskLevel, riskReasons } = request;
    const truncatedCmd = command.length > 100 ? command.slice(0, 97) + '...' : command;

    const text = [
      `*CLAWSHELL: ${riskLevel.toUpperCase()}*`,
      '',
      `Command: \`${truncatedCmd}\``,
      `Directory: ${workingDir}`,
      `Reason: ${(riskReasons || []).join(', ')}`,
      '',
      `Request ID: \`${id}\``,
    ].join('\n');

    const url = `https://api.telegram.org/bot${this.#botToken}/sendMessage`;
    const payload = {
      chat_id: this.#chatId,
      text,
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [[
          { text: 'APPROVE \u2713', callback_data: `approve:${id}` },
          { text: 'REJECT \u2717', callback_data: `reject:${id}` },
        ]],
      },
    };

    try {
      const response = await axios.post(url, payload);
      return {
        notificationId: String(response.data.result.message_id),
        receipt: null,
        timestamp: new Date().toISOString(),
      };
    } catch (err) {
      const msg = err.response?.data?.description || err.message;
      throw new Error(`Telegram send failed: ${msg}`);
    }
  }

  async pollForResponse(requestId, timeoutMs = 300_000) {
    const deadline = Date.now() + timeoutMs;
    const pollInterval = 3_000;
    let offset = 0;

    while (Date.now() < deadline) {
      try {
        const url = `https://api.telegram.org/bot${this.#botToken}/getUpdates`;
        const res = await axios.get(url, { params: { offset, timeout: 2 } });

        for (const update of res.data.result || []) {
          offset = update.update_id + 1;
          const cb = update.callback_query;
          if (!cb) continue;

          const [action, id] = (cb.data || '').split(':');
          if (id === requestId) {
            // Acknowledge the callback
            await axios.post(`https://api.telegram.org/bot${this.#botToken}/answerCallbackQuery`, {
              callback_query_id: cb.id,
              text: action === 'approve' ? 'Approved' : 'Rejected',
            }).catch(() => {});

            return {
              approved: action === 'approve',
              decidedBy: 'user_telegram',
            };
          }
        }
      } catch {
        // Network error — keep trying
      }

      await sleep(pollInterval);
    }

    return { approved: false, decidedBy: 'timeout' };
  }
}

export class MockNotifier {
  #autoApprove;
  #delayMs;

  constructor(opts = {}) {
    this.#autoApprove = opts.autoApprove !== false;
    this.#delayMs = opts.delayMs || 1000;
  }

  get type() { return 'mock'; }

  async sendApprovalRequest(request) {
    return {
      notificationId: `mock-${request.id}`,
      receipt: null,
      timestamp: new Date().toISOString(),
    };
  }

  async pollForResponse(_requestId, _timeoutMs) {
    await sleep(this.#delayMs);
    return {
      approved: this.#autoApprove,
      decidedBy: 'mock',
    };
  }
}

/**
 * Factory: returns the appropriate notifier based on available env vars.
 */
export function getNotifier(opts = {}) {
  if (opts.mock) {
    return new MockNotifier(opts);
  }

  if (process.env.CLAWSHELL_PUSHOVER_USER && process.env.CLAWSHELL_PUSHOVER_TOKEN) {
    return new PushoverNotifier(opts);
  }

  if (process.env.CLAWSHELL_TELEGRAM_BOT_TOKEN && process.env.CLAWSHELL_TELEGRAM_CHAT_ID) {
    return new TelegramNotifier(opts);
  }

  // Fall back to mock in dev/test
  return new MockNotifier(opts);
}

export function getMockNotifier(opts = {}) {
  return new MockNotifier(opts);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
