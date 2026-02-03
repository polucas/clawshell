# ClawShell

Human-in-the-loop security for OpenClaw agents.

## What it does

ClawShell intercepts shell commands before execution, analyzes their risk level, and requires your explicit approval (via phone notification) for dangerous operations like `rm -rf`, `curl` to external URLs, or accessing credentials.

| Risk Level | Action | Examples |
|------------|--------|----------|
| **Critical** | Auto-blocked | `rm -rf /`, fork bombs, `dd` to disks |
| **High** | Pushover/Telegram notification, waits for approval | `rm -rf`, `curl` to external URLs, `sudo`, credential access |
| **Medium** | Logged, allowed | `npm install`, `git push`, `git commit` |
| **Low** | Allowed | `ls`, `cat`, `git status`, `npm test` |

## Quick Start

1. Add to your OpenClaw workspace skills:
   ```
   npx clawhub install clawshell
   ```

2. Add your notification keys to `.env`:
   ```env
   CLAWSHELL_PUSHOVER_USER=your-user-key
   CLAWSHELL_PUSHOVER_TOKEN=your-app-token
   ```

3. Add to your `TOOLS.md`:
   ```
   Use clawshell_bash instead of bash for all shell commands.
   ```

4. Done! You'll get push notifications for risky commands.

## Tools

- **`clawshell_bash(command, workingDir)`** — Secure bash replacement with risk analysis
- **`clawshell_status()`** — View pending approvals and recent decisions
- **`clawshell_logs(count)`** — View audit log entries
- **`clawshell_config()`** — View current configuration (without secrets)

## Configuration

ClawShell reads configuration from environment variables (`CLAWSHELL_*`) with fallback to `config.yaml`.

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAWSHELL_PUSHOVER_USER` | -- | Pushover user key |
| `CLAWSHELL_PUSHOVER_TOKEN` | -- | Pushover app token |
| `CLAWSHELL_TELEGRAM_BOT_TOKEN` | -- | Telegram bot token (alternative) |
| `CLAWSHELL_TELEGRAM_CHAT_ID` | -- | Telegram chat ID (alternative) |
| `CLAWSHELL_TIMEOUT_SECONDS` | 300 | Seconds to wait for approval |
| `CLAWSHELL_LOG_DIR` | logs/ | JSONL log directory |
| `CLAWSHELL_BLOCKLIST` | -- | Comma-separated extra blocked commands |
| `CLAWSHELL_ALLOWLIST` | -- | Comma-separated extra allowed commands |

Custom rules can also be defined in `config.yaml` using exact strings, globs, or regex patterns. See `config.example.yaml` for the full template.

## Development

```bash
# Run unit tests (standalone)
npm test

# Docker - isolated (no network)
docker-compose -f docker/docker-compose.yml build
docker-compose -f docker/docker-compose.yml up -d
docker exec -it clawshell-dev bash

# Docker - with network (Pushover testing)
docker-compose -f docker/docker-compose.network.yml up -d
docker exec -it clawshell-dev-network bash

# Inside container
cd /app/workspace/skills/clawshell
node --test test/risk-analyzer.test.mjs
node --test test/logger.test.mjs
node --test test/integration.test.mjs
```

## Limitations

- **Not a security guarantee.** LLMs can encode, split, or obfuscate commands to bypass pattern matching.
- **Defense-in-depth only.** Use alongside OpenClaw's sandbox mode, not as a replacement.
- **Approval latency.** High-risk commands block execution until you respond or the timeout expires.

> **Always ask your AI to scan any skill or software for security risks.**

## License

MIT
