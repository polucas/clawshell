import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { minimatch } from 'minimatch';

// --- Built-in rule definitions ---

const CRITICAL_PATTERNS = [
  // Destructive system-level commands
  { regex: /\brm\s+(-[^\s]*\s+)*-{0,2}(rf|fr)\s+[\/~]\s*$/, reason: 'destructive_root_delete' },
  // Fork bombs (flexible whitespace)
  { regex: /:\s*\(\s*\)\s*\{.*:\s*\|\s*:.*&.*\}\s*;\s*:/, reason: 'fork_bomb' },
  { regex: /\b(bash|sh)\s+-c\s+.*fork\s*bomb/i, reason: 'fork_bomb' },
  // Disk destruction
  { regex: /\bdd\s+.*of=\/dev\//, reason: 'disk_overwrite' },
  { regex: /\bmkfs[.\s]/, reason: 'filesystem_format' },
  { regex: /\bformat\s+[A-Z]:/, reason: 'disk_format' },
  // Pipe to shell (encoding bypass)
  { regex: /\|\s*(ba)?sh\b/, reason: 'pipe_to_shell' },
  { regex: /\bbase64\s+(-d|--decode).*\|\s*(ba)?sh/, reason: 'encoded_shell_execution' },
  { regex: /\beval\s+.*\$\(/, reason: 'eval_command_substitution' },
];

const HIGH_PATTERNS = [
  // Destructive commands (non-root)
  { regex: /\brm\s+(-[^\s]*\s+)*-{0,2}(rf|fr)\b/, reason: 'destructive_command' },
  { regex: /\brm\s+(-[^\s]*\s+)*-r\b/, reason: 'recursive_delete' },
  // Network exfiltration (non-localhost)
  { regex: /\bcurl\s+/, reason: 'network_request', checkLocalhost: true },
  { regex: /\bwget\s+/, reason: 'network_request', checkLocalhost: true },
  { regex: /\bnc\s+/, reason: 'netcat', checkLocalhost: true },
  { regex: /\bssh\s+/, reason: 'ssh_connection' },
  { regex: /\bscp\s+/, reason: 'scp_transfer' },
  { regex: /\brsync\s+/, reason: 'rsync_transfer' },
  // Credential access
  { regex: /[~\/]\.ssh\/id_/, reason: 'ssh_key_access' },
  { regex: /[~\/]\.aws\//, reason: 'aws_credential_access' },
  { regex: /[~\/]\.openclaw\/credentials/, reason: 'openclaw_credential_access' },
  { regex: /\.env\b/, reason: 'env_file_access' },
  { regex: /\/etc\/shadow/, reason: 'shadow_file_access' },
  { regex: /\/etc\/passwd/, reason: 'passwd_file_access' },
  // System modification
  { regex: /\bsudo\s+/, reason: 'sudo_usage' },
  { regex: /\bsu\s+/, reason: 'su_usage' },
  { regex: /\bchmod\s+777\b/, reason: 'world_writable_permissions' },
  { regex: /\bchown\s+/, reason: 'ownership_change' },
  // Base64 decode (potential bypass)
  { regex: /\bbase64\s+(-d|--decode)/, reason: 'base64_decode' },
];

const MEDIUM_PATTERNS = [
  { regex: /\bnpm\s+install\b/, reason: 'package_install' },
  { regex: /\bpip\s+install\b/, reason: 'package_install' },
  { regex: /\bgit\s+push\b/, reason: 'git_push' },
  { regex: /\bgit\s+commit\b/, reason: 'git_commit' },
  { regex: /\bspawn\b/, reason: 'process_spawn' },
  { regex: /\bfork\b/, reason: 'process_fork' },
];

const LOW_COMMAND_PREFIXES = [
  'ls', 'cat', 'less', 'head', 'tail', 'echo', 'pwd', 'whoami',
  'npm test', 'npm run', 'npm start', 'pnpm', 'npx',
  'node', 'python', 'python3',
  'git status', 'git diff', 'git log', 'git branch', 'git show',
  'grep', 'find', 'wc', 'sort', 'uniq', 'which', 'env', 'printenv',
  'mkdir', 'touch', 'cp', 'mv', 'date', 'uname',
];

const LOCALHOST_PATTERN = /(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(?::\d+)?/;

export class RiskAnalyzer {
  #config;

  constructor(config = {}) {
    this.#config = this.#loadConfig(config);
  }

  analyzeCommand(command, workingDir = process.cwd()) {
    const trimmed = command.trim();
    const reasons = [];
    let level = 'low';

    // Command allowlist takes precedence over blocklist (per spec)
    if (this.#matchesCommandAllowlist(trimmed)) {
      return { level: 'low', reasons: ['allowlisted'], command: trimmed, workingDir, recommendation: 'allow' };
    }

    // Check custom blocklist (elevates to critical)
    const blockReason = this.#matchesBlocklist(trimmed);
    if (blockReason) {
      return { level: 'critical', reasons: [blockReason], command: trimmed, workingDir, recommendation: 'block' };
    }

    // Check critical patterns — never overridable by allowlist
    for (const pattern of CRITICAL_PATTERNS) {
      if (pattern.regex.test(trimmed)) {
        reasons.push(pattern.reason);
        level = 'critical';
      }
    }
    if (level === 'critical') {
      return { level, reasons, command: trimmed, workingDir, recommendation: 'block' };
    }

    // Check high-risk patterns — never overridable by allowlist
    for (const pattern of HIGH_PATTERNS) {
      if (pattern.regex.test(trimmed)) {
        // For network commands, check if targeting localhost
        if (pattern.checkLocalhost && LOCALHOST_PATTERN.test(trimmed)) {
          continue; // Skip — localhost is safe
        }
        reasons.push(pattern.reason);
        if (level !== 'high') level = 'high';
      }
    }
    if (level === 'high') {
      // Command allowlist can override high-risk (e.g. explicitly allowed commands)
      // but path allowlist alone should NOT override high-risk
      if (this.#matchesCommandAllowlist(trimmed)) {
        return { level: 'low', reasons: ['allowlisted'], command: trimmed, workingDir, recommendation: 'allow' };
      }
      return { level, reasons, command: trimmed, workingDir, recommendation: 'approve' };
    }

    // Check medium-risk patterns
    for (const pattern of MEDIUM_PATTERNS) {
      if (pattern.regex.test(trimmed)) {
        reasons.push(pattern.reason);
        if (level !== 'medium') level = 'medium';
      }
    }

    // File operations outside workspace boundary
    const workspace = process.env.WORKSPACE_DIR || '/app/workspace';
    if (workingDir && !workingDir.startsWith(workspace)) {
      // Only flag write-oriented file operations, not package manager installs
      const fileOps = /\b(cp|mv|tee|truncate)\b/;
      if (fileOps.test(trimmed)) {
        reasons.push('file_operation_outside_workspace');
        if (level !== 'medium') level = 'medium';
      }
    }

    if (level === 'medium') {
      // Allowlist (command or path) can downgrade medium to low
      if (this.#matchesAllowlist(trimmed, workingDir)) {
        return { level: 'low', reasons: ['allowlisted'], command: trimmed, workingDir, recommendation: 'allow' };
      }
      return { level, reasons, command: trimmed, workingDir, recommendation: 'log_and_allow' };
    }

    // Default: low risk
    return { level: 'low', reasons: ['standard_command'], command: trimmed, workingDir, recommendation: 'allow' };
  }

  #matchesCommandAllowlist(command) {
    const allowlist = this.#config.rules?.allowlist;
    if (!allowlist?.commands) return false;

    for (const pattern of allowlist.commands) {
      if (this.#matchPattern(command, pattern)) return true;
    }
    return false;
  }

  #matchesAllowlist(command, workingDir) {
    if (this.#matchesCommandAllowlist(command)) return true;

    const allowlist = this.#config.rules?.allowlist;
    if (!allowlist) return false;

    if (allowlist.paths && workingDir) {
      for (const pattern of allowlist.paths) {
        if (this.#matchPattern(workingDir, pattern)) return true;
      }
    }

    return false;
  }

  #matchesBlocklist(command) {
    const blocklist = this.#config.rules?.blocklist;
    if (!blocklist) return null;

    if (blocklist.commands) {
      for (const pattern of blocklist.commands) {
        if (this.#matchPattern(command, pattern)) return `blocklisted: ${pattern}`;
      }
    }

    return null;
  }

  #matchPattern(value, pattern) {
    // Regex pattern: must start with / and end with / optionally followed by valid flags only
    const regexMatch = pattern.match(/^\/(.+)\/([gimsuy]*)$/);
    if (regexMatch) {
      try {
        return new RegExp(regexMatch[1], regexMatch[2]).test(value);
      } catch {
        return false;
      }
    }

    // Exact match
    if (value === pattern) return true;

    // Glob match
    return minimatch(value, pattern, { dot: true });
  }

  #loadConfig(overrides) {
    let config = {};

    // Try config.yaml
    const configPaths = [
      join(process.cwd(), 'config.yaml'),
      join(process.cwd(), '..', 'config.yaml'),
    ];

    for (const configPath of configPaths) {
      if (existsSync(configPath)) {
        try {
          const raw = readFileSync(configPath, 'utf-8');
          config = YAML.parse(raw) || {};
          break;
        } catch { /* ignore parse errors */ }
      }
    }

    // Environment variable overrides (comma-separated)
    if (process.env.CLAWSHELL_BLOCKLIST) {
      config.rules = config.rules || {};
      config.rules.blocklist = config.rules.blocklist || {};
      config.rules.blocklist.commands = process.env.CLAWSHELL_BLOCKLIST.split(',').map(s => s.trim());
    }

    if (process.env.CLAWSHELL_ALLOWLIST) {
      config.rules = config.rules || {};
      config.rules.allowlist = config.rules.allowlist || {};
      config.rules.allowlist.commands = process.env.CLAWSHELL_ALLOWLIST.split(',').map(s => s.trim());
    }

    // Merge overrides
    return { ...config, ...overrides };
  }
}

// Convenience singleton
let _defaultAnalyzer;
export function getAnalyzer(config) {
  if (!_defaultAnalyzer) {
    _defaultAnalyzer = new RiskAnalyzer(config);
  }
  return _defaultAnalyzer;
}

export function analyzeCommand(command, workingDir) {
  return getAnalyzer().analyzeCommand(command, workingDir);
}
