import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const WRITE_TOOLS = new Set([
  'Write',
  'StrReplace',
  'ApplyPatch',
  'Delete',
  'EditNotebook',
  'TabWrite',
]);

const PRODUCT_PACKAGE_NAMES = new Set(['human-coder', '@human-coder/monorepo']);

const ALLOW_RE =
  /\b(you\s+(can|may)\s+use\s+(your\s+)?(agent|cursor)(\s+file)?\s+write\s+tools|allow\s+(cursor|agent)\s+(file\s+)?write\s+tools)\b/i;
const REVOKE_RE =
  /\b(lock\s+(cursor\s+)?writes|stop\s+using\s+(cursor|agent)\s+write\s+tools|human[-\s]?coder\s+only)\b/i;

export function ownerAllowPath(home = os.homedir()) {
  return path.join(home, '.human-coder', 'allow-cursor-write.json');
}

export function isOwnerWriteAllowed(home = os.homedir(), now = Date.now()) {
  try {
    const raw = fs.readFileSync(ownerAllowPath(home), 'utf8');
    const json = JSON.parse(raw);
    if (json?.allowed !== true) {
      return false;
    }
    const expires = Number(json.expiresAt);
    if (!Number.isFinite(expires) || expires <= now) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function setOwnerWriteAllowed(home, allowed, now = Date.now()) {
  const dir = path.join(home, '.human-coder');
  fs.mkdirSync(dir, { recursive: true });
  const dest = ownerAllowPath(home);
  if (!allowed) {
    try {
      fs.unlinkSync(dest);
    } catch {
      // missing is fine
    }
    return;
  }
  fs.writeFileSync(
    dest,
    `${JSON.stringify({ allowed: true, expiresAt: now + 12 * 60 * 60 * 1000 }, null, 2)}\n`,
    'utf8',
  );
}

export function isHumanCoderProductCwd(cwd) {
  let dir = path.resolve(cwd || '');
  for (let i = 0; i < 12; i += 1) {
    const pkgPath = path.join(dir, 'package.json');
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (PRODUCT_PACKAGE_NAMES.has(pkg.name)) {
        return true;
      }
    } catch {
      // keep walking
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }
  return false;
}

export function humanCoderMcpEnabled(home = os.homedir()) {
  const mcpPath = path.join(home, '.cursor', 'mcp.json');
  try {
    const json = JSON.parse(fs.readFileSync(mcpPath, 'utf8'));
    const servers = json?.mcpServers ?? json?.mcp;
    const entry = servers?.['human-coder'];
    if (!entry || typeof entry !== 'object') {
      return false;
    }
    return entry.disabled !== true;
  } catch {
    return false;
  }
}

export function isShellAsEditor(command) {
  const c = String(command ?? '');
  if (!c.trim()) {
    return false;
  }
  if (/\b(cat|tee)\s+>/i.test(c)) {
    return true;
  }
  if (/(^|[;&|]\s*)(echo|printf)\s+.*>/i.test(c)) {
    return true;
  }
  if (/<<\s*['"]?EOF/i.test(c)) {
    return true;
  }
  if (/\bsed\s+-i\b/i.test(c)) {
    return true;
  }
  if (/\bgit\s+apply\b/i.test(c)) {
    return true;
  }
  if (/\b(Set-Content|Out-File|Add-Content|Set-Content)\b/i.test(c)) {
    return true;
  }
  if (/python(3)?\s+-c\s+.*open\s*\(/i.test(c)) {
    return true;
  }
  if (/\b(vim|nano|notepad)\s+\S+/i.test(c)) {
    return true;
  }
  return false;
}

function toolNameOf(event) {
  return String(event?.tool_name ?? event?.toolName ?? event?.tool ?? '');
}

function cwdOf(event) {
  return String(event?.cwd ?? event?.workspace_roots?.[0] ?? process.cwd());
}

function pathsToCheck(event) {
  const input = event?.tool_input ?? event?.input ?? {};
  return [cwdOf(event), input.path, input.file_path, event?.path, event?.file_path]
    .filter(Boolean)
    .map((value) => String(value));
}

function promptOf(event) {
  return String(event?.prompt ?? event?.user_prompt ?? event?.command ?? event?.text ?? '');
}

function shellCommandOf(event) {
  return String(event?.command ?? event?.tool_input?.command ?? '');
}

const DENY_MESSAGE =
  'Human-Coder is on. Cursor Write / StrReplace / ApplyPatch / Delete and shell-as-editor are blocked. Use human_coder_edit or human_coder_patch. The owner must say “you can use your agent write tools” (or turn off the Human-Coder MCP server) before those tools work.';

export function decideCursorWriteLock(event, options = {}) {
  const home = options.home ?? os.homedir();
  const now = options.now ?? Date.now();
  const hookEvent = String(event?.hook_event_name ?? event?.event ?? '');
  const looksLikePrompt =
    hookEvent === 'beforeSubmitPrompt' ||
    hookEvent === 'UserPromptSubmit' ||
    (event?.prompt != null && toolNameOf(event) === '');

  if (looksLikePrompt) {
    const text = promptOf(event);
    if (REVOKE_RE.test(text)) {
      setOwnerWriteAllowed(home, false, now);
      return { permission: 'allow', agent_message: 'Cursor write tools locked again.' };
    }
    if (ALLOW_RE.test(text)) {
      setOwnerWriteAllowed(home, true, now);
      return {
        permission: 'allow',
        agent_message: 'Owner allowed Cursor write tools for up to 12 hours.',
      };
    }
    return { permission: 'allow' };
  }

  if (pathsToCheck(event).some((candidate) => isHumanCoderProductCwd(candidate))) {
    return { permission: 'allow' };
  }

  if (isOwnerWriteAllowed(home, now)) {
    return { permission: 'allow' };
  }

  if (!humanCoderMcpEnabled(home)) {
    return { permission: 'allow' };
  }

  const tool = toolNameOf(event);

  if (hookEvent === 'beforeShellExecution' || tool === 'Shell') {
    if (isShellAsEditor(shellCommandOf(event))) {
      return {
        permission: 'deny',
        user_message: DENY_MESSAGE,
        agent_message: DENY_MESSAGE,
      };
    }
    return { permission: 'allow' };
  }

  if (WRITE_TOOLS.has(tool)) {
    return {
      permission: 'deny',
      user_message: DENY_MESSAGE,
      agent_message: DENY_MESSAGE,
    };
  }

  return { permission: 'allow' };
}

function readStdin() {
  return fs.readFileSync(0, 'utf8');
}

function main() {
  let event = {};
  try {
    const raw = readStdin().trim();
    if (raw) {
      event = JSON.parse(raw);
    }
  } catch {
    event = {};
  }
  const result = decideCursorWriteLock(event);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.permission === 'deny') {
    process.exit(2);
  }
}

const thisFile = fileURLToPath(import.meta.url);
const invoked = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invoked && path.normalize(invoked).toLowerCase() === path.normalize(thisFile).toLowerCase()) {
  main();
}
