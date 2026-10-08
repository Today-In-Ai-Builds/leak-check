// One locked-down Claude Code call. The prompt carries a pull request's code,
// which anyone can write, so the model gets no tools at all: it cannot run
// commands, read or write files, or reach the network. It can only answer.
import { execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function claudeArgs(model = process.env.SHIP_CHECK_MODEL || 'sonnet') {
  return ['-p', '--model', model, '--output-format', 'json',
          '--tools', '',                       // no tools
          '--safe-mode',                       // no plugins, hooks, CLAUDE.md or skills of yours
          '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
          '--no-session-persistence'];         // nothing kept on disk
}

// The answer is the whole reply, or its ```json block. Only then fall back to
// scanning, so a stray "{}" in the model's prose is never taken for the answer.
export function firstJson(text) {
  const whole = text.trim();
  const fenced = whole.match(/```(?:json)?\s*\n([\s\S]*?)\n```/);
  for (const candidate of [whole, fenced?.[1]]) {
    if (!candidate) continue;
    try {
      const v = JSON.parse(candidate);
      if (v && typeof v === 'object' && !Array.isArray(v)) return v;
    } catch { /* not the whole answer */ }
  }
  for (let i = text.indexOf('{'); i !== -1; i = text.indexOf('{', i + 1)) {
    for (let j = text.lastIndexOf('}'); j > i; j = text.lastIndexOf('}', j - 1)) {
      try { return JSON.parse(text.slice(i, j + 1)); } catch { /* try a shorter span */ }
    }
  }
  throw new Error(`no JSON object in the reply: ${text.slice(0, 200)}`);
}

export async function askClaude(prompt) {
  const cwd = await mkdtemp(join(tmpdir(), 'ship-check-'));   // empty: no project files to read
  try {
    const stdout = await new Promise((resolve, reject) => {
      const child = execFile(process.env.CLAUDE_BIN || 'claude', claudeArgs(),
        // No shell, on any platform: a shell drops the empty `--tools ""` value
        // (which is what disables every tool) and mangles the JSON argument.
        { cwd, maxBuffer: 16 * 1024 * 1024, timeout: 10 * 60 * 1000, shell: false },
        (err, out, errOut) => (err ? reject(new Error(`claude failed: ${err.message} ${errOut}`)) : resolve(out)));
      // A missing or early-exiting claude errors the pipe: reject, don't crash.
      child.stdin.on('error', (e) => reject(new Error(`claude could not be started: ${e.message}`)));
      child.stdin.end(prompt);                  // stdin, not argv: diffs are long
    });
    const envelope = JSON.parse(stdout);
    if (envelope.is_error) throw new Error(`claude error: ${envelope.result}`);
    return firstJson(envelope.result);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}
