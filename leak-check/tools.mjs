// How the scanners are invoked. Every config is Leak Check's own: a scanned repo
// must never be able to allowlist its own leaks with .gitleaks.toml,
// .gitleaksignore or osv-scanner.toml.
import { join } from 'node:path';

export const TRUSTED_GITLEAKS = join(import.meta.dirname, 'gitleaks.toml');
export const TRUSTED_OSV = join(import.meta.dirname, 'osv-scanner.toml');

export function gitleaksArgs(mode, target, config, ignorePath, out) {
  return [mode, target, '--no-banner', '--exit-code', '0', '--config', config,
          '--gitleaks-ignore-path', ignorePath, '--report-format', 'json', '--report-path', out];
}

export function osvArgs(config) {
  return ['scan', 'source', '-r', '.', '--config', config, '--format', 'json'];
}

// osv-scanner exits 0 for clean, 1 for vulnerabilities found. Anything else, or
// no output at all, means nothing was checked: that must never read as clean.
export function osvResult(status, stdout) {
  if ((status !== 0 && status !== 1) || !String(stdout).trim()) {
    throw new Error(`osv-scanner failed (exit ${status}); dependencies were NOT checked`);
  }
  return JSON.parse(stdout);
}

export function explainedOrNone(x) {
  return x && typeof x.summary === 'string' && Array.isArray(x.findings)
    && x.findings.every((f) => f && typeof f.title === 'string' && typeof f.fix === 'string') ? x : undefined;
}
