// Turns gitleaks and osv-scanner output into findings. The secret is redacted
// here: past this file (the AI step, the report) only a preview exists.
import { createHash } from 'node:crypto';

// Four characters are only shown for long, random keys; for anything shorter
// (a password) even four characters give too much away, so only the length.
export function redact(secret = '') {
  const s = String(secret);
  return `${s.length >= 20 ? s.slice(0, 4) : ''}… (${s.length} characters)`;
}

// `current` is the set of files in the working tree. A secret in a file that is
// gone is still a leak: it lives in git history, and anyone who clones has it.
export function secretsFrom(gitleaks, current) {
  const seen = new Set();
  const out = [];
  for (const g of gitleaks ?? []) {
    // The secret's hash is part of the key: a rotated key on the same line is a second leak.
    const hash = createHash('sha256').update(String(g.Secret ?? '')).digest('hex');
    const key = `${g.File}|${g.RuleID}|${g.StartLine}|${hash}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      where: current.has(g.File) ? 'code' : 'history',
      file: g.File, line: g.StartLine, commit: (g.Commit ?? '').slice(0, 7),
      rule: g.RuleID, preview: redact(g.Secret),
    });
  }
  return out;
}

export function dependenciesFrom(osv) {
  const out = [];
  for (const r of osv?.results ?? []) {
    for (const p of r.packages ?? []) {
      const advisories = (p.vulnerabilities ?? []).map((v) => ({ id: v.id, summary: v.summary ?? '' }));
      if (advisories.length) {
        out.push({ package: p.package.name, version: p.package.version, source: r.source?.path, advisories });
      }
    }
  }
  return out;
}
