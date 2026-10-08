import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';

import { secretsFrom, redact, dependenciesFrom } from './findings.mjs';
import { clientScripts, probeEndpoint } from './live.mjs';
import { renderReport, verdict } from './report.mjs';

const fx = (f) => JSON.parse(readFileSync(join(import.meta.dirname, 'fixtures', f), 'utf8'));

// --- findings.mjs -----------------------------------------------------------

test('a secret still in the code is a secret in the code', () => {
  const now = new Set(['demo-app/public/app.js']);
  const s = secretsFrom(fx('gitleaks-history.json'), now).find((x) => x.file.endsWith('app.js'));
  assert.equal(s.where, 'code');
});

test('a secret whose file was deleted is still a leak, in the history', () => {
  const now = new Set(['demo-app/public/app.js']);          // .env no longer exists
  const s = secretsFrom(fx('gitleaks-history.json'), now).find((x) => x.file.endsWith('.env'));
  assert.equal(s.where, 'history');
  assert.match(s.commit, /^[0-9a-f]{7}$/);
});

test('the secret itself never leaves findings.mjs', () => {
  const all = JSON.stringify(secretsFrom(fx('gitleaks-history.json'), new Set()));
  assert.doesNotMatch(all, /FIXTURE-SECRET|FIXTURE-MATCH/);
});

test('redact keeps at most four characters and the length', () => {
  assert.equal(redact('abcd1234efgh5678ijkl'), 'abcd… (20 characters)');
  assert.equal(redact('abc'), '… (3 characters)');
});

test('a vulnerable dependency comes back with its advisories', () => {
  const [d] = dependenciesFrom(fx('osv.json'));
  assert.equal(d.package, 'lodash');
  assert.equal(d.version, '4.17.15');
  assert.ok(d.advisories.length >= 3);
  assert.ok(d.advisories.every((a) => /^GHSA-/.test(a.id)));
});

// --- live.mjs ---------------------------------------------------------------

function serve(routes) {
  return new Promise((resolve) => {
    const s = createServer((req, res) => {
      const r = routes[req.url];
      if (!r) return res.writeHead(404).end();
      res.writeHead(200, { 'content-type': r.type }).end(r.body);
    }).listen(0, '127.0.0.1', () => resolve({ s, base: `http://127.0.0.1:${s.address().port}` }));
  });
}

test('the page code every visitor downloads is collected, same-site scripts only', async () => {
  const { s, base } = await serve({
    '/': { type: 'text/html', body: '<script src="/app.js"></script><script src="https://cdn.example/x.js"></script>' },
    '/app.js': { type: 'text/javascript', body: 'const k = 1;' },
  });
  try {
    const files = await clientScripts(base);
    assert.deepEqual(files.map((f) => f.path), ['/app.js']);
    assert.equal(files[0].body, 'const k = 1;');
  } finally { s.close(); }
});

test('an endpoint that hands out personal data with no login is flagged', async () => {
  const { s, base } = await serve({
    '/api/notes': { type: 'application/json', body: JSON.stringify([{ owner: 'a@x.test', text: 't' }]) },
  });
  try {
    const f = await probeEndpoint(base, '/api/notes');
    assert.equal(f.open, true);
    assert.equal(f.records, 1);
    assert.deepEqual(f.fields, ['owner', 'text']);
  } finally { s.close(); }
});

test('an endpoint that refuses without a login is fine', async () => {
  const { s, base } = await serve({});
  try {
    assert.equal((await probeEndpoint(base, '/api/notes')).open, false);
  } finally { s.close(); }
});

test('only your own local app is probed', async () => {
  await assert.rejects(probeEndpoint('https://example.com', '/api/notes'), /only scans your own app/);
  await assert.rejects(clientScripts('http://203.0.113.9'), /only scans your own app/);
});

// --- report.mjs -------------------------------------------------------------

const sample = {
  secrets: [{ where: 'history', file: 'demo-app/.env', line: 3, commit: 'f8fa1b6', rule: 'generic-api-key', preview: 'abcd… (32 characters)' }],
  client: [{ file: '/app.js', line: 2, rule: 'generic-api-key', preview: 'Zx9q… (40 characters)' }],
  endpoints: [{ path: '/api/notes', open: true, records: 3, fields: ['id', 'owner', 'text'] }],
  dependencies: [{ package: 'lodash', version: '4.17.15', advisories: [{ id: 'GHSA-p6mc-m468-83gw', summary: 'Prototype Pollution' }] }],
  explained: { summary: 'Rotate both keys.', findings: [] },
};

test('any leak means the app is not safe to ship', () => {
  assert.equal(verdict(sample), 'leaking');
  assert.equal(verdict({ secrets: [], client: [], endpoints: [], dependencies: [] }), 'clean');
});

test('the report never prints a secret, only its preview', () => {
  const md = renderReport(sample);
  assert.match(md, /abcd… \(32 characters\)/);
  assert.match(md, /f8fa1b6/);
  assert.match(md, /rotate/i);
});

test('the report credits the scanners it ran', () => {
  const md = renderReport(sample);
  for (const t of ['gitleaks', 'osv-scanner']) assert.match(md, new RegExp(t));
});

import { clean } from './report.mjs';

test('mentions are broken but package@version commands stay copyable', () => {
  assert.doesNotMatch(clean('ping @octocat now'), /@octocat/);
  assert.equal(clean('run npm install lodash@latest'), 'run npm install lodash@latest');
});

// --- found by Ship Check's review of Leak Check, 2026-10-08 -----------------

import { code } from './report.mjs';
import { gitleaksArgs, osvArgs, osvResult, explainedOrNone } from './tools.mjs';
import { firstJson } from './claude.mjs';

test('a probe path cannot swap in another host', async () => {
  await assert.rejects(probeEndpoint('http://127.0.0.1:4322', 'http://169.254.169.254/latest'), /plain path/);
  await assert.rejects(probeEndpoint('http://127.0.0.1:4322', '//evil.example/x'), /plain path/);
});

test('the scanned repo cannot allowlist its own leaks', () => {
  const g = gitleaksArgs('git', '.', 'trusted.toml', 'empty-ignore', 'out.json');
  assert.ok(g.includes('--config') && g[g.indexOf('--config') + 1] === 'trusted.toml');
  assert.ok(g.includes('--gitleaks-ignore-path') && g[g.indexOf('--gitleaks-ignore-path') + 1] === 'empty-ignore');
  const o = osvArgs('trusted-osv.toml');
  assert.ok(o.includes('--config') && o[o.indexOf('--config') + 1] === 'trusted-osv.toml');
});

test('osv-scanner failing is an error, never a clean result', () => {
  assert.deepEqual(osvResult(0, '{"results":[]}'), { results: [] });
  assert.deepEqual(osvResult(1, '{"results":[{"packages":[]}]}'), { results: [{ packages: [] }] });
  assert.throws(() => osvResult(127, ''), /osv-scanner failed/);
  assert.throws(() => osvResult(1, ''), /osv-scanner failed/);
});

test('a missing or malformed AI answer drops the AI section, not the report', () => {
  assert.equal(explainedOrNone({ summary: 's', findings: 'nope' }), undefined);
  assert.deepEqual(explainedOrNone({ summary: 's', findings: [{ title: 't', fix: 'f' }] }).findings.length, 1);
});

test('names from the repo cannot break out of a code span', () => {
  assert.equal(code('a`b\nc'), '`a\'b c`');
});

test('two different secrets on the same line are two leaks', () => {
  const two = [
    { File: 'a.env', RuleID: 'generic-api-key', StartLine: 1, Commit: 'aaaaaaa1', Secret: 'first-secret-value-123456', Fingerprint: 'aaaaaaa1:a.env:generic-api-key:1' },
    { File: 'a.env', RuleID: 'generic-api-key', StartLine: 1, Commit: 'bbbbbbb2', Secret: 'second-secret-value-654321', Fingerprint: 'bbbbbbb2:a.env:generic-api-key:1' },
  ];
  assert.equal(secretsFrom(two, new Set()).length, 2);
});

test('short secrets show only their length', () => {
  assert.equal(redact('hunter2pass'), '… (11 characters)');
  assert.equal(redact('abcd1234efgh5678ijkl9012'), 'abcd… (24 characters)');
});

test('inline page scripts are scanned, and an error page is not a clean page', async () => {
  const { s, base } = await serve({
    '/': { type: 'text/html', body: '<script>const key = "inline";</script>' },
  });
  try {
    const files = await clientScripts(base);
    assert.deepEqual(files.map((f) => f.path), ['/ (inline script 1)']);
  } finally { s.close(); }
  const empty = await serve({});
  try {
    await assert.rejects(clientScripts(empty.base), /answered 404/);
  } finally { empty.s.close(); }
});

test('the JSON answer is the whole reply or its fenced block, not a stray {} in prose', () => {
  assert.deepEqual(firstJson('Like this: {} — answer:\n```json\n{"findings":[1]}\n```'), { findings: [1] });
  assert.deepEqual(firstJson('{"findings":[2]}'), { findings: [2] });
});
