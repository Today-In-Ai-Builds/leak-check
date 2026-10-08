// Regenerates the README's images and demo GIF from the real demo app and a
// real scan (.leak-check/findings.json, leak-check-report.md). Uses your
// installed Microsoft Edge; FFMPEG must point at ffmpeg for the GIF.
//   npm run demo-app &  npm run leak-check;  node docs/make-media.mjs
import { chromium } from 'playwright-core';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const here = import.meta.dirname;
const media = join(here, 'media');
const APP = 'http://127.0.0.1:4322';
mkdirSync(media, { recursive: true });
const findings = JSON.parse(readFileSync('.leak-check/findings.json', 'utf8'));
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function mapHtml(f) {
  const zone = (title, sub, pins) => `<div class="zone ${pins.length ? 'hot' : ''}"><h3>${title}</h3><p class="sub">${sub}</p>
    ${pins.length ? pins.map((p) => `<div class="pin"><b>●</b> ${esc(p)}</div>`).join('') : '<div class="ok">✓ nothing found</div>'}</div>`;
  const history = f.secrets.filter((s) => s.where === 'history');
  const code = f.secrets.filter((s) => s.where === 'code');
  // A key served to visitors is usually the same key that sits in the code: count it once.
  const shippedOnly = f.client.filter((c) => !code.some((s) => s.preview === c.preview));
  const unique = f.secrets.length + shippedOnly.length + f.endpoints.length + f.dependencies.length;
  return `<!doctype html><meta charset="utf-8"><style>
    body { margin:0; padding:34px; width:1180px; background:#f6f3f1; font:15px/1.45 "Segoe UI",system-ui,sans-serif; color:#231a17; }
    h1 { font-size:30px; margin:0 0 4px; } .lead { color:#6b5a54; margin:0 0 22px; font-size:17px; }
    .grid { display:grid; grid-template-columns: repeat(5, 1fr); gap:14px; }
    .zone { background:#fff; border:2px solid #e3d9d4; border-radius:14px; padding:16px; min-height:150px; }
    .zone.hot { border-color:#c9483a; box-shadow:0 0 0 4px #c9483a1f; }
    h3 { margin:0; font-size:18px; } .sub { margin:2px 0 12px; color:#8a7770; font-size:13px; }
    .pin { background:#fbe9e6; border-radius:8px; padding:8px 10px; margin:8px 0; font:13px/1.4 "Cascadia Mono",Consolas,monospace; }
    .pin b { color:#c9483a; } .ok { color:#3c8a55; font-weight:600; }
    .flow { display:flex; justify-content:space-between; color:#a08f88; font:600 12px "Cascadia Mono",Consolas,monospace; margin:10px 6px 0; }
  </style><h1>🚨 ${unique} leaks in a 40-line notes app</h1>
  <p class="lead">Where each one is, and who can reach it.</p><div class="grid">
  ${zone('🌐 Browser', 'what every visitor downloads', f.client.map((c) => `${c.file}:${c.line} API key ${c.preview}`))}
  ${zone('🔑 Code', 'what is in the repo now', code.map((s) => `${s.file.split('/').pop()}:${s.line} ${s.preview}`))}
  ${zone('🕰️ Git history', '"deleted" is not gone', history.map((s) => `${s.file.split('/').pop()} in ${s.commit}: password ${s.preview}`))}
  ${zone('🚪 API', 'answers with no login', f.endpoints.map((e) => `GET ${e.path}: ${e.records} people's notes`))}
  ${zone('📦 Dependencies', 'known vulnerabilities', f.dependencies.map((d) => `${d.package}@${d.version}: ${d.advisories.length} advisories`))}
  </div><div class="flow"><span>visitor</span><span>anyone who clones</span><span>anyone with the URL</span><span>supply chain</span></div>`;
}

function reportHtml(md) {
  const inline = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '<a>$1</a>');
  const body = md.split('\n').map((l) => {
    if (l.startsWith('# ')) return `<h1>${inline(l.slice(2))}</h1>`;
    if (l.startsWith('## ')) return `<h2>${inline(l.slice(3))}</h2>`;
    if (l.startsWith('> ')) return `<blockquote>${inline(l.slice(2))}</blockquote>`;
    if (/^(- |\d+\. )/.test(l)) return `<li>${inline(l.replace(/^(- |\d+\. )/, ''))}</li>`;
    if (l === '---') return '<hr>';
    return l.trim() ? `<p>${inline(l)}</p>` : '';
  }).join('\n');
  return `<!doctype html><meta charset="utf-8"><style>
    body { margin:0; padding:28px; width:900px; background:#0f1115; font:15px/1.55 "Segoe UI",system-ui,sans-serif; color:#e6e1dc; }
    .term { background:#171a21; border:1px solid #2a2f3a; border-radius:12px; padding:6px 24px 16px; }
    .bar { color:#7d8696; font:13px "Cascadia Mono",Consolas,monospace; padding:10px 0 4px; }
    h1 { font-size:24px; color:#ff8a6b; } h2 { font-size:17px; margin:18px 0 6px; }
    li { margin:4px 0 4px 18px; } code { font:13px "Cascadia Mono",Consolas,monospace; background:#262b36; padding:1px 5px; border-radius:4px; }
    blockquote { margin:6px 0; padding:8px 12px; border-left:3px solid #ff8a6b; background:#1f2229; } a { color:#8ab4ff; }
    hr { border:0; border-top:1px solid #2a2f3a; } p { margin:6px 0; }
  </style><div class="term"><div class="bar">$ npm run leak-check</div>${body}</div>`;
}

async function shot(browser, html, out, width) {
  const page = await browser.newPage({ viewport: { width, height: 400 }, deviceScaleFactor: 2 });
  await page.setContent(html);
  await page.screenshot({ path: join(media, out), fullPage: true });
  await page.close();
}

async function demoGif(browser) {
  const frames = join(media, '.frames');
  rmSync(frames, { recursive: true, force: true });
  mkdirSync(frames);
  const page = await browser.newPage({ viewport: { width: 900, height: 560 } });
  const list = [];
  const caption = (text, bad) => page.evaluate(([t, b]) => {
    let c = document.querySelector('#lc-cap');
    if (!c) { c = document.createElement('div'); c.id = 'lc-cap'; document.body.append(c); }
    c.textContent = t;
    c.style.cssText = 'position:fixed;left:22px;right:22px;bottom:20px;padding:14px 18px;border-radius:10px;z-index:9;' +
      `font:600 20px/1.3 Segoe UI,system-ui,sans-serif;color:#fff;background:${b ? '#b8382b' : '#1d1d1b'};box-shadow:0 8px 30px #0004`;
  }, [text, bad]);
  const hold = async (seconds) => {
    const f = join(frames, `${String(list.length).padStart(3, '0')}.png`);
    await page.screenshot({ path: f });
    list.push(`file '${f.replace(/\\/g, '/')}'\nduration ${seconds}`);
  };
  const viewText = (title, text, mark) => page.setContent(`<!doctype html><meta charset="utf-8"><body style="margin:0;background:#1e1e1e;color:#d4d4d4;font:15px/1.6 Consolas,monospace">
    <div style="background:#2d2d2d;color:#aaa;padding:8px 14px;font:13px Segoe UI">${esc(title)}</div>
    <pre style="padding:14px 18px;margin:0;white-space:pre-wrap">${esc(text).replace(esc(mark), `<span style="background:#b8382b;color:#fff;padding:1px 3px;border-radius:3px">${esc(mark)}</span>`)}</pre>`);

  await page.goto(APP); await caption('A normal notes app…'); await hold(2.2);
  const js = await (await fetch(`${APP}/app.js`)).text();
  const key = js.match(/"([A-Za-z0-9]{30,})"/)[1];
  const masked = js.replace(key, `${key.slice(0, 4)}${'•'.repeat(12)}`);
  await viewText(`${APP}/app.js  (sent to every visitor)`, masked, `${key.slice(0, 4)}${'•'.repeat(12)}`);
  await caption('…that ships its API key to every visitor.', true); await hold(2.6);
  const api = await (await fetch(`${APP}/api/notes`)).text();
  await viewText(`${APP}/api/notes  (no login)`, JSON.stringify(JSON.parse(api), null, 2), 'Door code for the office is 4471');
  await caption("Anyone can read everyone's notes. No login.", true); await hold(2.6);
  await page.setContent(reportHtml(readFileSync('leak-check-report.md', 'utf8').split('## What to do')[0]));
  await caption('Leak Check finds all five, and says what to fix first.'); await hold(3.4);
  await hold(0.1);   // ffmpeg's concat needs the last frame listed twice
  await page.close();

  writeFileSync(join(frames, 'list.txt'), list.join('\n'));
  const r = spawnSync(process.env.FFMPEG || 'ffmpeg', ['-y', '-f', 'concat', '-safe', '0', '-i', join(frames, 'list.txt'),
    '-vf', 'fps=10,scale=760:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer:bayer_scale=4',
    join(media, 'demo.gif')], { stdio: 'ignore' });
  rmSync(frames, { recursive: true, force: true });
  if (r.status !== 0) throw new Error('ffmpeg failed to make demo.gif');
}

const browser = await chromium.launch({ channel: 'msedge' });
await shot(browser, readFileSync(join(here, 'src', 'banner.html'), 'utf8'), 'banner.png', 1280);
await shot(browser, mapHtml(findings), 'leak-map.png', 1248);
await shot(browser, reportHtml(readFileSync('leak-check-report.md', 'utf8')), 'report.png', 956);
await demoGif(browser);
await browser.close();
console.log('wrote docs/media/banner.png, leak-map.png, report.png, demo.gif');
