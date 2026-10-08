// Looks at your running app the way a visitor's browser does: the page code it
// downloads, and whether an API answers without a login. Local apps only:
// scanning someone else's site without permission is not something this does.

const LOCAL = /^(localhost|127\.0\.0\.1|\[::1\]|[\w-]+\.localhost)$/i;

function local(base) {
  const url = new URL(base);
  if (!LOCAL.test(url.hostname)) {
    throw new Error(`Leak Check only scans your own app running locally (got ${url.hostname}).`);
  }
  return url;
}

const SCRIPT = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;

async function get(url) {
  try {
    return await fetch(url, { redirect: 'manual', credentials: 'omit' });
  } catch {
    throw new Error(`could not reach ${url.origin}: is your app running? (for the demo: npm run demo-app)`);
  }
}

const INLINE = /<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;

export async function clientScripts(base) {
  const origin = local(base);
  const page = await get(origin);
  // An error page has no scripts; reporting it as clean would be a lie.
  if (!page.ok) throw new Error(`${origin.origin} answered ${page.status}: the page code was NOT checked`);
  const html = await page.text();
  const out = [];
  let n = 0;
  for (const [, body] of html.matchAll(INLINE)) {
    if (body.trim()) out.push({ path: `/ (inline script ${++n})`, body });
  }
  for (const [, src] of html.matchAll(SCRIPT)) {
    const url = new URL(src, origin);
    if (url.origin !== origin.origin) continue;           // other sites' scripts are not yours to scan
    const res = await get(url);
    if (res.ok) out.push({ path: url.pathname, body: await res.text() });
  }
  return out;
}

export async function probeEndpoint(base, path) {
  // A plain "/path" only: "http://169.254.169.254/..." or "//host/x" would
  // replace the host and walk straight past the local-only check.
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) {
    throw new Error(`probe entries must be a plain path like /api/notes (got ${JSON.stringify(path)})`);
  }
  const url = new URL(path, local(base));
  local(url);
  const res = await get(url);
  if (!res.ok) return { path, open: false, status: res.status };
  let data;
  try { data = await res.json(); } catch { return { path, open: false, status: res.status }; }
  const rows = Array.isArray(data) ? data : [data];
  const first = rows.find((r) => r && typeof r === 'object') ?? {};
  return { path, open: rows.length > 0 && Object.keys(first).length > 0, status: res.status,
           records: rows.length, fields: Object.keys(first).sort() };
}
