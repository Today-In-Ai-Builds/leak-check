// The Leak Check report. It prints previews of secrets, never the secrets.

const MAX_TEXT = 600;

// AI text is not trusted as markup: no HTML, links or @mentions, bounded length.
export function clean(text) {
  const s = String(text ?? '')
    .replace(/<[^>]*>/g, '')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/https?:\/\/\S+/g, '[link removed]')
    .replace(/(^|[\s(])@(?=[\w-])/g, '$1@​')   // @mentions only: lodash@latest stays copyable
    .replace(/\s+/g, ' ').trim();
  return s.length > MAX_TEXT ? `${s.slice(0, MAX_TEXT)}…` : s;
}

// Repo-controlled names (files, JSON keys, packages) as a code span they cannot escape.
export function code(v) {
  return '`' + String(v ?? '').replace(/`/g, "'").replace(/[\r\n]+/g, ' ').slice(0, 200) + '`';
}

export function verdict({ secrets = [], client = [], endpoints = [], dependencies = [] }) {
  return secrets.length || client.length || endpoints.some((e) => e.open) || dependencies.length
    ? 'leaking' : 'clean';
}

export function renderReport(r) {
  const { secrets = [], client = [], endpoints = [], dependencies = [], explained } = r;
  const inCode = secrets.filter((s) => s.where === 'code');
  const inHistory = secrets.filter((s) => s.where === 'history');
  const open = endpoints.filter((e) => e.open);
  const lines = [verdict(r) === 'leaking' ? '# 🚨 Leak Check: leaking' : '# ✅ Leak Check: nothing found', ''];

  if (explained?.summary) lines.push(`> ${clean(explained.summary)}`, '');

  const section = (title, items, fmt) => {
    if (!items.length) return;
    lines.push(`## ${title}`, '', ...items.map(fmt), '');
  };
  section('🌐 Shipped to every visitor', client,
    (c) => `- ${code(c.file)} line ${c.line}: a ${code(c.rule)} (${code(c.preview)}) is in the page code anyone can download.`);
  section('🔑 In your code', inCode,
    (s) => `- ${code(`${s.file}:${s.line}`)}: ${code(s.rule)} (${code(s.preview)}).`);
  section('🕰️ Deleted, but still in git history', inHistory,
    (s) => `- ${code(`${s.file}:${s.line}`)} in commit ${code(s.commit)}: ${code(s.rule)} (${code(s.preview)}). ` +
      'Deleting the file did not remove it: anyone who clones the repo can read it.');
  section('🚪 Answers without a login', open,
    (e) => `- ${code(`GET ${e.path}`)} returned ${e.records} record(s) with fields ${e.fields.map((f) => code(f)).join(', ')} to a visitor who never signed in.`);
  section('📦 Dependencies with known vulnerabilities', dependencies,
    (d) => `- ${code(`${d.package}@${d.version}`)}: ${d.advisories.length} advisories (${d.advisories.slice(0, 3).map((a) => code(a.id)).join(', ')}${d.advisories.length > 3 ? ', …' : ''}).`);

  if (explained?.findings?.length) {
    lines.push('## What to do, in order', '');
    explained.findings.forEach((f, i) => lines.push(`${i + 1}. **${clean(f.title)}**: ${clean(f.fix)}`));
    lines.push('');
  }
  if (secrets.length || client.length) {
    lines.push('**Rotate every leaked key and password first.** Removing it from the code, or even rewriting git history, ' +
      'does not help once it has been pushed or served: assume someone has it.', '');
  }
  lines.push('---', 'Leak Check ran [gitleaks](https://github.com/gitleaks/gitleaks) on your code, your git history and the ' +
    'page code your app serves, [osv-scanner](https://github.com/google/osv-scanner) on your dependencies, and probed ' +
    'your own local app for endpoints that answer without a login.');
  return lines.join('\n');
}
