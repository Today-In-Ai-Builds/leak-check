// Notes: the demo app Leak Check scans. It is deliberately leaky. Never deploy it.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

const root = join(import.meta.dirname, 'public');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
const port = Number(process.env.PORT || 4322);

// Everyone's notes. A real app would keep these in a database.
const notes = [
  { id: 1, owner: 'ada@example.test', text: 'Quarterly numbers look rough, do not share yet' },
  { id: 2, owner: 'grace@example.test', text: 'Door code for the office is 4471' },
  { id: 3, owner: 'alan@example.test', text: 'Interview feedback: strong yes for the backend role' },
];

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/api/notes') {
    // Meant to return the signed-in user's notes. Nobody wired up the login check.
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify(notes));
  }
  const path = normalize(url.pathname).replace(/^[/\\]+/, '');
  const file = join(root, path || 'index.html');
  if (!file.startsWith(root)) return res.writeHead(403).end();
  let body;
  try {
    body = await readFile(file);
  } catch {
    return res.writeHead(404).end('not found');
  }
  res.writeHead(200, { 'content-type': types[extname(file)] || 'text/plain' }).end(body);
}).listen(port, '127.0.0.1', () => console.log(`notes app on http://127.0.0.1:${port}`));
