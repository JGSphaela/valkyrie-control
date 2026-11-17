/**
 * Zero-dependency localhost-only static dev server for `tauri dev` (`127.0.0.1:1420`).
 */
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const host = '127.0.0.1';
const port = Number(process.env.PORT || 1420);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
};

const ALLOWED_ROOT_FILES = new Set(['index.html', 'app.css']);
const ALLOWED_TOP_DIRS = new Set(['js', 'assets']);

function resolveSafeStaticPath(urlPath) {
  let pathname;
  try {
    pathname = decodeURIComponent(String(urlPath || '/').split('?')[0].split('#')[0]);
  } catch {
    return null;
  }

  if (pathname.includes('\0')) return null;
  if (pathname === '/') pathname = '/index.html';

  const normalized = path.posix.normalize(pathname);
  if (normalized.startsWith('/..') || normalized.includes('/../')) {
    return null;
  }

  const rel = normalized.replace(/^\/+/, '');
  if (!rel) return path.join(repoRoot, 'index.html');

  const topSegment = rel.split('/')[0];
  if (!ALLOWED_ROOT_FILES.has(rel) && !ALLOWED_TOP_DIRS.has(topSegment)) {
    return null;
  }

  const candidate = path.resolve(repoRoot, rel);
  const rootPrefix = repoRoot.endsWith(path.sep) ? repoRoot : `${repoRoot}${path.sep}`;
  if (candidate !== repoRoot && !candidate.startsWith(rootPrefix)) {
    return null;
  }

  return candidate;
}

const server = http.createServer((req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Method Not Allowed');
    return;
  }

  const filePath = resolveSafeStaticPath(req.url);
  if (!filePath) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Forbidden');
    return;
  }

  fs.stat(filePath, (statErr, stats) => {
    if (statErr || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': stats.size,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });

    if (req.method === 'HEAD') {
      res.end();
      return;
    }

    const stream = fs.createReadStream(filePath);
    stream.on('error', () => {
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      }
      res.end('Internal Server Error');
    });
    stream.pipe(res);
  });
});

server.listen(port, host, () => {
  console.log(`Valkyrie Control dev server listening on http://${host}:${port}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
