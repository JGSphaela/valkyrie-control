/**
 * Stages the static web frontend into `dist-web/` for Tauri's `frontendDist`
 * without altering the repository root used by GitHub Pages.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const distDir = path.join(repoRoot, 'dist-web');

const STATIC_FILES = ['index.html', 'app.css'];
const STATIC_DIRS = ['js', 'assets'];

fs.rmSync(distDir, { recursive: true, force: true });
fs.mkdirSync(distDir, { recursive: true });

for (const fileName of STATIC_FILES) {
  const srcPath = path.join(repoRoot, fileName);
  const dstPath = path.join(distDir, fileName);
  if (!fs.existsSync(srcPath)) {
    throw new Error(`Required static file missing: ${fileName}`);
  }
  fs.copyFileSync(srcPath, dstPath);
}

for (const dirName of STATIC_DIRS) {
  const srcDir = path.join(repoRoot, dirName);
  const dstDir = path.join(distDir, dirName);
  if (!fs.existsSync(srcDir)) {
    throw new Error(`Required static directory missing: ${dirName}`);
  }
  fs.cpSync(srcDir, dstDir, { recursive: true });
}

console.log(`Staged static web assets into ${path.relative(repoRoot, distDir)}/`);
