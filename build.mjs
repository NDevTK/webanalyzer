import * as esbuild from 'esbuild';
import { cpSync, mkdirSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const watch = process.argv.includes('--watch');

mkdirSync(resolve(__dirname, 'dist'), { recursive: true });

// Bundle the worker (needs Babel)
const workerBuild = esbuild.build({
  entryPoints: [resolve(__dirname, 'src/worker/index.js')],
  bundle: true,
  format: 'iife',
  outfile: resolve(__dirname, 'dist/worker.bundle.js'),
  platform: 'browser',
  target: 'es2022',
  minify: false,
  sourcemap: false,
  define: {
    'process.env.NODE_ENV': '"production"',
    'process.env.BABEL_8_BREAKING': 'false',
    'process.env': '{}',
  },
});

// Copy static files
const staticFiles = [
  'manifest.json',
  'background.js',
  'offscreen/offscreen.html',
  'offscreen/offscreen.js',
  'popup/popup.html',
  'popup/popup.js',
  'popup/popup.css',
  'icons/icon16.png',
  'icons/icon48.png',
  'icons/icon128.png',
];

await workerBuild;

for (const file of staticFiles) {
  const src = resolve(__dirname, 'src', file);
  const dest = resolve(__dirname, 'dist', file);
  mkdirSync(dirname(dest), { recursive: true });
  cpSync(src, dest);
}

console.log('Build complete → dist/');

if (watch) {
  const ctx = await esbuild.context({
    entryPoints: [resolve(__dirname, 'src/worker/index.js')],
    bundle: true,
    format: 'iife',
    outfile: resolve(__dirname, 'dist/worker.bundle.js'),
    platform: 'browser',
    target: 'es2022',
    define: {
      'process.env.NODE_ENV': '"production"',
      'process.env.BABEL_8_BREAKING': 'false',
      'process.env': '{}',
    },
  });
  await ctx.watch();
  console.log('Watching for changes...');
}
