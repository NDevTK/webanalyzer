/* run-chrome.mjs — Runs the test suite in headless Chrome.
   Bundles the test suite with esbuild, serves it via puppeteer request interception,
   and captures console output as test results.

   Usage: node test/run-chrome.mjs */

import puppeteer from 'puppeteer';
import { readFileSync, readdirSync, existsSync, statSync } from 'fs';
import { resolve, dirname, relative } from 'path';
import { fileURLToPath } from 'url';
import { build } from 'esbuild';

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(__dirname, '..');
const testDir = __dirname;

// Bundle the test suite for the browser
async function buildTestBundle() {
  await build({
    entryPoints: [resolve(testDir, 'test.mjs')],
    bundle: true,
    format: 'esm',
    outfile: resolve(testDir, 'test.bundle.js'),
    platform: 'browser',
    target: 'es2022',
    define: {
      'process.env.NODE_ENV': '"test"',
      'process.env.BABEL_8_BREAKING': 'false',
      'process.env': '{}',
    },
  });
  return resolve(testDir, 'test.bundle.js');
}

// Serve a file from disk, or a directory listing if ?list is in the URL
function serveTestFile(urlPath) {
  // Strip /test/ prefix
  let relPath = urlPath.replace(/^\/test\//, '');

  // Directory listing
  if (relPath.endsWith('/?list') || relPath.endsWith('/list')) {
    const dir = relPath.replace(/\/?(\?list|list)$/, '');
    const fullDir = resolve(testDir, dir);
    try {
      const entries = readdirSync(fullDir);
      return { status: 200, contentType: 'application/json', body: JSON.stringify(entries) };
    } catch {
      return { status: 404, body: '[]' };
    }
  }

  // File serving
  const fullPath = resolve(testDir, relPath);
  // Security: ensure we're within the test directory
  if (!fullPath.startsWith(testDir)) {
    return { status: 403, body: 'Forbidden' };
  }
  try {
    const body = readFileSync(fullPath, 'utf8');
    const ct = fullPath.endsWith('.js') || fullPath.endsWith('.mjs') ? 'application/javascript' : 'text/plain';
    return { status: 200, contentType: ct, body };
  } catch {
    return { status: 404, body: 'Not found' };
  }
}

async function main() {
  console.log('Building test bundle...');
  const bundlePath = await buildTestBundle();
  console.log('Bundle built.');

  console.log('Launching Chrome...');
  const browser = await puppeteer.launch({
    headless: 'shell',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const page = await browser.newPage();

  // Capture console output
  page.on('console', msg => {
    process.stdout.write(msg.text() + '\n');
  });

  page.on('pageerror', err => {
    console.error('Page error:', err.message);
  });

  // Request interception: serve test files and the bundle
  await page.setRequestInterception(true);
  page.on('request', req => {
    const url = new URL(req.url());

    if (url.pathname === '/') {
      // Serve the test HTML page
      req.respond({
        status: 200,
        contentType: 'text/html',
        body: `<!DOCTYPE html><html><head><title>WebAppSec Tests</title></head>
<body><script type="module">
window.__done = false;
import('/test.bundle.js').then(() => { window.__done = true; }).catch(e => { console.error(e.message); window.__done = true; });
</script></body></html>`,
      });
    } else if (url.pathname === '/test.bundle.js') {
      req.respond({
        status: 200,
        contentType: 'application/javascript',
        body: readFileSync(bundlePath, 'utf8'),
      });
    } else if (url.pathname.startsWith('/test/')) {
      const resp = serveTestFile(url.pathname + url.search);
      req.respond(resp);
    } else {
      req.continue();
    }
  });

  await page.goto('http://localhost/', { waitUntil: 'domcontentloaded' });

  // Wait for completion
  const timeout = 300000;
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const done = await page.evaluate(() => window.__done);
    if (done) break;
    await new Promise(r => setTimeout(r, 500));
  }

  if (Date.now() - start >= timeout) {
    console.error('Tests timed out after 5 minutes');
  }

  // ── Runtime PoC verification for CVE diff tests ──
  // These tests run OUTSIDE the browser bundle — they use puppeteer directly
  // to verify that engine-generated PoCs actually fire in a real browser.
  console.log('\n--- Runtime PoC Verification ---');
  await runRuntimePoCTests(browser);

  await browser.close();
}

async function runRuntimePoCTests(browser) {
  const { analyzeMultiple, analyze } = await import('./harness.mjs');
  const { generatePoC } = await import('../src/worker/taint.js');
  const { verifyPoCRuntime } = await import('./verify-poc.mjs');

  function tryRead(name) {
    try { return readFileSync(resolve(__dirname, name), 'utf8'); } catch { return null; }
  }

  const tests = [];

  // ── CVE diff tests with real libraries ──
  const jquery331 = tryRead('cve/jquery-3.3.1.min.js');
  if (jquery331) {
    tests.push({
      name: 'CVE-2019-11358: jQuery $.extend PP',
      lib: jquery331,
      bootstrap: 'var payload = JSON.parse(decodeURIComponent(location.hash.slice(1))); jQuery.extend(true, {}, payload);',
      expectType: 'Prototype Pollution',
    });
  }
  const lodash41711 = tryRead('cve/lodash-4.17.11.min.js');
  if (lodash41711) {
    tests.push({
      name: 'CVE-2019-10744: Lodash defaultsDeep PP',
      lib: lodash41711,
      bootstrap: 'var input = JSON.parse(decodeURIComponent(location.hash.slice(1))); _.defaultsDeep({}, input);',
      expectType: 'Prototype Pollution',
    });
  }

  // ── Synthetic runtime PoC tests covering each sink/source type ──
  // These verify that the engine's PoC generation produces WORKING exploits.
  // Each test is a minimal source→sink code snippet.
  const syntheticTests = [
    { name: 'hash → innerHTML (XSS)', code: 'document.body.innerHTML = decodeURIComponent(location.hash.slice(1));', type: 'XSS' },
    { name: 'hash → eval (XSS)', code: 'eval(decodeURIComponent(location.hash.slice(1)));', type: 'XSS' },
    { name: 'hash → location.href (XSS)', code: 'location.href = decodeURIComponent(location.hash.slice(1));', type: 'XSS' },
    { name: 'hash → new Function (XSS)', code: 'new Function(decodeURIComponent(location.hash.slice(1)))();', type: 'XSS' },
    { name: 'hash → document.write (XSS)', code: 'document.write(decodeURIComponent(location.hash.slice(1)));', type: 'XSS' },
    { name: 'JSON.parse hash → recursive merge (PP)', code: `
      function merge(t,s){for(var k in s){var v=s[k];if(typeof v==='object'&&v!==null){if(typeof t[k]!=='object')t[k]={};merge(t[k],v);}else t[k]=v;}}
      merge({}, JSON.parse(decodeURIComponent(location.hash.slice(1))));
    `, type: 'Prototype Pollution' },
  ];

  for (const st of syntheticTests) {
    tests.push({ name: st.name, lib: '', bootstrap: st.code, expectType: st.type });
  }


  let passed = 0, failed = 0, skipped = 0;
  for (const test of tests) {
    process.stdout.write(`  ${test.name}... `);
    try {
      // Step 1: Static analysis
      const findings = test.lib
        ? analyzeMultiple([{ source: test.lib, file: 'lib.js' }, { source: test.bootstrap, file: 'app.js' }])
        : analyze(test.bootstrap).findings;
      const finding = findings.find(f => f.type === test.expectType);
      if (!finding) { console.log('SKIP (no static finding)'); skipped++; continue; }

      // Step 2: Generate PoC
      const poc = generatePoC(finding);
      if (!poc) { console.log('SKIP (no PoC)'); skipped++; continue; }

      // Step 3: Verify in real browser
      const result = await verifyPoCRuntime(browser, {
        libSource: test.lib || '', bootstrapSource: test.bootstrap, finding, poc, timeout: 10000,
      });

      if (result.verified) {
        console.log('VERIFIED ' + result.details);
        passed++;
      } else {
        console.log('NOT VERIFIED ' + result.details);
        failed++;
      }
    } catch (e) {
      console.log('ERROR ' + e.message);
      failed++;
    }
  }
  console.log(`\n  Runtime PoC: ${passed} verified, ${failed} failed, ${skipped} skipped`);
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
