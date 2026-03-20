/**
 * verify-poc.mjs — End-to-end runtime PoC verification.
 *
 * Architecture:
 * 1. HTTP server serves the VICTIM PAGE (library + bootstrap — NO attacker content)
 * 2. The PoC vector determines the ATTACKER ACTION (navigate to crafted URL, send postMessage, etc.)
 * 3. Puppeteer executes the attacker action and checks for the exploit side effect
 *
 * The victim page is served as-is — the attacker input arrives through the browser's
 * native mechanisms (URL, postMessage, localStorage), exactly like a real attack.
 *
 * XSS: detected via page.on('dialog') — real alert() from the victim page
 * PP: detected via page.evaluate(() => ({}).polluted) — real prototype pollution
 */

import http from 'http';

/**
 * @param {import('puppeteer').Browser} browser
 * @param {Object} opts
 * @param {string} opts.libSource - Vulnerable library source code
 * @param {string} opts.bootstrapSource - Victim's application code (reads source, writes to sink)
 * @param {Object} opts.finding - Finding from the taint engine
 * @param {Object} opts.poc - PoC from generatePoC(finding, pageUrl)
 * @param {number} [opts.timeout=5000]
 * @returns {Promise<{verified: boolean, details: string}>}
 */
export async function verifyPoCRuntime(browser, { libSource, bootstrapSource, finding, poc, timeout = 5000 }) {
  if (!poc?.vector) return { verified: false, details: 'No PoC vector generated' };

  // Start HTTP server serving the victim page
  const victimHTML = `<!DOCTYPE html>
<html><head><title>Victim Page</title></head>
<body>
<script>${libSource}<\/script>
<script>${bootstrapSource}<\/script>
</body></html>`;

  const { server, port } = await startServer(victimHTML);
  const pageUrl = `http://127.0.0.1:${port}`;

  try {
    const page = await browser.newPage();
    try {
      if (finding.type === 'Prototype Pollution') {
        return await verifyPP(page, pageUrl, poc, timeout);
      } else {
        return await verifyXSS(page, pageUrl, poc, timeout);
      }
    } finally {
      await page.close();
    }
  } finally {
    server.close();
  }
}

function startServer(html) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
    server.on('error', reject);
  });
}

/**
 * Verify PP:
 * 1. Navigate to the victim page with the crafted URL (hash contains the PP payload)
 * 2. The bootstrap code reads location.hash, parses JSON, calls the vulnerable merge
 * 3. Check if ({}).polluted === true after the page loads
 */
async function verifyPP(page, pageUrl, poc, timeoutMs) {
  // The PoC vector has the full delivery URL: pageUrl#encodedPayload
  // Replace the base URL with our local server
  const url = replaceBaseUrl(poc.vector, pageUrl);

  try {
    await page.goto(url, { waitUntil: 'load', timeout: timeoutMs });
    // Wait for async operations (setTimeout, Promise chains)
    await new Promise(r => setTimeout(r, 200));

    const polluted = await page.evaluate(() => ({}).polluted === true);
    return {
      verified: polluted,
      details: polluted
        ? 'PP CONFIRMED: ({}).polluted === true in real browser'
        : 'PP not triggered',
    };
  } catch (e) {
    return { verified: false, details: 'Error: ' + e.message };
  }
}

/**
 * Verify XSS:
 * 1. Navigate to the victim page with the crafted URL
 * 2. The bootstrap code reads the taint source and writes to the sink
 * 3. Detect alert() via page.on('dialog') — the REAL browser dialog
 */
async function verifyXSS(page, pageUrl, poc, timeoutMs) {
  return new Promise(async (resolve) => {
    let resolved = false;
    const timer = setTimeout(() => {
      if (!resolved) { resolved = true; resolve({ verified: false, details: 'XSS not triggered within ' + timeoutMs + 'ms' }); }
    }, timeoutMs);

    page.on('dialog', async (dialog) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        const msg = dialog.message();
        await dialog.dismiss();
        resolve({ verified: true, details: `XSS CONFIRMED: alert("${msg}") in real browser` });
      }
    });

    const url = replaceBaseUrl(poc.vector, pageUrl);

    try {
      await page.goto(url, { waitUntil: 'load', timeout: timeoutMs });

      // For postMessage vectors: the vector is a JS script that sends the message
      // Execute it in the page context AFTER the page loads
      if (poc.vector && !poc.vector.startsWith('http')) {
        await page.evaluate((script) => { eval(script); }, poc.vector);
      }
    } catch (e) {
      if (!resolved) { resolved = true; clearTimeout(timer); resolve({ verified: false, details: 'Error: ' + e.message }); }
    }
  });
}

/**
 * Replace the base URL in a PoC vector with the local server URL.
 * Preserves the path, query, and hash from the original vector.
 */
function replaceBaseUrl(vector, localUrl) {
  if (!vector) return localUrl;

  // If vector is not a URL (e.g., postMessage script), return the local URL
  if (!vector.startsWith('http')) return localUrl;

  try {
    const parsed = new URL(vector);
    return `${localUrl}${parsed.pathname === '/' ? '' : parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    // URL parsing failed — try to extract hash/query manually
    const hashIdx = vector.indexOf('#');
    if (hashIdx >= 0) return `${localUrl}/${vector.slice(hashIdx)}`;
    return localUrl;
  }
}
