import puppeteer from 'puppeteer';
const browser = await puppeteer.launch({ headless: 'shell', args: ['--no-sandbox'] });
const page = await browser.newPage();
page.on('console', msg => console.log(msg.text()));
await page.evaluate(() => {
  // Discover URL properties: set a relative URL, check if the browser resolves it
  const PROBE_VALUE = 'relative-test-path';
  const tags = ['a', 'area', 'iframe', 'frame', 'embed', 'object', 'form', 'base',
                'script', 'img', 'video', 'audio', 'source', 'link', 'input'];

  for (const tag of tags) {
    let el;
    try { el = document.createElement(tag); } catch { continue; }

    // Walk setters
    let proto = el;
    while (proto && proto !== Object.prototype) {
      for (const [name, desc] of Object.entries(Object.getOwnPropertyDescriptors(proto))) {
        if (!desc.set) continue;
        try {
          el[name] = PROBE_VALUE;
          const val = el[name];
          // URL properties get resolved by the browser (contain the origin)
          if (typeof val === 'string' && val !== PROBE_VALUE && val.includes('://')) {
            const tt = typeof trustedTypes !== 'undefined' ? trustedTypes.getPropertyType(tag, name) : '';
            console.log(`${tag}.${name} → URL property (resolved to ${val}) TT=${tt || 'none'}`);
          }
          // Reset
          try { el[name] = ''; } catch {}
        } catch {}
      }
      proto = Object.getPrototypeOf(proto);
    }
  }
});
await browser.close();
