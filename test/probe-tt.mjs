import puppeteer from 'puppeteer';
const browser = await puppeteer.launch({ headless: 'shell', args: ['--no-sandbox'] });
const page = await browser.newPage();
page.on('console', msg => console.log(msg.text()));
await page.evaluate(() => {
  const hasTT = typeof trustedTypes !== 'undefined' && typeof trustedTypes.getPropertyType === 'function';
  console.log('trustedTypes available:', hasTT);
  if (hasTT) {
    console.log('div:innerHTML →', trustedTypes.getPropertyType('div', 'innerHTML'));
    console.log('script:src →', trustedTypes.getPropertyType('script', 'src'));
    console.log('script:text →', trustedTypes.getPropertyType('script', 'text'));
    console.log('script:textContent →', trustedTypes.getPropertyType('script', 'textContent'));
    console.log('iframe:srcdoc →', trustedTypes.getPropertyType('iframe', 'srcdoc'));
    console.log('iframe:src →', trustedTypes.getPropertyType('iframe', 'src'));
    console.log('a:href →', trustedTypes.getPropertyType('a', 'href'));
    console.log('img:src →', trustedTypes.getPropertyType('img', 'src'));
    console.log('embed:src →', trustedTypes.getPropertyType('embed', 'src'));
    console.log('object:data →', trustedTypes.getPropertyType('object', 'data'));
  }
});
await browser.close();
