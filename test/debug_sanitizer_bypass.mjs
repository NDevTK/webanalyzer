import { analyzeMultiple } from './harness.mjs';

// Simulates a real-world pattern: library has a "sanitizer" that doesn't
// actually sanitize properly. Both vulnerable and patched versions should
// still produce XSS findings because .replace() is not in our SANITIZERS list
// — only DOMPurify.sanitize, encodeURIComponent, etc. are trusted sanitizers.

const vulnLib = `
  (function(root) {
    function SafeHTML(input) {
      return input.replace(/<script/gi, '');
    }
    root.SafeHTML = SafeHTML;
  })(window);
`;

const boot = 'document.body.innerHTML = SafeHTML(location.hash.slice(1));';

const f1 = analyzeMultiple([
  { source: vulnLib, file: 'safehtml.js' },
  { source: boot, file: 'app.js' },
]);
console.log('Vulnerable lib:', f1.length, 'findings');
for (const f of f1) console.log('  ' + f.type + ' → ' + f.sink?.fingerprint);
