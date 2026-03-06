/* test/test.mjs — Unified test suite for the taint analysis engine.
   Covers positive detections, negative (safe) patterns, and baseline library scans. */

import { readFileSync, readdirSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { analyze, analyzeMultiple } from './harness.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const libsDir = resolve(__dirname, 'libs');

let passed = 0, failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL  ${name}`);
    console.log(`        ${e.message}`);
  }
}

function expect(findings) {
  const obj = {
    toHaveType(type) {
      const found = findings.some(f => f.type === type);
      if (!found) throw new Error(`Expected finding of type "${type}" but got: [${findings.map(f => f.type).join(', ') || 'none'}]`);
    },
    toHaveCount(n) {
      if (findings.length !== n) throw new Error(`Expected ${n} findings, got ${findings.length}: [${findings.map(f => f.type + ':' + f.title).join('; ')}]`);
    },
    toHaveAtLeast(n) {
      if (findings.length < n) throw new Error(`Expected at least ${n} findings, got ${findings.length}`);
    },
    toBeEmpty() {
      if (findings.length > 0) throw new Error(`Expected no findings, got ${findings.length}: [${findings.map(f => f.type + ': ' + f.title).join('; ')}]`);
    },
    notToHaveType(type) {
      const found = findings.some(f => f.type === type);
      if (found) throw new Error(`Expected no "${type}" finding but got one: ${findings.filter(f => f.type === type).map(f => f.title).join('; ')}`);
    },
    get not() {
      return {
        toHaveType(type) { obj.notToHaveType(type); },
      };
    },
  };
  return obj;
}


// ╔═══════════════════════════════════════════════════════╗
// ║  POSITIVE DETECTIONS — should find vulnerabilities    ║
// ╚═══════════════════════════════════════════════════════╝


// ─── XSS: innerHTML ─────────────────────────────────────

console.log('\n--- XSS: innerHTML ---');

test('location.hash → innerHTML (direct)', () => {
  const { findings } = analyze(`
    document.getElementById('x').innerHTML = location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.search → variable → innerHTML', () => {
  const { findings } = analyze(`
    var q = location.search;
    document.getElementById('x').innerHTML = q;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → substring → innerHTML', () => {
  const { findings } = analyze(`
    var h = location.hash.substring(1);
    document.getElementById('out').innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.search → split → join → innerHTML', () => {
  const { findings } = analyze(`
    var parts = location.search.split('&');
    var result = parts.join('<br>');
    document.getElementById('out').innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → template literal → innerHTML', () => {
  const { findings } = analyze(`
    var h = location.hash;
    document.getElementById('out').innerHTML = \`<div>\${h}</div>\`;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → concat → innerHTML', () => {
  const { findings } = analyze(`
    var h = location.hash;
    document.getElementById('out').innerHTML = '<span>' + h + '</span>';
  `);
  expect(findings).toHaveType('XSS');
});

test('document.referrer → innerHTML', () => {
  const { findings } = analyze(`
    document.getElementById('ref').innerHTML = document.referrer;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.URL → innerHTML', () => {
  const { findings } = analyze(`
    var u = document.URL;
    document.body.innerHTML = u;
  `);
  expect(findings).toHaveType('XSS');
});

test('window.name → innerHTML', () => {
  const { findings } = analyze(`
    document.getElementById('x').innerHTML = window.name;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.cookie → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.cookie;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.href → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = location.href;
  `);
  expect(findings).toHaveType('XSS');
});

test('window.location.href → innerHTML via variable', () => {
  const { findings } = analyze(`
    var url = window.location.href;
    document.body.innerHTML = url;
  `);
  expect(findings).toHaveType('XSS');
});

test('innerHTML += tainted', () => {
  const { findings } = analyze(`
    document.body.innerHTML += location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.host → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = location.host;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hostname → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = location.hostname;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: eval / Function / document.write ──────────────

console.log('\n--- XSS: eval / Function / document.write ---');

test('location.hash → eval', () => {
  const { findings } = analyze(`
    eval(location.hash.substring(1));
  `);
  expect(findings).toHaveType('XSS');
});

test('location.search → new Function()', () => {
  const { findings } = analyze(`
    var code = location.search.substring(1);
    var fn = new Function(code);
    fn();
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → document.write', () => {
  const { findings } = analyze(`
    document.write(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → setTimeout(string)', () => {
  const { findings } = analyze(`
    var h = location.hash.slice(1);
    setTimeout(h, 100);
  `);
  expect(findings).toHaveType('XSS');
});

test('location.search → document.writeln', () => {
  const { findings } = analyze(`
    document.writeln(location.search);
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → setInterval(string)', () => {
  const { findings } = analyze(`
    var code = location.hash.slice(1);
    setInterval(code, 1000);
  `);
  expect(findings).toHaveType('XSS');
});

test('binary + in sink argument: eval("code" + tainted)', () => {
  const { findings } = analyze(`
    var h = location.hash.slice(1);
    eval("var x = " + h);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: other sinks ──────────────────────────────────

console.log('\n--- XSS: insertAdjacentHTML / outerHTML / srcdoc ---');

test('location.hash → insertAdjacentHTML', () => {
  const { findings } = analyze(`
    var data = location.hash.slice(1);
    document.body.insertAdjacentHTML('beforeend', data);
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → outerHTML', () => {
  const { findings } = analyze(`
    document.getElementById('x').outerHTML = location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.search → iframe srcdoc', () => {
  const { findings } = analyze(`
    var q = location.search;
    document.querySelector('iframe').srcdoc = q;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → DOMParser.parseFromString', () => {
  const { findings } = analyze(`
    var parser = new DOMParser();
    var doc = parser.parseFromString(location.hash, 'text/html');
  `);
  expect(findings).toHaveType('XSS');
});

test('template literal directly in innerHTML assignment', () => {
  const { findings } = analyze(`
    document.body.innerHTML = \`<div>\${location.hash}</div>\`;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: jQuery sinks ─────────────────────────────────

console.log('\n--- XSS: jQuery sinks ---');

test('location.hash → $.html()', () => {
  const { findings } = analyze(`
    var h = location.hash;
    $('#output').html(h);
  `);
  expect(findings).toHaveType('XSS');
});

test('location.search → jQuery.append()', () => {
  const { findings } = analyze(`
    var data = location.search;
    jQuery('#list').append(data);
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → $.prepend()', () => {
  const { findings } = analyze(`
    $('#container').prepend(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: javascript: URI injection ────────────────────

console.log('\n--- XSS: javascript: URI injection ---');

test('location.hash → location.href', () => {
  const { findings } = analyze(`
    location.href = location.hash.substring(1);
  `);
  expect(findings).toHaveType('XSS');
});

test('URLSearchParams → window.open', () => {
  const { findings } = analyze(`
    var url = new URLSearchParams(location.search).get('next');
    window.open(url);
  `);
  expect(findings).toHaveType('XSS');
});

test('location.search → location.assign', () => {
  const { findings } = analyze(`
    var next = location.search.split('url=')[1];
    location.assign(next);
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → window.location.href (XSS)', () => {
  const { findings } = analyze(`
    var next = location.hash.slice(1);
    window.location.href = next;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.search → window.location.assign (XSS)', () => {
  const { findings } = analyze(`
    var url = location.search.split('goto=')[1];
    window.location.assign(url);
  `);
  expect(findings).toHaveType('XSS');
});

test('location.search → window.location.replace (XSS)', () => {
  const { findings } = analyze(`
    var url = location.search.split('url=')[1];
    window.location.replace(url);
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → location.replace', () => {
  const { findings } = analyze(`
    var next = location.hash.substring(1);
    location.replace(next);
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted value → location (direct assignment)', () => {
  const { findings } = analyze(`
    var url = location.search.split('redirect=')[1];
    window.location = url;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.cookie → location.href (redirect)', () => {
  const { findings } = analyze(`
    var next = document.cookie.split('redirect=')[1];
    location.href = next;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: interprocedural ──────────────────────────────

console.log('\n--- XSS: interprocedural ---');

test('taint through function call', () => {
  const { findings } = analyze(`
    function renderContent(html) {
      document.getElementById('out').innerHTML = html;
    }
    var data = location.hash;
    renderContent(data);
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through function return', () => {
  const { findings } = analyze(`
    function getData() {
      return location.hash.substring(1);
    }
    document.getElementById('out').innerHTML = getData();
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through arrow function', () => {
  const { findings } = analyze(`
    const getParam = () => location.search;
    document.body.innerHTML = getParam();
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through two levels of function calls', () => {
  const { findings } = analyze(`
    function getInput() {
      return location.hash.slice(1);
    }
    function render(content) {
      document.getElementById('app').innerHTML = content;
    }
    render(getInput());
  `);
  expect(findings).toHaveType('XSS');
});

test('3-level deep call chain', () => {
  const { findings } = analyze(`
    function getInput() {
      return location.hash.slice(1);
    }
    function processInput(input) {
      return '<div>' + input + '</div>';
    }
    function renderOutput(html) {
      document.body.innerHTML = html;
    }
    renderOutput(processInput(getInput()));
  `);
  expect(findings).toHaveType('XSS');
});

test('4-level deep call chain', () => {
  const { findings } = analyze(`
    function readHash() { return location.hash; }
    function decode(h) { return decodeURIComponent(h); }
    function wrap(s) { return '<p>' + s + '</p>'; }
    function display(html) { document.body.innerHTML = html; }
    display(wrap(decode(readHash())));
  `);
  expect(findings).toHaveType('XSS');
});

test('5-level deep call chain', () => {
  const { findings } = analyze(`
    function a() { return location.hash; }
    function b(x) { return x.slice(1); }
    function c(x) { return '<b>' + x + '</b>'; }
    function d(x) { return '<div>' + x + '</div>'; }
    function e(html) { document.body.innerHTML = html; }
    e(d(c(b(a()))));
  `);
  expect(findings).toHaveType('XSS');
});

test('closure captures tainted variable', () => {
  const { findings } = analyze(`
    var h = location.hash;
    function render() {
      document.body.innerHTML = h;
    }
    render();
  `);
  expect(findings).toHaveType('XSS');
});

test('factory function returns closure with taint', () => {
  const { findings } = analyze(`
    function makeRenderer(content) {
      return function() {
        document.body.innerHTML = content;
      };
    }
    var render = makeRenderer(location.hash);
    render();
  `);
  expect(findings).toHaveType('XSS');
});

test('factory returns arrow closure with taint', () => {
  const { findings } = analyze(`
    function createHandler(data) {
      return () => {
        document.body.innerHTML = data;
      };
    }
    var handler = createHandler(location.hash);
    handler();
  `);
  expect(findings).toHaveType('XSS');
});

test('factory returns object with methods (module pattern)', () => {
  const { findings } = analyze(`
    function createWidget(content) {
      return {
        render: function() {
          document.body.innerHTML = content;
        }
      };
    }
    var widget = createWidget(location.hash);
    widget.render();
  `);
  expect(findings).toHaveType('XSS');
});

test('IIFE module pattern with methods', () => {
  const { findings } = analyze(`
    var myModule = (function() {
      function render(html) {
        document.body.innerHTML = html;
      }
      return { render: render };
    })();
    myModule.render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('function passed as callback receives taint', () => {
  const { findings } = analyze(`
    function doRender(fn) {
      fn(location.hash);
    }
    doRender(function(html) {
      document.body.innerHTML = html;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('rest parameter receives taint', () => {
  const { findings } = analyze(`
    function render(...args) {
      document.body.innerHTML = args[0];
    }
    render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('function with default param from tainted source', () => {
  const { findings } = analyze(`
    function render(html = location.hash) {
      document.body.innerHTML = html;
    }
    render();
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: ES6 classes ──────────────────────────────────

console.log('\n--- XSS: ES6 classes ---');

test('class method receives tainted arg → innerHTML', () => {
  const { findings } = analyze(`
    class Renderer {
      render(html) {
        document.body.innerHTML = html;
      }
    }
    var r = new Renderer();
    r.render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('class with tainted constructor property → method sinks it', () => {
  const { findings } = analyze(`
    class Widget {
      constructor(content) {
        this.content = content;
      }
      render() {
        document.body.innerHTML = this.content;
      }
    }
    var w = new Widget(location.hash);
    w.render();
  `);
  expect(findings).toHaveType('XSS');
});

test('static class method with tainted arg → innerHTML', () => {
  const { findings } = analyze(`
    class Util {
      static inject(html) {
        document.body.innerHTML = html;
      }
    }
    Util.inject(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('constructor function + prototype method', () => {
  const { findings } = analyze(`
    function Widget(html) {
      this.html = html;
    }
    Widget.prototype.render = function() {
      document.body.innerHTML = this.html;
    };
    var w = new Widget(location.hash);
    w.render();
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: control flow ─────────────────────────────────

console.log('\n--- XSS: control flow ---');

test('taint through if/else branches', () => {
  const { findings } = analyze(`
    var data;
    if (Math.random() > 0.5) {
      data = location.hash;
    } else {
      data = location.search;
    }
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through ternary', () => {
  const { findings } = analyze(`
    var x = true ? location.hash : location.search;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('ternary with both branches tainted → innerHTML', () => {
  const { findings } = analyze(`
    var x = Math.random() > 0.5 ? location.hash : location.search;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through for loop', () => {
  const { findings } = analyze(`
    var params = location.search.split('&');
    var result = '';
    for (var i = 0; i < params.length; i++) {
      result += params[i];
    }
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through while loop', () => {
  const { findings } = analyze(`
    var parts = location.search.split('&');
    var i = 0;
    var result = '';
    while (i < parts.length) {
      result += parts[i];
      i++;
    }
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through do-while loop', () => {
  const { findings } = analyze(`
    var data = location.hash;
    var output = '';
    do {
      output = data;
    } while (false);
    document.body.innerHTML = output;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through try/catch', () => {
  const { findings } = analyze(`
    var data;
    try {
      data = decodeURIComponent(location.hash.slice(1));
    } catch(e) {
      data = location.hash.slice(1);
    }
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through switch case', () => {
  const { findings } = analyze(`
    var h = location.hash;
    var result;
    switch (h) {
      case '#admin':
        result = h;
        break;
      default:
        result = h;
    }
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through nested if-else', () => {
  const { findings } = analyze(`
    var h = location.hash;
    var output;
    if (h.length > 5) {
      if (h.startsWith('#a')) {
        output = h;
      } else {
        output = h.slice(1);
      }
    } else {
      output = h;
    }
    document.body.innerHTML = output;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint survives catch reassignment from tainted source', () => {
  const { findings } = analyze(`
    var data;
    try {
      data = JSON.parse(location.hash.slice(1));
    } catch (e) {
      data = location.hash;
    }
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: destructuring / spread / array ───────────────

console.log('\n--- XSS: destructuring / spread / array ---');

test('taint through destructuring', () => {
  const { findings } = analyze(`
    var url = new URL(location.href);
    var { searchParams } = url;
    var val = searchParams.get('q');
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through array.map', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    var html = items.map(function(item) { return '<li>' + item + '</li>'; }).join('');
    document.getElementById('list').innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through spread into object', () => {
  const { findings } = analyze(`
    var params = { q: location.hash };
    var merged = { ...params };
    document.body.innerHTML = merged.q;
  `);
  expect(findings).toHaveType('XSS');
});

test('array destructuring from tainted split → innerHTML', () => {
  const { findings } = analyze(`
    var [first, second] = location.search.split('&');
    document.body.innerHTML = first;
  `);
  expect(findings).toHaveType('XSS');
});

test('array destructuring with rest from tainted → innerHTML', () => {
  const { findings } = analyze(`
    var [head, ...rest] = location.hash.split('/');
    document.body.innerHTML = rest.join('/');
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted value pushed to array → join → innerHTML', () => {
  const { findings } = analyze(`
    var items = [];
    items.push(location.hash);
    document.body.innerHTML = items.join('');
  `);
  expect(findings).toHaveType('XSS');
});

test('array with tainted element → pop → innerHTML', () => {
  const { findings } = analyze(`
    var arr = [location.hash, 'safe'];
    var item = arr.pop();
    document.body.innerHTML = item;
  `);
  expect(findings).toHaveType('XSS');
});

test('for...of over tainted array → innerHTML', () => {
  const { findings } = analyze(`
    var params = location.search.split('&');
    for (var p of params) {
      document.body.innerHTML += p;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('for...in over tainted object → innerHTML', () => {
  const { findings } = analyze(`
    var params = { q: location.hash };
    for (var key in params) {
      document.body.innerHTML = params[key];
    }
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: URLSearchParams / URL constructor ────────────

console.log('\n--- XSS: URLSearchParams / URL constructor ---');

test('URLSearchParams.get → innerHTML', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    var q = params.get('q');
    document.getElementById('out').innerHTML = q;
  `);
  expect(findings).toHaveType('XSS');
});

test('new URL(location.href).searchParams.get → innerHTML', () => {
  const { findings } = analyze(`
    var url = new URL(location.href);
    var q = url.searchParams.get('q');
    document.body.innerHTML = q;
  `);
  expect(findings).toHaveType('XSS');
});

test('new URLSearchParams(location.search) → get → innerHTML', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    document.body.innerHTML = params.get('name');
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: postMessage without origin check ─────────────

console.log('\n--- XSS: postMessage ---');

test('postMessage data → innerHTML (no origin check)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(event) {
      document.getElementById('output').innerHTML = event.data;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('postMessage data → eval (no origin check)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      eval(e.data);
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('window.onmessage = handler without origin check → innerHTML', () => {
  const { findings } = analyze(`
    window.onmessage = function(e) {
      document.body.innerHTML = e.data;
    };
  `);
  expect(findings).toHaveType('XSS');
});

test('self.onmessage = handler without origin check → eval', () => {
  const { findings } = analyze(`
    self.onmessage = function(event) {
      eval(event.data);
    };
  `);
  expect(findings).toHaveType('XSS');
});

test('addEventListener with named function reference', () => {
  const { findings } = analyze(`
    function handleMessage(event) {
      document.body.innerHTML = event.data;
    }
    window.addEventListener('message', handleMessage);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: localStorage / sessionStorage ────────────────

console.log('\n--- XSS: storage ---');

test('localStorage.getItem → innerHTML', () => {
  const { findings } = analyze(`
    var saved = localStorage.getItem('data');
    document.body.innerHTML = saved;
  `);
  expect(findings).toHaveType('XSS');
});

test('sessionStorage.getItem → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = sessionStorage.getItem('html');
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: additional sources ───────────────────────────

console.log('\n--- XSS: additional sources ---');

test('location.pathname → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = location.pathname;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.baseURI → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.baseURI;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.documentURI → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.documentURI;
  `);
  expect(findings).toHaveType('XSS');
});

test('window.location.hash → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = window.location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

test('window.location.search → innerHTML', () => {
  const { findings } = analyze(`
    var q = window.location.search;
    document.body.innerHTML = q;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.location.hash → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.location.hash;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: async/await ──────────────────────────────────

console.log('\n--- XSS: async/await ---');

test('await expression preserves taint', () => {
  const { findings } = analyze(`
    async function fetchData() {
      var url = location.hash.slice(1);
      var response = await fetch(url);
      var text = await response.text();
      document.body.innerHTML = text;
    }
    fetchData();
  `);
  expect(findings).toHaveType('XSS');
});

test('async arrow function with tainted return', () => {
  const { findings } = analyze(`
    const getHash = async () => location.hash;
    document.body.innerHTML = getHash();
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: IIFE patterns ────────────────────────────────

console.log('\n--- XSS: IIFE ---');

test('IIFE returning tainted value → innerHTML', () => {
  const { findings } = analyze(`
    var data = (function() { return location.hash; })();
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});

test('arrow IIFE returning tainted value → innerHTML', () => {
  const { findings } = analyze(`
    var data = (() => location.hash)();
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});

test('IIFE with tainted argument → sink inside', () => {
  const { findings } = analyze(`
    (function(input) {
      document.body.innerHTML = input;
    })(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: optional chaining / sequence ─────────────────

console.log('\n--- XSS: optional chaining / sequence ---');

test('location.hash → optional member → insertAdjacentHTML', () => {
  const { findings } = analyze(`
    var container = document.getElementById('app');
    container?.insertAdjacentHTML('beforeend', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('sequence expression: last value is tainted', () => {
  const { findings } = analyze(`
    var x = (0, location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: chained string methods ───────────────────────

console.log('\n--- XSS: chained methods ---');

test('location.search → split → join → trim → innerHTML', () => {
  const { findings } = analyze(`
    var q = location.search.slice(1).split('&').join(', ').trim();
    document.body.innerHTML = q;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → replace → toLowerCase → innerHTML', () => {
  const { findings } = analyze(`
    var h = location.hash.replace('#', '').toLowerCase();
    document.body.innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted → toString → innerHTML', () => {
  const { findings } = analyze(`
    var h = location.hash;
    document.body.innerHTML = h.toString();
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.concat(safe) → innerHTML', () => {
  const { findings } = analyze(`
    var h = location.hash;
    var result = h.concat(' suffix');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe.concat(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var result = 'prefix '.concat(location.hash);
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('String(tainted) preserves taint → innerHTML', () => {
  const { findings } = analyze(`
    var h = String(location.hash);
    document.body.innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: object property taint ────────────────────────

console.log('\n--- XSS: object property taint ---');

test('tainted value stored in object property → innerHTML', () => {
  const { findings } = analyze(`
    var config = {};
    config.html = location.hash;
    document.body.innerHTML = config.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('object literal with tainted property → destructured → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { content: location.hash };
    var { content } = obj;
    document.body.innerHTML = content;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: template literals ────────────────────────────

console.log('\n--- XSS: template literals ---');

test('tagged template with tainted expression', () => {
  const { findings } = analyze(`
    function html(strings, ...values) { return strings.join('') + values.join(''); }
    var h = location.hash;
    document.body.innerHTML = html\`<div>\${h}</div>\`;
  `);
  expect(findings).toHaveType('XSS');
});

test('nested template literals with taint', () => {
  const { findings } = analyze(`
    var h = location.hash;
    var inner = \`<span>\${h}</span>\`;
    document.body.innerHTML = \`<div>\${inner}</div>\`;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: logical operators ────────────────────────────

console.log('\n--- XSS: logical operators ---');

test('tainted || default → innerHTML', () => {
  const { findings } = analyze(`
    var h = location.hash || 'default';
    document.body.innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});

test('condition && tainted → innerHTML', () => {
  const { findings } = analyze(`
    var h = true && location.hash;
    document.body.innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});

test('nullish coalescing with taint', () => {
  const { findings } = analyze(`
    var h = location.hash ?? 'fallback';
    document.body.innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: passthroughs ─────────────────────────────────

console.log('\n--- XSS: passthroughs ---');

test('location.hash → JSON.parse → innerHTML', () => {
  const { findings } = analyze(`
    var data = JSON.parse(location.hash.slice(1));
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → decodeURIComponent → innerHTML', () => {
  const { findings } = analyze(`
    var h = decodeURIComponent(location.hash.slice(1));
    document.body.innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});

test('location.hash → atob → innerHTML', () => {
  const { findings } = analyze(`
    var decoded = atob(location.hash.slice(1));
    document.body.innerHTML = decoded;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: multiple sinks / sources ─────────────────────

console.log('\n--- XSS: multiple sinks / sources ---');

test('same tainted var flows to two different sinks', () => {
  const { findings } = analyze(`
    var h = location.hash;
    document.getElementById('a').innerHTML = h;
    document.getElementById('b').innerHTML = h;
  `);
  expect(findings).toHaveAtLeast(2);
});

test('hash + search concatenated → innerHTML', () => {
  const { findings } = analyze(`
    var combined = location.hash + location.search;
    document.body.innerHTML = combined;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: assignment expressions ───────────────────────

console.log('\n--- XSS: assignments ---');

test('chained var assignment: a = b = tainted', () => {
  const { findings } = analyze(`
    var a, b;
    a = b = location.hash;
    document.body.innerHTML = a;
  `);
  expect(findings).toHaveType('XSS');
});

test('chained var assignment: sink uses b', () => {
  const { findings } = analyze(`
    var a, b;
    a = b = location.hash;
    document.body.innerHTML = b;
  `);
  expect(findings).toHaveType('XSS');
});

test('assignment expression returns tainted value → innerHTML', () => {
  const { findings } = analyze(`
    var x;
    document.body.innerHTML = (x = location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('string += tainted → innerHTML', () => {
  const { findings } = analyze(`
    var html = '<div>';
    html += location.hash;
    html += '</div>';
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: scope-aware ──────────────────────────────────

console.log('\n--- XSS: scope-aware ---');

test('tainted var shadowed by safe inner var still detects outer use', () => {
  const { findings } = analyze(`
    var data = location.hash;
    function inner() {
      var data = "safe";
      document.getElementById('safe').innerHTML = data;
    }
    document.getElementById('vuln').innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: nested callbacks ─────────────────────────────

console.log('\n--- XSS: nested callbacks ---');

test('setTimeout callback uses tainted closure var → innerHTML', () => {
  const { findings } = analyze(`
    var h = location.hash;
    setTimeout(function() {
      document.body.innerHTML = h;
    }, 0);
  `);
  expect(findings).toHaveType('XSS');
});

test('array.forEach with tainted elements → innerHTML', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    items.forEach(function(item) {
      document.body.innerHTML += item;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('array.map + join + innerHTML', () => {
  const { findings } = analyze(`
    var tags = location.hash.split(',');
    var html = tags.map(function(t) { return '<span>' + t + '</span>'; }).join('');
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── XSS: promise chains ───────────────────────────────

console.log('\n--- XSS: promise chains ---');

test('fetch with tainted URL → .then → innerHTML', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    fetch(url).then(function(r) { return r.text(); }).then(function(text) {
      document.body.innerHTML = text;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('fetch(tainted) → response.json() → innerHTML', () => {
  const { findings } = analyze(`
    var endpoint = location.hash.slice(1);
    fetch(endpoint).then(function(r) {
      return r.json();
    }).then(function(data) {
      document.body.innerHTML = data.html;
    });
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Prototype Pollution ────────────────────────────────

console.log('\n--- Prototype Pollution ---');

test('nested computed assignment with tainted keys', () => {
  const { findings } = analyze(`
    var key1 = location.hash.slice(1);
    var key2 = location.search.slice(1);
    var obj = {};
    obj[key1][key2] = 'polluted';
  `);
  expect(findings).toHaveType('Prototype Pollution');
});

test('prototype pollution via URLSearchParams keys', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    var key = params.get('key');
    var sub = params.get('sub');
    var obj = {};
    obj[key][sub] = 'value';
  `);
  expect(findings).toHaveType('Prototype Pollution');
});


// ─── Cross-file ─────────────────────────────────────────

console.log('\n--- Cross-file ---');

test('script A sets tainted global, script B sinks it', () => {
  const findings = analyzeMultiple([
    { source: `var globalData = location.hash;`, file: 'a.js' },
    { source: `document.body.innerHTML = globalData;`, file: 'b.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

test('script A defines function, script B calls it with tainted arg', () => {
  const findings = analyzeMultiple([
    { source: `function renderHTML(content) { document.body.innerHTML = content; }`, file: 'utils.js' },
    { source: `renderHTML(location.hash);`, file: 'app.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

test('taint flows across 3 scripts via globals', () => {
  const findings = analyzeMultiple([
    { source: `var rawInput = location.hash;`, file: 'a.js' },
    { source: `var processed = rawInput;`, file: 'b.js' },
    { source: `document.body.innerHTML = processed;`, file: 'c.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

test('function in A, taint in B, sink call in C', () => {
  const findings = analyzeMultiple([
    { source: `function show(html) { document.body.innerHTML = html; }`, file: 'utils.js' },
    { source: `var userContent = location.hash;`, file: 'input.js' },
    { source: `show(userContent);`, file: 'main.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

test('taint flows through global object across files', () => {
  const findings = analyzeMultiple([
    { source: `var app = {}; app.data = location.hash;`, file: 'a.js' },
    { source: `document.body.innerHTML = app.data;`, file: 'b.js' },
  ]);
  expect(findings).toHaveType('XSS');
});


// ╔═══════════════════════════════════════════════════════╗
// ║  NEGATIVE TESTS — should NOT find vulnerabilities     ║
// ╚═══════════════════════════════════════════════════════╝


// ─── Safe: static content ───────────────────────────────

console.log('\n--- Safe: static content ---');

test('static string → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = '<p>Hello world</p>';
  `);
  expect(findings).toBeEmpty();
});

test('computed from safe values → innerHTML', () => {
  const { findings } = analyze(`
    var name = "Alice";
    var age = 30;
    document.body.innerHTML = '<p>' + name + ' is ' + age + '</p>';
  `);
  expect(findings).toBeEmpty();
});

test('number → innerHTML', () => {
  const { findings } = analyze(`
    var count = 42;
    document.getElementById('counter').innerHTML = count;
  `);
  expect(findings).toBeEmpty();
});

test('function returning static string → innerHTML', () => {
  const { findings } = analyze(`
    function getGreeting() { return '<h1>Hello</h1>'; }
    document.body.innerHTML = getGreeting();
  `);
  expect(findings).toBeEmpty();
});

test('IIFE returning static value → innerHTML', () => {
  const { findings } = analyze(`
    var content = (function() { return '<p>Hello</p>'; })();
    document.body.innerHTML = content;
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: sanitized flows ──────────────────────────────

console.log('\n--- Safe: sanitized ---');

test('location.hash → DOMPurify.sanitize → innerHTML', () => {
  const { findings } = analyze(`
    var dirty = location.hash.slice(1);
    var clean = DOMPurify.sanitize(dirty);
    document.body.innerHTML = clean;
  `);
  expect(findings).toBeEmpty();
});

test('location.hash → encodeURIComponent → innerHTML', () => {
  const { findings } = analyze(`
    var h = location.hash;
    var safe = encodeURIComponent(h);
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});

test('location.hash → parseInt → innerHTML', () => {
  const { findings } = analyze(`
    var h = location.hash.slice(1);
    var num = parseInt(h, 10);
    document.body.innerHTML = num;
  `);
  expect(findings).toBeEmpty();
});

test('location.hash → Number() → innerHTML', () => {
  const { findings } = analyze(`
    var h = Number(location.hash.slice(1));
    document.body.innerHTML = h;
  `);
  expect(findings).toBeEmpty();
});

test('parseFloat kills taint', () => {
  const { findings } = analyze(`
    var h = parseFloat(location.hash.slice(1));
    document.body.innerHTML = h;
  `);
  expect(findings).toBeEmpty();
});

test('Boolean() kills taint', () => {
  const { findings } = analyze(`
    var b = Boolean(location.hash);
    document.body.innerHTML = b;
  `);
  expect(findings).toBeEmpty();
});

test('Math.floor kills taint', () => {
  const { findings } = analyze(`
    var n = Math.floor(location.hash.slice(1));
    document.body.innerHTML = n;
  `);
  expect(findings).toBeEmpty();
});

test('Math.round kills taint', () => {
  const { findings } = analyze(`
    var n = Math.round(Number(location.hash.slice(1)));
    document.body.innerHTML = n;
  `);
  expect(findings).toBeEmpty();
});

test('Math.abs kills taint', () => {
  const { findings } = analyze(`
    var n = Math.abs(location.hash.slice(1));
    document.body.innerHTML = n;
  `);
  expect(findings).toBeEmpty();
});

test('Math.ceil kills taint', () => {
  const { findings } = analyze(`
    var n = Math.ceil(location.hash.slice(1));
    document.body.innerHTML = n;
  `);
  expect(findings).toBeEmpty();
});

test('encodeURI kills taint', () => {
  const { findings } = analyze(`
    var h = encodeURI(location.hash);
    document.body.innerHTML = h;
  `);
  expect(findings).toBeEmpty();
});

test('escapeHtml(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var h = escapeHtml(location.hash);
    document.body.innerHTML = h;
  `);
  expect(findings).toBeEmpty();
});

test('sanitizeHtml(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var h = sanitizeHtml(location.hash);
    document.body.innerHTML = h;
  `);
  expect(findings).toBeEmpty();
});

test('escape(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var h = escape(location.hash);
    document.body.innerHTML = h;
  `);
  expect(findings).toBeEmpty();
});

test('DOMPurify.sanitize in template literal', () => {
  const { findings } = analyze(`
    var h = location.hash;
    var clean = DOMPurify.sanitize(h);
    document.body.innerHTML = \`<div>\${clean}</div>\`;
  `);
  expect(findings).toBeEmpty();
});

test('DOMPurify.sanitize then string concat', () => {
  const { findings } = analyze(`
    var h = DOMPurify.sanitize(location.hash);
    document.body.innerHTML = '<div>' + h + '</div>';
  `);
  expect(findings).toBeEmpty();
});

test('custom sanitizer wrapper using DOMPurify', () => {
  const { findings } = analyze(`
    function clean(html) {
      return DOMPurify.sanitize(html);
    }
    var h = location.hash;
    document.body.innerHTML = clean(h);
  `);
  expect(findings).toBeEmpty();
});

test('custom sanitizer wrapper using encodeURIComponent', () => {
  const { findings } = analyze(`
    function safeEncode(s) {
      return encodeURIComponent(s);
    }
    document.body.innerHTML = safeEncode(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('Number(tainted) in template literal → innerHTML', () => {
  const { findings } = analyze(`
    var count = Number(location.hash.slice(1));
    document.body.innerHTML = \`Count: \${count}\`;
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: textContent / innerText ──────────────────────

console.log('\n--- Safe: textContent / innerText ---');

test('location.hash → textContent (safe)', () => {
  const { findings } = analyze(`
    document.getElementById('out').textContent = location.hash;
  `);
  expect(findings).toBeEmpty();
});

test('location.hash → div.textContent (safe)', () => {
  const { findings } = analyze(`
    var div = document.createElement('div');
    div.textContent = location.hash;
    document.body.appendChild(div);
  `);
  expect(findings).toBeEmpty();
});

test('location.hash → innerText (safe)', () => {
  const { findings } = analyze(`
    document.getElementById('out').innerText = location.hash;
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: createTextNode ───────────────────────────────

console.log('\n--- Safe: createTextNode ---');

test('location.hash → createTextNode → appendChild (safe)', () => {
  const { findings } = analyze(`
    var text = document.createTextNode(location.hash);
    document.body.appendChild(text);
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: setAttribute ─────────────────────────────────

console.log('\n--- Safe: setAttribute ---');

test('setAttribute("title", tainted) is not a sink', () => {
  const { findings } = analyze(`
    document.body.setAttribute('title', location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('setAttribute("class", tainted) is not a sink', () => {
  const { findings } = analyze(`
    document.body.setAttribute('class', location.hash);
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: numeric coercion ─────────────────────────────

console.log('\n--- Safe: numeric coercion ---');

test('unary + coercion kills taint', () => {
  const { findings } = analyze(`
    var h = +location.hash.slice(1);
    document.body.innerHTML = h;
  `);
  expect(findings).toBeEmpty();
});

test('typeof kills taint', () => {
  const { findings } = analyze(`
    var t = typeof location.hash;
    document.body.innerHTML = t;
  `);
  expect(findings).toBeEmpty();
});

test('boolean NOT kills taint', () => {
  const { findings } = analyze(`
    var b = !location.hash;
    document.body.innerHTML = b;
  `);
  expect(findings).toBeEmpty();
});

test('!!tainted → innerHTML (boolean coercion)', () => {
  const { findings } = analyze(`
    var exists = !!location.hash;
    document.body.innerHTML = exists;
  `);
  expect(findings).toBeEmpty();
});

test('void expression is always undefined', () => {
  const { findings } = analyze(`
    var h = location.hash;
    document.body.innerHTML = void h;
  `);
  expect(findings).toBeEmpty();
});

test('bitwise NOT (~) kills taint (produces number)', () => {
  const { findings } = analyze(`
    var h = ~location.hash.slice(1);
    document.body.innerHTML = h;
  `);
  expect(findings).toBeEmpty();
});

test('unary minus kills taint (produces number)', () => {
  const { findings } = analyze(`
    var h = -location.hash.slice(1);
    document.body.innerHTML = h;
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: numeric property access ──────────────────────

console.log('\n--- Safe: numeric property access ---');

test('.length of tainted string → innerHTML (number)', () => {
  const { findings } = analyze(`
    var len = location.hash.length;
    document.body.innerHTML = len;
  `);
  expect(findings).toBeEmpty();
});

test('.indexOf on tainted string → innerHTML (number)', () => {
  const { findings } = analyze(`
    var idx = location.hash.indexOf('admin');
    document.body.innerHTML = idx;
  `);
  expect(findings).toBeEmpty();
});

test('.includes on tainted string → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var has = location.hash.includes('admin');
    document.body.innerHTML = has;
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: setTimeout/setInterval with function ────────

console.log('\n--- Safe: setTimeout/setInterval with function ---');

test('setTimeout with function ref is safe', () => {
  const { findings } = analyze(`
    var h = location.hash;
    setTimeout(function() {
      console.log(h);
    }, 100);
  `);
  expect(findings).toBeEmpty();
});

test('setTimeout with arrow function is safe', () => {
  const { findings } = analyze(`
    var h = location.hash;
    setTimeout(() => console.log(h), 100);
  `);
  expect(findings).toBeEmpty();
});

test('setInterval with function expression is safe', () => {
  const { findings } = analyze(`
    var h = location.hash;
    setInterval(function() { console.log(h); }, 1000);
  `);
  expect(findings).toBeEmpty();
});

test('setInterval with arrow function is safe', () => {
  const { findings } = analyze(`
    setInterval(() => console.log(location.hash), 1000);
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: postMessage with origin check ────────────────

console.log('\n--- Safe: postMessage with origin check ---');

test('postMessage handler with origin === check', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(event) {
      if (event.origin === 'https://trusted.com') {
        document.body.innerHTML = event.data;
      }
    });
  `);
  expect(findings).toBeEmpty();
});

test('postMessage handler with origin !== check', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(event) {
      if (event.origin !== 'https://trusted.com') return;
      document.body.innerHTML = event.data;
    });
  `);
  expect(findings).toBeEmpty();
});

test('postMessage handler with == origin check', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(event) {
      if (event.origin == 'https://trusted.com') {
        document.body.innerHTML = event.data;
      }
    });
  `);
  expect(findings).toBeEmpty();
});

test('postMessage handler with !== origin guard (early return)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin !== 'https://safe.com') return;
      document.body.innerHTML = e.data;
    });
  `);
  expect(findings).toBeEmpty();
});

test('onmessage handler with === origin check', () => {
  const { findings } = analyze(`
    window.onmessage = function(event) {
      if (event.origin === 'https://trusted.com') {
        document.body.innerHTML = event.data;
      }
    };
  `);
  expect(findings).toBeEmpty();
});

test('message handler that only logs, does not sink', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      console.log('Got message from', e.origin);
    });
  `);
  expect(findings).toBeEmpty();
});


// ─── postMessage: weak origin checks (should still flag) ─────

console.log('\n--- postMessage: weak origin checks ---');

test('origin === "null" is weak (sandboxed iframe bypass)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin === 'null') {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('origin.includes() is weak (substring bypass)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin.includes('trusted.com')) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('origin.indexOf() is weak (substring bypass)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin.indexOf('trusted') !== -1) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('origin.endsWith() is weak (prefix bypass)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(event) {
      if (event.origin.endsWith('trusted.com')) {
        document.body.innerHTML = event.data;
      }
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('unanchored regex is weak', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (/trusted\\.com/.test(e.origin)) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('origin.startsWith("http") is weak (not an origin check)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin.startsWith('http')) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('origin === "" is weak (empty string)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin === '') return;
      document.body.innerHTML = e.data;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('origin compared to bare domain (no scheme) is weak', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin === 'trusted.com') {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('custom weak validator (uses includes) still flags', () => {
  const { findings } = analyze(`
    function isAllowed(origin) {
      return origin.includes('trusted.com');
    }
    window.addEventListener('message', function(e) {
      if (isAllowed(e.origin)) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('onmessage with origin === "null" is weak', () => {
  const { findings } = analyze(`
    window.onmessage = function(e) {
      if (e.origin === 'null') {
        document.body.innerHTML = e.data;
      }
    };
  `);
  expect(findings).toHaveType('XSS');
});

test('origin === "*" is weak (wildcard)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin === '*') {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ─── postMessage: strong origin checks (should suppress) ─────

console.log('\n--- postMessage: strong origin checks ---');

test('origin === full https URL is strong', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin === 'https://trusted.example.com') {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toBeEmpty();
});

test('origin.startsWith with full origin is strong', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin.startsWith('https://trusted.com')) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toBeEmpty();
});

test('allowList.includes(origin) is strong', () => {
  const { findings } = analyze(`
    var allowed = ['https://a.com', 'https://b.com'];
    window.addEventListener('message', function(e) {
      if (allowed.includes(e.origin)) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toBeEmpty();
});

test('anchored regex is strong', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (/^https:\\/\\/trusted\\.com$/.test(e.origin)) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toBeEmpty();
});

test('custom strong validator (uses === full origin) suppresses', () => {
  const { findings } = analyze(`
    function checkOrigin(o) {
      return o === 'https://trusted.com';
    }
    window.addEventListener('message', function(e) {
      if (checkOrigin(e.origin)) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toBeEmpty();
});

test('custom validator with allowlist is strong', () => {
  const { findings } = analyze(`
    var ALLOWED = ['https://a.com', 'https://b.com'];
    function validateOrigin(origin) {
      return ALLOWED.includes(origin);
    }
    window.addEventListener('message', function(e) {
      if (validateOrigin(e.origin)) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toBeEmpty();
});

test('origin compared to variable is strong (benefit of doubt)', () => {
  const { findings } = analyze(`
    var expectedOrigin = 'https://partner.com';
    window.addEventListener('message', function(e) {
      if (e.origin === expectedOrigin) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toBeEmpty();
});

test('origin !== full URL with early return is strong', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin !== 'https://trusted.com') return;
      document.body.innerHTML = e.data;
    });
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: DOM reads ────────────────────────────────────

console.log('\n--- Safe: DOM reads ---');

test('querySelector result → innerHTML is not a finding', () => {
  const { findings } = analyze(`
    var el = document.querySelector('.content');
    document.body.innerHTML = el;
  `);
  expect(findings).toBeEmpty();
});

test('getElementById → innerHTML is not a finding', () => {
  const { findings } = analyze(`
    var el = document.getElementById('template');
    document.body.innerHTML = el;
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: taint does not reach sink ────────────────────

console.log('\n--- Safe: taint does not reach sink ---');

test('tainted var reassigned to safe value before sink', () => {
  const { findings } = analyze(`
    var data = location.hash;
    data = "safe value";
    document.body.innerHTML = data;
  `);
  expect(findings).toBeEmpty();
});

test('safe inner variable shadows tainted global', () => {
  const { findings } = analyze(`
    var data = location.hash;
    function safe() {
      var data = "clean";
      document.body.innerHTML = data;
    }
    safe();
  `);
  expect(findings).toBeEmpty();
});

test('tainted var overwritten by safe literal', () => {
  const { findings } = analyze(`
    var x = location.hash;
    x = 'safe';
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('tainted var overwritten by sanitized value', () => {
  const { findings } = analyze(`
    var x = location.hash;
    x = DOMPurify.sanitize(x);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('tainted var stored but only safe var used in sink', () => {
  const { findings } = analyze(`
    var tainted = location.hash;
    var safe = 'hello';
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});

test('tainted var passed to function but function only uses static string', () => {
  const { findings } = analyze(`
    function render(unused) {
      document.body.innerHTML = '<p>Hello</p>';
    }
    render(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('tainted var overwritten in both if and else', () => {
  const { findings } = analyze(`
    var data = location.hash;
    if (Math.random() > 0.5) {
      data = 'safe-a';
    } else {
      data = 'safe-b';
    }
    document.body.innerHTML = data;
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: non-sink APIs ────────────────────────────────

console.log('\n--- Safe: non-sink APIs ---');

test('console.log is not a sink', () => {
  const { findings } = analyze(`
    console.log(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('JSON.stringify is not a sink', () => {
  const { findings } = analyze(`
    var str = JSON.stringify({ h: location.hash });
    document.body.textContent = str;
  `);
  expect(findings).toBeEmpty();
});

test('alert is not a sink we care about', () => {
  const { findings } = analyze(`
    alert(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('localStorage.setItem is not a sink', () => {
  const { findings } = analyze(`
    localStorage.setItem('data', location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('tainted value used only as fetch body (not a URL)', () => {
  const { findings } = analyze(`
    var data = location.hash;
    fetch('/api/log', { method: 'POST', body: data });
  `);
  expect(findings).toBeEmpty();
});

test('tainted value used only in console.warn', () => {
  const { findings } = analyze(`
    var h = location.hash;
    console.warn('Hash is:', h);
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: non-source attributes ────────────────────────

console.log('\n--- Safe: non-source attributes ---');

test('element.className is not a source', () => {
  const { findings } = analyze(`
    var cls = document.body.className;
    document.body.innerHTML = cls;
  `);
  expect(findings).toBeEmpty();
});

test('element.id is not a source', () => {
  const { findings } = analyze(`
    var id = document.body.id;
    document.body.innerHTML = id;
  `);
  expect(findings).toBeEmpty();
});

test('navigator.userAgent is not tracked as a source', () => {
  const { findings } = analyze(`
    document.body.innerHTML = navigator.userAgent;
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: complex safe patterns ────────────────────────

console.log('\n--- Safe: complex safe patterns ---');

test('location used only for comparison, not sunk', () => {
  const { findings } = analyze(`
    if (location.hash === '#admin') {
      document.body.innerHTML = '<h1>Admin</h1>';
    }
  `);
  expect(findings).toBeEmpty();
});

test('fetch with hardcoded URL', () => {
  const { findings } = analyze(`
    fetch('/api/data').then(r => r.json()).then(data => {
      document.body.innerHTML = '<pre>' + JSON.stringify(data) + '</pre>';
    });
  `);
  expect(findings).toBeEmpty();
});

test('fetch with static URL → .then → innerHTML', () => {
  const { findings } = analyze(`
    fetch('/api/safe').then(function(r) { return r.json(); }).then(function(data) {
      document.body.innerHTML = data.html;
    });
  `);
  expect(findings).toBeEmpty();
});

test('JSON.stringify(tainted) → textContent', () => {
  const { findings } = analyze(`
    var data = { q: location.hash };
    document.body.textContent = JSON.stringify(data);
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: cross-file sanitization ──────────────────────

console.log('\n--- Safe: cross-file sanitization ---');

test('script A taints, script B sanitizes, script C sinks (safe)', () => {
  const findings = analyzeMultiple([
    { source: `var userInput = location.hash;`, file: 'a.js' },
    { source: `var safe = DOMPurify.sanitize(userInput);`, file: 'b.js' },
    { source: `document.body.innerHTML = safe;`, file: 'c.js' },
  ]);
  if (findings.some(f => f.type === 'XSS')) {
    throw new Error('Expected sanitization to clear taint across files');
  }
});

test('taint set in script A, sanitized in script B, used in script C', () => {
  const findings = analyzeMultiple([
    { source: `var data = location.hash;`, file: 'a.js' },
    { source: `data = parseInt(data, 10);`, file: 'b.js' },
    { source: `document.body.innerHTML = data;`, file: 'c.js' },
  ]);
  if (findings.some(f => f.type === 'XSS')) {
    throw new Error('Expected parseInt to clear taint across files');
  }
});

test('taint in A, DOMPurify in B, sink in C', () => {
  const findings = analyzeMultiple([
    { source: `var dirty = location.hash;`, file: 'a.js' },
    { source: `var clean = DOMPurify.sanitize(dirty);`, file: 'b.js' },
    { source: `document.body.innerHTML = clean;`, file: 'c.js' },
  ]);
  expect(findings).notToHaveType('XSS');
});

test('taint in A, encodeURIComponent in B, sink in C', () => {
  const findings = analyzeMultiple([
    { source: `var raw = location.search;`, file: 'a.js' },
    { source: `var encoded = encodeURIComponent(raw);`, file: 'b.js' },
    { source: `document.body.innerHTML = encoded;`, file: 'c.js' },
  ]);
  expect(findings).notToHaveType('XSS');
});


// ╔═══════════════════════════════════════════════════════╗
// ║  FUNCTION TRACING — advanced interprocedural patterns ║
// ╚═══════════════════════════════════════════════════════╝


// ─── Function expression in local scope ─────────────────

console.log('\n--- Function expression in local scope ---');

test('var fn = function(){} inside function body, then called', () => {
  const { findings } = analyze(`
    function init() {
      var render = function(html) {
        document.body.innerHTML = html;
      };
      render(location.hash);
    }
    init();
  `);
  expect(findings).toHaveType('XSS');
});

test('const arrow inside function body, then called', () => {
  const { findings } = analyze(`
    function setup() {
      const output = (data) => {
        document.body.innerHTML = data;
      };
      output(location.search);
    }
    setup();
  `);
  expect(findings).toHaveType('XSS');
});

test('let fn reassigned then called with taint', () => {
  const { findings } = analyze(`
    let handler = function(x) { console.log(x); };
    handler = function(x) { document.body.innerHTML = x; };
    handler(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Named callback to array methods ────────────────────

console.log('\n--- Named callback to array methods ---');

test('forEach with named function reference', () => {
  const { findings } = analyze(`
    function renderItem(item) {
      document.body.innerHTML += item;
    }
    var items = location.search.split('&');
    items.forEach(renderItem);
  `);
  expect(findings).toHaveType('XSS');
});

test('map with named function reference', () => {
  const { findings } = analyze(`
    function wrapTag(text) {
      return '<li>' + text + '</li>';
    }
    var items = location.hash.split(',');
    var html = items.map(wrapTag).join('');
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Method setter/getter pattern ───────────────────────

console.log('\n--- Method setter/getter pattern ---');

test('method sets this.data, another method reads it into sink', () => {
  const { findings } = analyze(`
    function Component() {}
    Component.prototype.setData = function(d) { this.data = d; };
    Component.prototype.render = function() { document.body.innerHTML = this.data; };
    var c = new Component();
    c.setData(location.hash);
    c.render();
  `);
  expect(findings).toHaveType('XSS');
});

test('class setter method + render method', () => {
  const { findings } = analyze(`
    class View {
      update(html) { this.html = html; }
      render() { document.body.innerHTML = this.html; }
    }
    var v = new View();
    v.update(location.hash);
    v.render();
  `);
  expect(findings).toHaveType('XSS');
});

test('obj property set directly, then method reads this.*', () => {
  const { findings } = analyze(`
    var widget = {
      render: function() { document.body.innerHTML = this.content; }
    };
    widget.content = location.hash;
    widget.render();
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Object.assign taint propagation ────────────────────

console.log('\n--- Object.assign ---');

test('Object.assign merges tainted property', () => {
  const { findings } = analyze(`
    var config = {};
    Object.assign(config, { html: location.hash });
    document.body.innerHTML = config.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('Object.assign from tainted source object', () => {
  const { findings } = analyze(`
    var source = { data: location.hash };
    var target = Object.assign({}, source);
    document.body.innerHTML = target.data;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Returned function called immediately ───────────────

console.log('\n--- Returned function called immediately ---');

test('factory()() — returned function invoked immediately', () => {
  const { findings } = analyze(`
    function getRenderer() {
      return function(html) {
        document.body.innerHTML = html;
      };
    }
    getRenderer()(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('arrow factory()() pattern', () => {
  const { findings } = analyze(`
    const makeWriter = () => (data) => {
      document.body.innerHTML = data;
    };
    makeWriter()(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Class method calling sibling via this ──────────────

console.log('\n--- Class: this.method() calls ---');

test('class method delegates to this.helper() which sinks', () => {
  const { findings } = analyze(`
    class App {
      show(html) { document.body.innerHTML = html; }
      init(data) { this.show(data); }
    }
    var app = new App();
    app.init(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('this.getData() returns tainted this.data', () => {
  const { findings } = analyze(`
    class Store {
      constructor(d) { this.data = d; }
      getData() { return this.data; }
      render() { document.body.innerHTML = this.getData(); }
    }
    var s = new Store(location.hash);
    s.render();
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Reduce accumulating taint ──────────────────────────

console.log('\n--- Array reduce ---');

test('reduce accumulates tainted items into string → innerHTML', () => {
  const { findings } = analyze(`
    var parts = location.search.split('&');
    var combined = parts.reduce(function(acc, item) {
      return acc + item;
    }, '');
    document.body.innerHTML = combined;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Nested property paths ──────────────────────────────

console.log('\n--- Nested property paths ---');

test('deep property set and read: state.ui.html', () => {
  const { findings } = analyze(`
    var state = { ui: {} };
    state.ui.html = location.hash;
    document.body.innerHTML = state.ui.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('three-level deep: app.config.template.body', () => {
  const { findings } = analyze(`
    var app = { config: { template: {} } };
    app.config.template.body = location.hash;
    document.body.innerHTML = app.config.template.body;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Function hoisting ─────────────────────────────────

console.log('\n--- Function hoisting ---');

test('function called before declaration (hoisted)', () => {
  const { findings } = analyze(`
    renderContent(location.hash);
    function renderContent(html) {
      document.body.innerHTML = html;
    }
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Aliased function reference ─────────────────────────

console.log('\n--- Aliased function reference ---');

test('function assigned to another variable, then called', () => {
  const { findings } = analyze(`
    function dangerousRender(html) {
      document.body.innerHTML = html;
    }
    var fn = dangerousRender;
    fn(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('method extracted to variable, then called', () => {
  const { findings } = analyze(`
    var obj = {
      render: function(html) { document.body.innerHTML = html; }
    };
    var r = obj.render;
    r(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Callback stored then invoked ──────────────────────

console.log('\n--- Callback stored then invoked ---');

test('callback passed to function, stored, then invoked', () => {
  const { findings } = analyze(`
    function register(callback) {
      callback(location.hash);
    }
    function sink(data) {
      document.body.innerHTML = data;
    }
    register(sink);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through Promise.all ──────────────────────────

console.log('\n--- Promise patterns ---');

test('fetch(tainted) in Promise.all → innerHTML', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    Promise.all([fetch(url)]).then(function(results) {
      document.body.innerHTML = results[0];
    });
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Negative: function tracing safe patterns ───────────

console.log('\n--- Safe: function tracing patterns ---');

test('named forEach callback that sanitizes each item', () => {
  const { findings } = analyze(`
    var results = [];
    function sanitizeItem(item) {
      results.push(encodeURIComponent(item));
    }
    location.search.split('&').forEach(sanitizeItem);
    document.body.innerHTML = results.join('');
  `);
  expect(findings).toBeEmpty();
});

test('Object.assign with only safe properties', () => {
  const { findings } = analyze(`
    var config = Object.assign({}, { title: 'Hello', count: 42 });
    document.body.innerHTML = config.title;
  `);
  expect(findings).toBeEmpty();
});

test('method overwrites taint before returning', () => {
  const { findings } = analyze(`
    function process(input) {
      var result = DOMPurify.sanitize(input);
      return result;
    }
    document.body.innerHTML = process(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('factory returns function that sanitizes', () => {
  const { findings } = analyze(`
    function makeSafe() {
      return function(data) {
        return encodeURIComponent(data);
      };
    }
    var sanitize = makeSafe();
    document.body.innerHTML = sanitize(location.hash);
  `);
  expect(findings).toBeEmpty();
});


// ╔═══════════════════════════════════════════════════════╗
// ║  OPEN REDIRECT vs XSS — navigation sink classification ║
// ╚═══════════════════════════════════════════════════════╝

// Navigation sinks (location.href, location.assign, etc.) are classified as:
// - XSS when javascript: URIs are possible (no scheme validation)
// - Open Redirect when the URL scheme is validated (http/https only)

console.log('\n--- Open Redirect vs XSS: positive (Open Redirect) ---');

test('startsWith http → location.href is Open Redirect', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    if (url.startsWith('http')) {
      location.href = url;
    }
  `);
  expect(findings).toHaveType('Open Redirect');
  expect(findings).not.toHaveType('XSS');
});

test('startsWith https:// → location.assign is Open Redirect', () => {
  const { findings } = analyze(`
    var url = new URLSearchParams(location.search).get('next');
    if (url.startsWith('https://')) {
      location.assign(url);
    }
  `);
  expect(findings).toHaveType('Open Redirect');
  expect(findings).not.toHaveType('XSS');
});

test('startsWith / (relative URL) → window.location.href is Open Redirect', () => {
  const { findings } = analyze(`
    var path = location.hash.slice(1);
    if (path.startsWith('/')) {
      window.location.href = path;
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('indexOf http === 0 → location.replace is Open Redirect', () => {
  const { findings } = analyze(`
    var url = location.search.split('url=')[1];
    if (url.indexOf('http') === 0) {
      location.replace(url);
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('url.protocol === https: → window.open is Open Redirect', () => {
  const { findings } = analyze(`
    var raw = location.hash.slice(1);
    var url = new URL(raw);
    if (url.protocol === 'https:') {
      window.open(url.href);
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('url.protocol === http: → location.href is Open Redirect', () => {
  const { findings } = analyze(`
    var raw = location.search.split('redirect=')[1];
    var parsed = new URL(raw);
    if (parsed.protocol === 'http:') {
      location.href = parsed.href;
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('negated javascript: check → Open Redirect', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    if (!url.startsWith('javascript:')) {
      location.href = url;
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('protocol !== javascript: → Open Redirect', () => {
  const { findings } = analyze(`
    var raw = location.search.split('url=')[1];
    var parsed = new URL(raw);
    if (parsed.protocol !== 'javascript:') {
      window.location.href = parsed.href;
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('regex test /^https?:/ → Open Redirect', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    if (/^https?:\\/\\//.test(url)) {
      location.href = url;
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('url.match regex → Open Redirect', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    if (url.match(/^https?:/)) {
      location.assign(url);
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('early return guard: if (!startsWith http) return → Open Redirect', () => {
  const { findings } = analyze(`
    function redirect() {
      var url = location.hash.slice(1);
      if (!url.startsWith('http')) return;
      location.href = url;
    }
    redirect();
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('slice comparison → Open Redirect', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    if (url.slice(0, 4) === 'http') {
      location.href = url;
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('logical AND with scheme check → Open Redirect', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    if (url && url.startsWith('https://')) {
      location.href = url;
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

console.log('\n--- Open Redirect vs XSS: positive (XSS — no scheme check) ---');

test('no scheme check → location.href is XSS', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    location.href = url;
  `);
  expect(findings).toHaveType('XSS');
  expect(findings).not.toHaveType('Open Redirect');
});

test('no scheme check → location.assign is XSS', () => {
  const { findings } = analyze(`
    var next = location.search.split('url=')[1];
    location.assign(next);
  `);
  expect(findings).toHaveType('XSS');
});

test('no scheme check → window.open is XSS', () => {
  const { findings } = analyze(`
    var url = new URLSearchParams(location.search).get('next');
    window.open(url);
  `);
  expect(findings).toHaveType('XSS');
});

test('no scheme check → window.location.replace is XSS', () => {
  const { findings } = analyze(`
    var url = location.search.split('url=')[1];
    window.location.replace(url);
  `);
  expect(findings).toHaveType('XSS');
});

test('irrelevant check (length) still XSS', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    if (url.length > 0) {
      location.href = url;
    }
  `);
  expect(findings).toHaveType('XSS');
  expect(findings).not.toHaveType('Open Redirect');
});

test('innerHTML remains XSS even with scheme check', () => {
  const { findings } = analyze(`
    var data = location.hash.slice(1);
    if (data.startsWith('http')) {
      document.body.innerHTML = data;
    }
  `);
  expect(findings).toHaveType('XSS');
  expect(findings).not.toHaveType('Open Redirect');
});

console.log('\n--- Open Redirect vs XSS: negative (safe patterns) ---');

test('scheme check + sanitized URL → no finding', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    if (url.startsWith('https://')) {
      var safe = encodeURIComponent(url);
      location.href = safe;
    }
  `);
  expect(findings).toBeEmpty();
});

test('hardcoded URL → no finding', () => {
  const { findings } = analyze(`
    location.href = 'https://example.com';
  `);
  expect(findings).toBeEmpty();
});

test('location.href → innerHTML is still XSS (not redirect)', () => {
  const { findings } = analyze(`
    document.body.innerHTML = location.href;
  `);
  expect(findings).toHaveType('XSS');
  expect(findings).not.toHaveType('Open Redirect');
});


// ╔═══════════════════════════════════════════════════════╗
// ║  MINIFIED CODE — taint detection on minified JS       ║
// ╚═══════════════════════════════════════════════════════╝

console.log('\n--- Minified code ---');

test('minified: location.hash → innerHTML (no whitespace)', () => {
  const { findings } = analyze(
    `var a=location.hash;document.getElementById("x").innerHTML=a;`
  );
  expect(findings).toHaveType('XSS');
});

test('minified: function call with tainted arg', () => {
  const { findings } = analyze(
    `function f(a){document.body.innerHTML=a}f(location.hash);`
  );
  expect(findings).toHaveType('XSS');
});

test('minified: chained assignments', () => {
  const { findings } = analyze(
    `var a=location.search,b=a,c=b;document.body.innerHTML=c;`
  );
  expect(findings).toHaveType('XSS');
});

test('minified: ternary with tainted branch', () => {
  const { findings } = analyze(
    `var a=location.hash,b=true?a:"safe";document.body.innerHTML=b;`
  );
  expect(findings).toHaveType('XSS');
});

test('minified: eval with tainted input', () => {
  const { findings } = analyze(
    `var a=location.hash;eval(a);`
  );
  expect(findings).toHaveType('XSS');
});

test('minified: comma-separated vars with taint flow', () => {
  const { findings } = analyze(
    `var a=location.hash,b=document.createElement("div");b.innerHTML=a;`
  );
  expect(findings).toHaveType('XSS');
});

test('minified: IIFE wrapping tainted flow', () => {
  const { findings } = analyze(
    `(function(){var a=location.hash;document.body.innerHTML=a})();`
  );
  expect(findings).toHaveType('XSS');
});

test('minified: safe code produces no findings', () => {
  const { findings } = analyze(
    `var a="hello",b=document.createElement("div");b.textContent=a;`
  );
  expect(findings).toBeEmpty();
});


// ╔═══════════════════════════════════════════════════════╗
// ║  ADVANCED AST PATTERNS — scope-aware edge cases        ║
// ╚═══════════════════════════════════════════════════════╝


// ─── Script injection: createElement('script') + .src ───

console.log('\n--- Script injection ---');

test('document.createElement("script") with tainted src', () => {
  const { findings } = analyze(`
    var s = document.createElement('script');
    s.src = location.hash.slice(1);
    document.body.appendChild(s);
  `);
  expect(findings).toHaveType('Script Injection');
});

test('createElement variable tag with tainted src', () => {
  const { findings } = analyze(`
    var el = document.createElement('script');
    el.setAttribute('src', location.search.slice(1));
    document.head.appendChild(el);
  `);
  expect(findings).toHaveType('Script Injection');
});


// ─── globalThis / self aliases as taint sources ─────────

console.log('\n--- Source aliases: globalThis, self, window ---');

test('globalThis.location.hash → innerHTML', () => {
  const { findings } = analyze(`
    var h = globalThis.location.hash;
    document.body.innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});

test('self.location.search → innerHTML', () => {
  const { findings } = analyze(`
    var q = self.location.search;
    document.body.innerHTML = q;
  `);
  expect(findings).toHaveType('XSS');
});

test('window.document.cookie → innerHTML', () => {
  const { findings } = analyze(`
    var c = window.document.cookie;
    document.body.innerHTML = c;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Optional chaining preserves taint ──────────────────

console.log('\n--- Optional chaining taint propagation ---');

test('optional chaining on tainted object property', () => {
  const { findings } = analyze(`
    var obj = { data: location.hash };
    var val = obj?.data;
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('deep optional chain preserves taint', () => {
  const { findings } = analyze(`
    var state = { ui: { content: location.hash } };
    var html = state?.ui?.content;
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

test('optional call on tainted method result', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    var val = params?.get?.('q');
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── finally block control flow ─────────────────────────

console.log('\n--- Control flow: finally ---');

test('finally overwrites safe catch with tainted value', () => {
  const { findings } = analyze(`
    var data;
    try {
      throw new Error();
    } catch (e) {
      data = 'safe';
    } finally {
      data = location.hash;
    }
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted in try, safe in finally → safe', () => {
  const { findings } = analyze(`
    var data;
    try {
      data = location.hash;
    } finally {
      data = 'safe string';
    }
    document.body.innerHTML = data;
  `);
  expect(findings).toBeEmpty();
});


// ─── switch fall-through ────────────────────────────────

console.log('\n--- Control flow: switch fall-through ---');

test('switch case assigns taint, falls through to sink', () => {
  const { findings } = analyze(`
    var result = '';
    var h = location.hash;
    switch (h.length) {
      case 5:
        result = h;
      case 10:
        document.body.innerHTML = result;
        break;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('switch default with tainted value', () => {
  const { findings } = analyze(`
    var action = location.hash;
    switch (action) {
      case '#safe':
        document.body.innerHTML = 'ok';
        break;
      default:
        document.body.innerHTML = action;
    }
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Getter returning tainted value ─────────────────────

console.log('\n--- Object getter/setter patterns ---');

test('getter returns tainted value → innerHTML', () => {
  const { findings } = analyze(`
    var obj = {
      get html() { return location.hash; }
    };
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe getter returns static string', () => {
  const { findings } = analyze(`
    var obj = {
      get title() { return 'Hello World'; }
    };
    document.body.innerHTML = obj.title;
  `);
  expect(findings).toBeEmpty();
});


// ─── URLSearchParams iterator methods ───────────────────

console.log('\n--- URLSearchParams advanced ---');

test('URLSearchParams.toString() → innerHTML', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    document.body.innerHTML = params.toString();
  `);
  expect(findings).toHaveType('XSS');
});

test('for-of over URLSearchParams.entries() → innerHTML', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    for (var pair of params.entries()) {
      document.body.innerHTML += pair[1];
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('spread URLSearchParams.values() → join → innerHTML', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    var vals = [...params.values()];
    document.body.innerHTML = vals.join(',');
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Map/Set with tainted values ────────────────────────

console.log('\n--- Map/Set taint propagation ---');

test('Map.set() then Map.get() → innerHTML', () => {
  const { findings } = analyze(`
    var map = new Map();
    map.set('key', location.hash);
    document.body.innerHTML = map.get('key');
  `);
  expect(findings).toHaveType('XSS');
});

test('safe Map with static values → no finding', () => {
  const { findings } = analyze(`
    var map = new Map();
    map.set('key', 'hello');
    document.body.innerHTML = map.get('key');
  `);
  expect(findings).toBeEmpty();
});


// ─── Array flatMap and reduceRight ──────────────────────

console.log('\n--- Advanced array methods ---');

test('flatMap preserves taint through callback', () => {
  const { findings } = analyze(`
    var items = [location.hash, location.search];
    var flat = items.flatMap(function(x) { return [x]; });
    document.body.innerHTML = flat.join('');
  `);
  expect(findings).toHaveType('XSS');
});

test('reduceRight accumulates tainted values', () => {
  const { findings } = analyze(`
    var parts = location.search.split('&');
    var combined = parts.reduceRight(function(acc, item) {
      return acc + item;
    }, '');
    document.body.innerHTML = combined;
  `);
  expect(findings).toHaveType('XSS');
});

test('Array.from with tainted iterable', () => {
  const { findings } = analyze(`
    var arr = Array.from(location.search.split('&'));
    document.body.innerHTML = arr.join('');
  `);
  expect(findings).toHaveType('XSS');
});

test('filter preserves taint on matching elements', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    var filtered = items.filter(function(x) { return x.length > 0; });
    document.body.innerHTML = filtered.join('');
  `);
  expect(findings).toHaveType('XSS');
});

test('find returns tainted element → innerHTML', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    var found = items.find(function(x) { return x.startsWith('q='); });
    document.body.innerHTML = found;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Labeled break with tainted loop var ────────────────

console.log('\n--- Labeled statements ---');

test('labeled break out of nested loop with tainted value', () => {
  const { findings } = analyze(`
    var result;
    outer: for (var i = 0; i < 1; i++) {
      var items = location.search.split('&');
      for (var j = 0; j < items.length; j++) {
        result = items[j];
        break outer;
      }
    }
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Comma operator / sequence expressions ──────────────

console.log('\n--- Sequence and comma operator ---');

test('comma operator: tainted last expression → innerHTML', () => {
  const { findings } = analyze(`
    var x = (0, location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('comma operator: tainted first, safe last → safe', () => {
  const { findings } = analyze(`
    var x = (location.hash, 'safe');
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});


// ─── for-of / for-in with tainted iterables ─────────────

console.log('\n--- for-of / for-in with taint ---');

test('for-of over tainted array → innerHTML', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    for (var item of items) {
      document.body.innerHTML += item;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('for-in over object with tainted values → innerHTML', () => {
  const { findings } = analyze(`
    var config = { html: location.hash };
    for (var key in config) {
      document.body.innerHTML = config[key];
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('for-of with destructuring preserves taint', () => {
  const { findings } = analyze(`
    var entries = [[location.hash, 'val']];
    for (var [key, val] of entries) {
      document.body.innerHTML = key;
    }
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Nullish coalescing edge cases ──────────────────────

console.log('\n--- Nullish coalescing edge cases ---');

test('null ?? tainted → innerHTML', () => {
  const { findings } = analyze(`
    var val = null ?? location.hash;
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted ?? fallback → innerHTML', () => {
  const { findings } = analyze(`
    var val = location.hash ?? 'default';
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Logical assignment operators ───────────────────────

console.log('\n--- Logical assignment operators ---');

test('||= with tainted value', () => {
  const { findings } = analyze(`
    var content = '';
    content ||= location.hash;
    document.body.innerHTML = content;
  `);
  expect(findings).toHaveType('XSS');
});

test('??= with tainted value', () => {
  const { findings } = analyze(`
    var data = null;
    data ??= location.hash;
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Safe: taint killed by reassignment in all branches ─

console.log('\n--- Safe: comprehensive branch coverage ---');

test('taint overwritten in all switch cases → safe', () => {
  const { findings } = analyze(`
    var data = location.hash;
    switch (data.length) {
      case 0: data = 'empty'; break;
      case 1: data = 'short'; break;
      default: data = 'long'; break;
    }
    document.body.innerHTML = data;
  `);
  expect(findings).toBeEmpty();
});

test('ternary sanitizes: DOMPurify on both branches', () => {
  const { findings } = analyze(`
    var raw = location.hash;
    var safe = raw.length > 0 ? DOMPurify.sanitize(raw) : '';
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});

test('Map with only safe static values → no finding', () => {
  const { findings } = analyze(`
    var map = new Map();
    map.set('a', 'hello');
    map.set('b', 'world');
    document.body.innerHTML = map.get('a');
  `);
  expect(findings).toBeEmpty();
});


// ─── Script injection negatives ─────────────────────────

console.log('\n--- Safe: createElement non-script ---');

test('createElement("div") with tainted textContent is safe', () => {
  const { findings } = analyze(`
    var div = document.createElement('div');
    div.textContent = location.hash;
    document.body.appendChild(div);
  `);
  expect(findings).toBeEmpty();
});

test('createElement("img") with static src is safe', () => {
  const { findings } = analyze(`
    var img = document.createElement('img');
    img.src = '/logo.png';
    document.body.appendChild(img);
  `);
  expect(findings).toBeEmpty();
});


// ─── Async/await taint propagation ──────────────────────

console.log('\n--- Async/await advanced ---');

test('async function: tainted resolved value → innerHTML', () => {
  const { findings } = analyze(`
    async function getInput() {
      return location.hash;
    }
    async function render() {
      var html = await getInput();
      document.body.innerHTML = html;
    }
    render();
  `);
  expect(findings).toHaveType('XSS');
});

test('chained .then() with tainted return', () => {
  const { findings } = analyze(`
    var p = Promise.resolve(location.hash);
    p.then(function(val) { return val; })
     .then(function(val) { document.body.innerHTML = val; });
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Computed property access with tainted value ────────

console.log('\n--- Computed property access ---');

test('tainted value read from computed property → innerHTML', () => {
  const { findings } = analyze(`
    var store = { html: location.hash };
    var key = 'html';
    document.body.innerHTML = store[key];
  `);
  expect(findings).toHaveType('XSS');
});

test('dynamic property read from tainted object → innerHTML', () => {
  const { findings } = analyze(`
    var obj = {};
    obj.content = location.hash;
    var prop = 'content';
    document.body.innerHTML = obj[prop];
  `);
  expect(findings).toHaveType('XSS');
});


// ─── String.raw and tagged template edge cases ──────────

console.log('\n--- Tagged templates advanced ---');

test('String.raw with tainted expression → innerHTML', () => {
  const { findings } = analyze(`
    var h = location.hash;
    var raw = String.raw\`\${h}\`;
    document.body.innerHTML = raw;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Void, typeof, delete — safe operators ──────────────

console.log('\n--- Safe: void/typeof/delete ---');

test('typeof tainted is safe (returns string type name)', () => {
  const { findings } = analyze(`
    var t = typeof location.hash;
    document.body.innerHTML = t;
  `);
  expect(findings).toBeEmpty();
});

test('void tainted is safe (always undefined)', () => {
  const { findings } = analyze(`
    var v = void location.hash;
    document.body.innerHTML = v;
  `);
  expect(findings).toBeEmpty();
});


// ╔═══════════════════════════════════════════════════════╗
// ║  ADVANCED AST PATTERNS II — deeper edge cases          ║
// ╚═══════════════════════════════════════════════════════╝


// ─── Destructuring with default values ──────────────────

console.log('\n--- Destructuring with defaults ---');

test('destructuring default from tainted source', () => {
  const { findings } = analyze(`
    var { q = location.hash } = {};
    document.body.innerHTML = q;
  `);
  expect(findings).toHaveType('XSS');
});

test('array destructuring with tainted element', () => {
  const { findings } = analyze(`
    var [first, second] = location.search.split('&');
    document.body.innerHTML = first;
  `);
  expect(findings).toHaveType('XSS');
});

test('nested destructuring extracts tainted value', () => {
  const { findings } = analyze(`
    var obj = { nested: { html: location.hash } };
    var { nested: { html } } = obj;
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

test('destructuring with rename extracts tainted value', () => {
  const { findings } = analyze(`
    var obj = { content: location.hash };
    var { content: myHtml } = obj;
    document.body.innerHTML = myHtml;
  `);
  expect(findings).toHaveType('XSS');
});

test('destructuring safe default when source property exists is safe', () => {
  const { findings } = analyze(`
    var { q = 'default' } = { q: 'safe' };
    document.body.innerHTML = q;
  `);
  expect(findings).toBeEmpty();
});


// ─── Rest/spread patterns ───────────────────────────────

console.log('\n--- Rest/spread taint propagation ---');

test('spread array with tainted elements → innerHTML', () => {
  const { findings } = analyze(`
    var tainted = [location.hash];
    var combined = [...tainted, 'safe'];
    document.body.innerHTML = combined.join('');
  `);
  expect(findings).toHaveType('XSS');
});

test('spread into function call with tainted array', () => {
  const { findings } = analyze(`
    function render(a, b) {
      document.body.innerHTML = a;
    }
    var args = [location.hash, 'safe'];
    render(...args);
  `);
  expect(findings).toHaveType('XSS');
});

test('object spread propagates tainted property', () => {
  const { findings } = analyze(`
    var source = { html: location.hash };
    var merged = { ...source, safe: 'ok' };
    document.body.innerHTML = merged.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('rest parameter collects tainted arg', () => {
  const { findings } = analyze(`
    function sink(...args) {
      document.body.innerHTML = args[0];
    }
    sink(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Generator functions ────────────────────────────────

console.log('\n--- Generator functions ---');

test('generator yields tainted value → next().value → innerHTML', () => {
  const { findings } = analyze(`
    function* gen() {
      yield location.hash;
    }
    var it = gen();
    document.body.innerHTML = it.next().value;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Class fields and private-like patterns ─────────────

console.log('\n--- Class fields ---');

test('class with tainted field set in constructor → render', () => {
  const { findings } = analyze(`
    class Widget {
      constructor(html) {
        this._html = html;
      }
      render() {
        document.body.innerHTML = this._html;
      }
    }
    var w = new Widget(location.hash);
    w.render();
  `);
  expect(findings).toHaveType('XSS');
});

test('class static method returning tainted value', () => {
  const { findings } = analyze(`
    class Config {
      static getInput() { return location.hash; }
    }
    document.body.innerHTML = Config.getInput();
  `);
  expect(findings).toHaveType('XSS');
});


// ─── try-catch taint flow ───────────────────────────────

console.log('\n--- try-catch taint flow ---');

test('taint assigned in try, used after try-catch block', () => {
  const { findings } = analyze(`
    var data;
    try {
      data = location.hash;
    } catch (e) {
      data = 'fallback';
    }
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted value thrown and caught → innerHTML', () => {
  const { findings } = analyze(`
    try {
      throw location.hash;
    } catch (e) {
      document.body.innerHTML = e;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('catch block assigns taint from error message', () => {
  const { findings } = analyze(`
    var data;
    try {
      JSON.parse(location.hash);
    } catch (e) {
      data = location.hash;
    }
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Ternary / conditional expression edge cases ────────

console.log('\n--- Ternary edge cases ---');

test('ternary: both branches tainted → innerHTML', () => {
  const { findings } = analyze(`
    var val = Math.random() > 0.5 ? location.hash : location.search;
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('nested ternary with taint in deep branch', () => {
  const { findings } = analyze(`
    var a = true ? (false ? 'safe' : location.hash) : 'safe2';
    document.body.innerHTML = a;
  `);
  expect(findings).toHaveType('XSS');
});

test('ternary with both branches safe → safe', () => {
  const { findings } = analyze(`
    var val = Math.random() > 0.5 ? 'hello' : 'world';
    document.body.innerHTML = val;
  `);
  expect(findings).toBeEmpty();
});


// ─── Closure capture patterns ───────────────────────────

console.log('\n--- Closure capture ---');

test('closure captures tainted variable across scope', () => {
  const { findings } = analyze(`
    var tainted = location.hash;
    function outer() {
      function inner() {
        document.body.innerHTML = tainted;
      }
      inner();
    }
    outer();
  `);
  expect(findings).toHaveType('XSS');
});

test('returned closure captures tainted value', () => {
  const { findings } = analyze(`
    function makeRenderer() {
      var data = location.hash;
      return function() {
        document.body.innerHTML = data;
      };
    }
    var render = makeRenderer();
    render();
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Multiple assignment targets ────────────────────────

console.log('\n--- Multiple assignment targets ---');

test('destructured array from tainted split → two sinks', () => {
  const { findings } = analyze(`
    var [a, b] = location.search.split('=');
    document.body.innerHTML = b;
  `);
  expect(findings).toHaveType('XSS');
});

test('comma-separated var declarations with taint chain', () => {
  const { findings } = analyze(`
    var a = location.hash, b = a.slice(1), c = b.toUpperCase();
    document.body.innerHTML = c;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── While/do-while loop taint ──────────────────────────

console.log('\n--- Loop taint patterns ---');

test('while loop reading tainted input → innerHTML', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    var i = 0;
    var html = '';
    while (i < items.length) {
      html += items[i];
      i++;
    }
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

test('do-while loop with tainted accumulation', () => {
  const { findings } = analyze(`
    var parts = location.search.split('&');
    var result = '';
    var i = 0;
    do {
      result += parts[i] || '';
      i++;
    } while (i < parts.length);
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Chained method calls edge cases ────────────────────

console.log('\n--- Chained method edge cases ---');

test('location.hash.split().reverse().join() → innerHTML', () => {
  const { findings } = analyze(`
    var reversed = location.hash.split('').reverse().join('');
    document.body.innerHTML = reversed;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.replace().replace().trim() → innerHTML', () => {
  const { findings } = analyze(`
    var clean = location.hash.replace('#', '').replace('/', '').trim();
    document.body.innerHTML = clean;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.padStart() → innerHTML', () => {
  const { findings } = analyze(`
    var padded = location.hash.padStart(10, '0');
    document.body.innerHTML = padded;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.repeat() → innerHTML', () => {
  const { findings } = analyze(`
    var repeated = location.hash.repeat(2);
    document.body.innerHTML = repeated;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── new Function() as sink ─────────────────────────────

console.log('\n--- new Function() sink ---');

test('new Function(tainted) is XSS', () => {
  const { findings } = analyze(`
    var code = location.hash.slice(1);
    var fn = new Function(code);
    fn();
  `);
  expect(findings).toHaveType('XSS');
});

test('new Function with safe string → safe', () => {
  const { findings } = analyze(`
    var fn = new Function('return 42');
    document.body.innerHTML = fn();
  `);
  expect(findings).toBeEmpty();
});


// ─── document.write / writeln ───────────────────────────

console.log('\n--- document.write/writeln ---');

test('document.write with tainted data', () => {
  const { findings } = analyze(`
    var h = location.hash;
    document.write('<div>' + h + '</div>');
  `);
  expect(findings).toHaveType('XSS');
});

test('document.writeln with tainted data', () => {
  const { findings } = analyze(`
    document.writeln(location.search);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── outerHTML / srcdoc sinks ───────────────────────────

console.log('\n--- outerHTML / srcdoc sinks ---');

test('outerHTML with tainted data is XSS', () => {
  const { findings } = analyze(`
    document.body.outerHTML = location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

test('iframe.srcdoc with tainted data is XSS', () => {
  const { findings } = analyze(`
    var iframe = document.createElement('iframe');
    iframe.srcdoc = location.hash;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── jQuery sinks ───────────────────────────────────────

console.log('\n--- jQuery sinks ---');

test('$.html(tainted) is XSS', () => {
  const { findings } = analyze(`
    var data = location.hash;
    $.html(data);
  `);
  expect(findings).toHaveType('XSS');
});

test('jQuery.append(tainted) is XSS', () => {
  const { findings } = analyze(`
    jQuery.append(location.search);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Short-circuit evaluation ───────────────────────────

console.log('\n--- Short-circuit evaluation ---');

test('safe || tainted: right side is tainted → innerHTML', () => {
  const { findings } = analyze(`
    var val = '' || location.hash;
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted && safe: safe last but tainted path → innerHTML', () => {
  const { findings } = analyze(`
    var val = location.hash && 'safe';
    document.body.innerHTML = val;
  `);
  // Both branches possible: could be tainted (falsy hash) or safe string
  // Engine conservatively reports taint present
  expect(findings).toHaveType('XSS');
});


// ─── Recursive function with taint ──────────────────────

console.log('\n--- Recursive function ---');

test('recursive function passing tainted value through', () => {
  const { findings } = analyze(`
    function process(data, depth) {
      if (depth > 3) {
        document.body.innerHTML = data;
        return;
      }
      process(data, depth + 1);
    }
    process(location.hash, 0);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through array push/pop ───────────────────────

console.log('\n--- Array push/pop taint ---');

test('push tainted value, then access array → innerHTML', () => {
  const { findings } = analyze(`
    var arr = [];
    arr.push(location.hash);
    document.body.innerHTML = arr[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('push tainted, join → innerHTML', () => {
  const { findings } = analyze(`
    var parts = [];
    parts.push(location.hash);
    parts.push(location.search);
    document.body.innerHTML = parts.join('');
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Event handler patterns ─────────────────────────────

console.log('\n--- Event handler patterns ---');

test('hashchange event → newURL → innerHTML', () => {
  const { findings } = analyze(`
    window.addEventListener('hashchange', function(event) {
      document.body.innerHTML = event.newURL;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('DOMParser.parseFromString with tainted input', () => {
  const { findings } = analyze(`
    var parser = new DOMParser();
    var doc = parser.parseFromString(location.hash, 'text/html');
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Template literal only with safe expressions ────────

console.log('\n--- Safe: template literals with safe data ---');

test('template literal with only safe interpolations', () => {
  const { findings } = analyze(`
    var name = 'Alice';
    var count = 42;
    document.body.innerHTML = \`<p>\${name}: \${count}</p>\`;
  `);
  expect(findings).toBeEmpty();
});

test('template literal with sanitized taint', () => {
  const { findings } = analyze(`
    var h = parseInt(location.hash.slice(1), 10);
    document.body.innerHTML = \`<p>Page \${h}</p>\`;
  `);
  expect(findings).toBeEmpty();
});


// ─── Taint through string concatenation variants ────────

console.log('\n--- String concat variants ---');

test('Array.prototype.join.call with tainted array', () => {
  const { findings } = analyze(`
    var arr = [location.hash, 'safe'];
    var result = Array.prototype.join.call(arr, '');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('string + number with tainted string → innerHTML', () => {
  const { findings } = analyze(`
    var msg = location.hash + 42;
    document.body.innerHTML = msg;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Safe: forEach with sanitization ────────────────────

console.log('\n--- Safe: sanitized in loop ---');

test('forEach sanitizes each element before sink', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    items.forEach(function(item) {
      document.body.innerHTML += encodeURIComponent(item);
    });
  `);
  expect(findings).toBeEmpty();
});


// ─── Conditional (ternary) sanitization ─────────────────

console.log('\n--- Safe: conditional sanitization ---');

test('ternary: sanitized in truthy, safe literal in falsy', () => {
  const { findings } = analyze(`
    var raw = location.hash;
    var safe = raw ? DOMPurify.sanitize(raw) : '';
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});


// ─── Assignment to different objects ────────────────────

console.log('\n--- Property isolation ---');

test('taint on obj.a does not leak to obj.b', () => {
  const { findings } = analyze(`
    var obj = {};
    obj.tainted = location.hash;
    obj.safe = 'hello';
    document.body.innerHTML = obj.safe;
  `);
  expect(findings).toBeEmpty();
});

test('taint on one map key does not leak to another', () => {
  const { findings } = analyze(`
    var map = new Map();
    map.set('dirty', location.hash);
    map.set('clean', 'safe');
    document.body.innerHTML = map.get('clean');
  `);
  expect(findings).toBeEmpty();
});


// ─── Multiple sources same sink ─────────────────────────

console.log('\n--- Multiple sources to same sink ---');

test('hash + cookie + search concatenated → innerHTML', () => {
  const { findings } = analyze(`
    var a = location.hash;
    var b = document.cookie;
    var c = location.search;
    document.body.innerHTML = a + b + c;
  `);
  expect(findings).toHaveType('XSS');
  expect(findings).toHaveAtLeast(1);
});


// ─── Complex control flow ───────────────────────────────

console.log('\n--- Complex control flow ---');

test('taint in one branch of if-else, safe in other, both sink', () => {
  const { findings } = analyze(`
    var html;
    if (Math.random() > 0.5) {
      html = location.hash;
    } else {
      html = 'safe';
    }
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

test('loop builds tainted string then sinks', () => {
  const { findings } = analyze(`
    var params = location.search.slice(1).split('&');
    var html = '<ul>';
    for (var i = 0; i < params.length; i++) {
      html += '<li>' + params[i] + '</li>';
    }
    html += '</ul>';
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

test('switch with taint only in one case, but no break → falls through', () => {
  const { findings } = analyze(`
    var content;
    var mode = 'user';
    switch (mode) {
      case 'user':
        content = location.hash;
      case 'admin':
        document.body.innerHTML = content;
        break;
    }
  `);
  expect(findings).toHaveType('XSS');
});


// ─── String method chain that sanitizes ─────────────────

console.log('\n--- Safe: string method sanitization ---');

test('parseInt on chained tainted value kills taint', () => {
  const { findings } = analyze(`
    var page = parseInt(location.hash.slice(1).split('&')[0], 10);
    document.body.innerHTML = page;
  `);
  expect(findings).toBeEmpty();
});


// ╔═══════════════════════════════════════════════════════╗
// ║  ADVANCED AST PATTERNS III — real-world edge cases     ║
// ╚═══════════════════════════════════════════════════════╝


// ─── Prototype method assignment patterns ───────────────

console.log('\n--- Prototype method patterns ---');

test('Constructor.prototype.method sets this.x, used in another prototype method', () => {
  const { findings } = analyze(`
    function Widget() {}
    Widget.prototype.load = function(data) { this.content = data; };
    Widget.prototype.render = function() { document.body.innerHTML = this.content; };
    var w = new Widget();
    w.load(location.hash);
    w.render();
  `);
  expect(findings).toHaveType('XSS');
});

test('prototype method chain: this.process().render()', () => {
  const { findings } = analyze(`
    function App() {}
    App.prototype.setData = function(d) { this.html = d; return this; };
    App.prototype.render = function() { document.body.innerHTML = this.html; };
    var a = new App();
    a.setData(location.hash).render();
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint via class inheritance pattern ────────────────

console.log('\n--- Class patterns ---');

test('class method calls super-like helper that sinks', () => {
  const { findings } = analyze(`
    class Base {
      output(html) { document.body.innerHTML = html; }
    }
    class Derived {
      render(data) { this.output(data); }
      output(html) { document.body.innerHTML = html; }
    }
    var d = new Derived();
    d.render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('class with computed method name (static string)', () => {
  const { findings } = analyze(`
    class View {
      ['render'](html) { document.body.innerHTML = html; }
    }
    var v = new View();
    v.render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Callback patterns: event emitter style ─────────────

console.log('\n--- Callback: event emitter style ---');

test('register callback, invoke with tainted data', () => {
  const { findings } = analyze(`
    var handlers = [];
    function on(fn) { handlers.push(fn); }
    function emit(data) { handlers[0](data); }
    on(function(d) { document.body.innerHTML = d; });
    emit(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('higher-order: function returns tainted via callback', () => {
  const { findings } = analyze(`
    function withData(callback) {
      var data = location.hash;
      callback(data);
    }
    withData(function(d) {
      document.body.innerHTML = d;
    });
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through property shorthand ───────────────────

console.log('\n--- Property shorthand ---');

test('shorthand property propagates taint', () => {
  const { findings } = analyze(`
    var content = location.hash;
    var obj = { content };
    document.body.innerHTML = obj.content;
  `);
  expect(findings).toHaveType('XSS');
});

test('shorthand destructuring from tainted object', () => {
  const { findings } = analyze(`
    var data = { html: location.hash, id: 42 };
    var { html, id } = data;
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Cross-scope taint through module pattern ───────────

console.log('\n--- Module pattern ---');

test('IIFE module: method returns tainted internal state', () => {
  const { findings } = analyze(`
    var mod = (function() {
      var data;
      return {
        setData: function(d) { data = d; },
        render: function() { document.body.innerHTML = data; }
      };
    })();
    mod.setData(location.hash);
    mod.render();
  `);
  expect(findings).toHaveType('XSS');
});

test('revealing module: returned function accesses closure taint', () => {
  const { findings } = analyze(`
    var mod = (function() {
      function render(html) {
        document.body.innerHTML = html;
      }
      return { render: render };
    })();
    mod.render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── URL constructor taint flow ─────────────────────────

console.log('\n--- URL constructor taint ---');

test('new URL(tainted).href → location.href is XSS', () => {
  const { findings } = analyze(`
    var raw = location.hash.slice(1);
    var url = new URL(raw);
    location.href = url.href;
  `);
  expect(findings).toHaveType('XSS');
});

test('new URL(tainted).searchParams.get() → innerHTML', () => {
  const { findings } = analyze(`
    var url = new URL(location.href);
    var q = url.searchParams.get('q');
    document.body.innerHTML = q;
  `);
  expect(findings).toHaveType('XSS');
});

test('new URLSearchParams(tainted).get() → eval', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    var code = params.get('code');
    eval(code);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Deep interprocedural: 3+ function hops ────────────

console.log('\n--- Deep interprocedural ---');

test('A calls B calls C: taint through 3 hops to sink', () => {
  const { findings } = analyze(`
    function a(x) { return b(x); }
    function b(x) { return c(x); }
    function c(x) { document.body.innerHTML = x; }
    a(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('factory → method → helper → sink', () => {
  const { findings } = analyze(`
    function createApp() {
      return {
        show: function(html) { render(html); }
      };
    }
    function render(html) {
      document.body.innerHTML = html;
    }
    var app = createApp();
    app.show(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through array methods: every/some/findIndex ──

console.log('\n--- Array methods: every/some/findIndex ---');

test('array.some callback receives tainted element → sink inside', () => {
  const { findings } = analyze(`
    var items = [location.hash, 'safe'];
    items.some(function(item) {
      document.body.innerHTML = item;
      return true;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('array.every callback with tainted data → innerHTML', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    items.every(function(item) {
      document.body.innerHTML += item;
      return true;
    });
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through conditional assignment ───────────────

console.log('\n--- Conditional assignment ---');

test('ternary assigns tainted in only one path → tainted', () => {
  const { findings } = analyze(`
    var x = Math.random() > 0.5 ? location.hash : location.search;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('&&= with tainted value', () => {
  const { findings } = analyze(`
    var data = 'initial';
    data &&= location.hash;
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through string methods not yet tested ────────

console.log('\n--- String methods: slice/at/charAt ---');

test('tainted.at(0) preserves taint', () => {
  const { findings } = analyze(`
    var h = location.hash;
    var first = h.at(0);
    document.body.innerHTML = first;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.charAt(0) preserves taint', () => {
  const { findings } = analyze(`
    document.body.innerHTML = location.hash.charAt(0);
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.normalize() preserves taint', () => {
  const { findings } = analyze(`
    var n = location.hash.normalize('NFC');
    document.body.innerHTML = n;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.valueOf() preserves taint', () => {
  const { findings } = analyze(`
    var v = location.hash.valueOf();
    document.body.innerHTML = v;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.replaceAll() preserves taint', () => {
  const { findings } = analyze(`
    var clean = location.hash.replaceAll('#', '');
    document.body.innerHTML = clean;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through JSON round-trip ──────────────────────

console.log('\n--- JSON round-trip ---');

test('JSON.parse(JSON.stringify(tainted)) preserves taint', () => {
  const { findings } = analyze(`
    var data = location.hash;
    var serialized = JSON.stringify(data);
    var parsed = JSON.parse(serialized);
    document.body.innerHTML = parsed;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── postMessage via object destructuring ───────────────

console.log('\n--- postMessage: destructured data ---');

test('message handler: destructured event.data → innerHTML', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(event) {
      var data = event.data;
      var html = data;
      document.body.innerHTML = html;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('message handler: event.data.html → innerHTML', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      document.body.innerHTML = e.data.html;
    });
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through multiple reassignment hops ───────────

console.log('\n--- Variable reassignment chains ---');

test('taint through 5 variable hops', () => {
  const { findings } = analyze(`
    var a = location.hash;
    var b = a;
    var c = b;
    var d = c;
    var e = d;
    document.body.innerHTML = e;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through property chain: a.x = b.y = tainted', () => {
  const { findings } = analyze(`
    var obj = {};
    var cfg = {};
    obj.html = cfg.data = location.hash;
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── document.location aliases ──────────────────────────

console.log('\n--- document.location aliases ---');

test('document.location.href → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.location.href;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.location.search → innerHTML', () => {
  const { findings } = analyze(`
    var q = document.location.search;
    document.body.innerHTML = q;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.location.pathname → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.location.pathname;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── window.location direct assignment (XSS) ───────────

console.log('\n--- window.location direct assignment ---');

test('window.location = tainted is XSS', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    window.location = url;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through Set iteration ────────────────────────

console.log('\n--- Set iteration ---');

test('Set.add(tainted) then for-of over Set → innerHTML', () => {
  const { findings } = analyze(`
    var s = new Set();
    s.add(location.hash);
    for (var item of s) {
      document.body.innerHTML = item;
    }
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Complex negative: taint killed mid-chain ───────────

console.log('\n--- Safe: taint killed mid-chain ---');

test('tainted → sanitized in function → returned → innerHTML', () => {
  const { findings } = analyze(`
    function sanitize(raw) {
      return DOMPurify.sanitize(raw);
    }
    function process(input) {
      return sanitize(input);
    }
    document.body.innerHTML = process(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('taint killed by Number() in middle of chain', () => {
  const { findings } = analyze(`
    var raw = location.hash.slice(1);
    var id = Number(raw);
    var html = '<div data-id="' + id + '">Hello</div>';
    document.body.innerHTML = html;
  `);
  expect(findings).toBeEmpty();
});

test('ternary: both branches sanitized → safe', () => {
  const { findings } = analyze(`
    var raw = location.hash;
    var safe = raw.length > 10
      ? encodeURIComponent(raw)
      : DOMPurify.sanitize(raw);
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});

test('tainted assigned to property, then property overwritten with safe', () => {
  const { findings } = analyze(`
    var config = {};
    config.html = location.hash;
    config.html = 'safe content';
    document.body.innerHTML = config.html;
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: shorthand property with safe value ───────────

console.log('\n--- Safe: shorthand and destructuring ---');

test('shorthand property with safe variable → innerHTML', () => {
  const { findings } = analyze(`
    var content = 'hello world';
    var obj = { content };
    document.body.innerHTML = obj.content;
  `);
  expect(findings).toBeEmpty();
});

test('destructuring non-tainted fields from mixed object', () => {
  const { findings } = analyze(`
    var obj = { safe: 'hello', tainted: location.hash };
    var { safe } = obj;
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: class method that sanitizes ──────────────────

console.log('\n--- Safe: class sanitization ---');

test('class method sanitizes before rendering', () => {
  const { findings } = analyze(`
    class SafeRenderer {
      render(html) {
        var clean = DOMPurify.sanitize(html);
        document.body.innerHTML = clean;
      }
    }
    var r = new SafeRenderer();
    r.render(location.hash);
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: JSON.stringify is not a sink ─────────────────

console.log('\n--- Safe: JSON.stringify chain ---');

test('JSON.stringify of tainted → textContent is safe', () => {
  const { findings } = analyze(`
    var data = { q: location.hash };
    document.body.textContent = JSON.stringify(data);
  `);
  expect(findings).toBeEmpty();
});


// ─── Safe: tainted only in unused branch ────────────────

console.log('\n--- Safe: unused taint paths ---');

test('tainted var declared but only safe var reaches sink', () => {
  const { findings } = analyze(`
    var tainted = location.hash;
    var output = 'Welcome, user!';
    document.body.innerHTML = output;
  `);
  expect(findings).toBeEmpty();
});

test('function receives tainted but returns sanitized value', () => {
  const { findings } = analyze(`
    function process(input) {
      var n = parseInt(input, 10);
      return '<span>' + n + '</span>';
    }
    document.body.innerHTML = process(location.hash);
  `);
  expect(findings).toBeEmpty();
});


// ─── Open Redirect: additional patterns ─────────────────

console.log('\n--- Open Redirect: additional ---');

test('new URL(tainted).protocol === "https:" → window.location = Open Redirect', () => {
  const { findings } = analyze(`
    var raw = location.hash.slice(1);
    var parsed = new URL(raw);
    if (parsed.protocol === 'https:') {
      window.location = parsed.href;
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('ternary with scheme check → location.assign is Open Redirect', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    url.startsWith('http') ? location.assign(url) : null;
  `);
  expect(findings).toHaveType('Open Redirect');
});


// ─── Taint through decodeURIComponent chain ─────────────

console.log('\n--- Passthrough chains ---');

test('decodeURIComponent(atob(tainted)) → innerHTML', () => {
  const { findings } = analyze(`
    var encoded = location.hash.slice(1);
    var decoded = decodeURIComponent(atob(encoded));
    document.body.innerHTML = decoded;
  `);
  expect(findings).toHaveType('XSS');
});

test('JSON.parse(decodeURIComponent(tainted)) → innerHTML', () => {
  const { findings } = analyze(`
    var raw = decodeURIComponent(location.search.slice(1));
    var data = JSON.parse(raw);
    document.body.innerHTML = data.html;
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Cross-file: complex patterns ───────────────────────

console.log('\n--- Cross-file: advanced ---');

test('factory in file A, tainted call in file B, sink in file C', () => {
  const findings = analyzeMultiple([
    { source: `function createRenderer() { return function(html) { document.body.innerHTML = html; }; }`, file: 'factory.js' },
    { source: `var render = createRenderer();`, file: 'setup.js' },
    { source: `render(location.hash);`, file: 'main.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

test('class in file A, instantiated with tainted data in file B', () => {
  const findings = analyzeMultiple([
    { source: `class Panel { constructor(h) { this.html = h; } render() { document.body.innerHTML = this.html; } }`, file: 'panel.js' },
    { source: `var p = new Panel(location.hash); p.render();`, file: 'app.js' },
  ]);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through conditional function call ────────────

console.log('\n--- Conditional function call ---');

test('function called only in if branch still analyzed', () => {
  const { findings } = analyze(`
    function render(html) {
      document.body.innerHTML = html;
    }
    var h = location.hash;
    if (h.length > 0) {
      render(h);
    }
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through array literal with spread ────────────

console.log('\n--- Array spread patterns ---');

test('[...taintedArray, safe].join() → innerHTML', () => {
  const { findings } = analyze(`
    var parts = location.search.split('&');
    var all = [...parts, 'end'];
    document.body.innerHTML = all.join(' ');
  `);
  expect(findings).toHaveType('XSS');
});

test('Object.keys/values of tainted object', () => {
  const { findings } = analyze(`
    var params = { q: location.hash };
    var vals = Object.values(params);
    document.body.innerHTML = vals.join('');
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through String constructor ───────────────────

console.log('\n--- String constructor ---');

test('new String(tainted).toString() → innerHTML', () => {
  const { findings } = analyze(`
    var s = new String(location.hash);
    document.body.innerHTML = s.toString();
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint through setTimeout/setInterval with string arg ──

console.log('\n--- setTimeout/setInterval string arg ---');

test('setTimeout(taintedString) is XSS', () => {
  const { findings } = analyze(`
    var code = location.hash.slice(1);
    setTimeout(code, 0);
  `);
  expect(findings).toHaveType('XSS');
});

test('setInterval(taintedString) is XSS', () => {
  const { findings } = analyze(`
    var code = location.hash.slice(1);
    setInterval(code, 1000);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Negative: array callback isolates taint correctly ──

console.log('\n--- Safe: array callback isolation ---');

test('findIndex returns number, not tainted element', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    var idx = items.findIndex(function(x) { return x.startsWith('q='); });
    document.body.innerHTML = idx;
  `);
  expect(findings).toBeEmpty();
});

test('some() returns boolean, not tainted element', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    var has = items.some(function(x) { return x === 'admin'; });
    document.body.innerHTML = has;
  `);
  expect(findings).toBeEmpty();
});

test('every() returns boolean, not tainted element', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    var all = items.every(function(x) { return x.length > 0; });
    document.body.innerHTML = all;
  `);
  expect(findings).toBeEmpty();
});

test('indexOf on tainted array returns number', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    var pos = items.indexOf('admin');
    document.body.innerHTML = pos;
  `);
  expect(findings).toBeEmpty();
});


// ─── UpdateExpression kills taint (i++, --x) ────────────

console.log('\n--- Safe: update expressions ---');

test('i++ is always numeric → safe', () => {
  const { findings } = analyze(`
    var i = location.hash.length;
    i++;
    document.body.innerHTML = i;
  `);
  expect(findings).toBeEmpty();
});


// ─── Taint through chained promise: .catch().then() ─────

console.log('\n--- Promise: catch/finally chains ---');

test('.catch() callback receives taint → innerHTML', () => {
  const { findings } = analyze(`
    var p = Promise.resolve(location.hash);
    p.catch(function(err) { return err; })
     .then(function(val) { document.body.innerHTML = val; });
  `);
  expect(findings).toHaveType('XSS');
});

test('.finally() does not receive value, original taint preserved', () => {
  const { findings } = analyze(`
    var p = Promise.resolve(location.hash);
    p.finally(function() { console.log('done'); })
     .then(function(val) { document.body.innerHTML = val; });
  `);
  expect(findings).toHaveType('XSS');
});


// ─── window.name as source ──────────────────────────────

console.log('\n--- window.name as source ---');

test('window.name → eval', () => {
  const { findings } = analyze(`
    eval(window.name);
  `);
  expect(findings).toHaveType('XSS');
});

test('window.name → document.write', () => {
  const { findings } = analyze(`
    document.write(window.name);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Mixed sources: cookie + URL ────────────────────────

console.log('\n--- Mixed sources ---');

test('document.cookie → template literal → innerHTML', () => {
  const { findings } = analyze(`
    var cookie = document.cookie;
    document.body.innerHTML = \`<div>\${cookie}</div>\`;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.referrer → location.assign is XSS', () => {
  const { findings } = analyze(`
    location.assign(document.referrer);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Taint from assignment expression used inline ───────

console.log('\n--- Inline assignment expressions ---');

test('sink uses (x = tainted) inline', () => {
  const { findings } = analyze(`
    var x;
    eval(x = location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted assigned inline within function arg', () => {
  const { findings } = analyze(`
    var h;
    document.write(h = location.hash);
  `);
  expect(findings).toHaveType('XSS');
});


// ─── Negative: safe navigation patterns ─────────────────

console.log('\n--- Safe: navigation patterns ---');

test('hardcoded relative path → location.href is safe', () => {
  const { findings } = analyze(`
    location.href = '/dashboard';
  `);
  expect(findings).toBeEmpty();
});

test('safe computed URL from static parts → location.assign is safe', () => {
  const { findings } = analyze(`
    var base = 'https://example.com';
    var path = '/page';
    location.assign(base + path);
  `);
  expect(findings).toBeEmpty();
});


// ─── Logical nullish assignment with no prior taint ─────

console.log('\n--- Safe: logical assignment with safe values ---');

test('??= with safe value only → safe', () => {
  const { findings } = analyze(`
    var data = null;
    data ??= 'safe default';
    document.body.innerHTML = data;
  `);
  expect(findings).toBeEmpty();
});

test('||= with safe value only → safe', () => {
  const { findings } = analyze(`
    var data = '';
    data ||= '<p>Default</p>';
    document.body.innerHTML = data;
  `);
  expect(findings).toBeEmpty();
});


// ─── Taint through Object.values/Object.keys/Object.entries ──

console.log('\n--- Object.values/keys/entries ---');

test('Object.entries of tainted object → forEach → innerHTML', () => {
  const { findings } = analyze(`
    var config = { html: location.hash };
    Object.entries(config).forEach(function(pair) {
      document.body.innerHTML += pair[1];
    });
  `);
  expect(findings).toHaveType('XSS');
});


// ╔═══════════════════════════════════════════════════════╗
// ║  ROUND 4 — Advanced AST patterns & edge cases          ║
// ╚═══════════════════════════════════════════════════════╝

// ── Tagged template literals ──
console.log('\n--- Tagged template literals ---');

test('tagged template with tainted expression → innerHTML', () => {
  const { findings } = analyze(`
    function html(strings, ...vals) { return strings.reduce((r,s,i) => r + s + (vals[i]||''), ''); }
    var x = html\`<div>\${location.hash}</div>\`;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('tagged template: safe literal only → no finding', () => {
  const { findings } = analyze(`
    function html(strings, ...vals) { return strings.reduce((r,s,i) => r + s + (vals[i]||''), ''); }
    var x = html\`<div>hello</div>\`;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── self.location / globalThis.location sources ──
console.log('\n--- self/globalThis location sources ---');

test('self.location.hash → innerHTML', () => {
  const { findings } = analyze(`
    var x = self.location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('self.location.search → eval', () => {
  const { findings } = analyze(`
    eval(self.location.search);
  `);
  expect(findings).toHaveType('XSS');
});

test('globalThis.location.hash → innerHTML', () => {
  const { findings } = analyze(`
    var x = globalThis.location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('globalThis.location.search → document.write', () => {
  const { findings } = analyze(`
    document.write(globalThis.location.search);
  `);
  expect(findings).toHaveType('XSS');
});

// ── URLSearchParams.getAll() ──
console.log('\n--- URLSearchParams.getAll ---');

test('URLSearchParams.getAll → forEach → innerHTML', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    params.getAll('tag').forEach(function(t) {
      document.body.innerHTML += t;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── decodeURI passthrough ──
console.log('\n--- decodeURI passthrough ---');

test('decodeURI(location.hash) → innerHTML', () => {
  const { findings } = analyze(`
    var x = decodeURI(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: typeof / instanceof / in kill taint ──
console.log('\n--- Safe: typeof/instanceof/in ---');

test('typeof tainted → innerHTML is safe (boolean/string result)', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var t = typeof x;
    document.body.innerHTML = t;
  `);
  expect(findings).toBeEmpty();
});

test('void tainted → innerHTML is safe', () => {
  const { findings } = analyze(`
    var x = void location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('!tainted → innerHTML is safe (boolean)', () => {
  const { findings } = analyze(`
    var x = !location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('~tainted → innerHTML is safe (bitwise number)', () => {
  const { findings } = analyze(`
    var x = ~location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('+tainted (unary plus) → innerHTML is safe (numeric)', () => {
  const { findings } = analyze(`
    var x = +location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('-tainted (unary minus) → innerHTML is safe (numeric)', () => {
  const { findings } = analyze(`
    var x = -location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: charCodeAt returns number ──
console.log('\n--- Safe: charCodeAt/codePointAt ---');

test('tainted.charCodeAt(0) → innerHTML is safe', () => {
  const { findings } = analyze(`
    var code = location.hash.charCodeAt(0);
    document.body.innerHTML = code;
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: sanitizer coverage ──
console.log('\n--- Safe: sanitizer variants ---');

test('Math.ceil(tainted) → innerHTML is safe', () => {
  const { findings } = analyze(`
    var x = Math.ceil(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('Boolean(tainted) → innerHTML is safe', () => {
  const { findings } = analyze(`
    var x = Boolean(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('encodeURI(tainted) → innerHTML is safe', () => {
  const { findings } = analyze(`
    var x = encodeURI(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('escape(tainted) → innerHTML is safe', () => {
  const { findings } = analyze(`
    var x = escape(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Prototype pollution: Object.assign / Object.create ──
console.log('\n--- Object.assign/create patterns ---');

test('Object.assign({}, tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var src = { html: location.hash };
    var merged = Object.assign({}, src);
    document.body.innerHTML = merged.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('Object.assign with multiple sources, one tainted → innerHTML', () => {
  const { findings } = analyze(`
    var safe = { a: 'hi' };
    var bad = { b: location.hash };
    var merged = Object.assign({}, safe, bad);
    document.body.innerHTML = merged.b;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Class inheritance ──
console.log('\n--- Class inheritance ---');

test('subclass inherits parent method that sinks tainted data', () => {
  const { findings } = analyze(`
    class Base {
      render(html) { document.body.innerHTML = html; }
    }
    class Child extends Base {}
    var c = new Child();
    c.render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('class with super() in constructor passes tainted arg', () => {
  const { findings } = analyze(`
    class Base {
      constructor(data) { document.body.innerHTML = data; }
    }
    class Child extends Base {
      constructor(x) { super(x); }
    }
    new Child(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Nested try-catch-finally ──
console.log('\n--- Nested try-catch-finally ---');

test('tainted thrown, caught, re-thrown, caught again → innerHTML', () => {
  const { findings } = analyze(`
    try {
      try {
        throw location.hash;
      } catch (inner) {
        throw inner;
      }
    } catch (outer) {
      document.body.innerHTML = outer;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('finally block does not receive tainted exception value', () => {
  const { findings } = analyze(`
    var clean = "safe";
    try {
      throw location.hash;
    } catch(e) {
      // caught
    } finally {
      document.body.innerHTML = clean;
    }
  `);
  expect(findings).toBeEmpty();
});

// ── Switch fall-through ──
console.log('\n--- Switch fall-through ---');

test('switch fall-through: tainted assigned in one case, used after break in another', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var result;
    switch(x.length) {
      case 1:
        result = x;
      case 2:
        result = result || 'default';
        break;
    }
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Indirect eval ──
console.log('\n--- Indirect eval ---');

test('(0, eval)(tainted) is still XSS', () => {
  const { findings } = analyze(`
    var x = location.hash;
    (0, eval)(x);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Recursive function with tainted arg ──
console.log('\n--- Recursive taint propagation ---');

test('recursive function with tainted arg eventually sinks', () => {
  const { findings } = analyze(`
    function process(data, depth) {
      if (depth === 0) {
        document.body.innerHTML = data;
        return;
      }
      process(data, depth - 1);
    }
    process(location.hash, 3);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Getter/setter patterns ──
console.log('\n--- Getter/setter-like patterns ---');

test('setter method stores taint, getter method retrieves it → innerHTML', () => {
  const { findings } = analyze(`
    class Store {
      setData(d) { this.data = d; }
      getData() { return this.data; }
    }
    var s = new Store();
    s.setData(location.hash);
    document.body.innerHTML = s.getData();
  `);
  expect(findings).toHaveType('XSS');
});

// ── for-of with destructuring ──
console.log('\n--- for-of with destructuring ---');

test('for-of destructuring array of tainted objects → innerHTML', () => {
  const { findings } = analyze(`
    var items = [{ html: location.hash }];
    for (var { html } of items) {
      document.body.innerHTML = html;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Comma/sequence expression ──
console.log('\n--- Sequence expression ---');

test('sequence expression: last value is tainted → innerHTML', () => {
  const { findings } = analyze(`
    var x = (0, location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('sequence expression: only first value tainted, last safe → no finding', () => {
  const { findings } = analyze(`
    var x = (location.hash, "safe");
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Reduce with tainted accumulator ──
console.log('\n--- Array.reduce taint propagation ---');

test('reduce with tainted initial value → innerHTML', () => {
  const { findings } = analyze(`
    var parts = ['<b>', '</b>'];
    var result = parts.reduce(function(acc, s) { return acc + s; }, location.hash);
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('reduce over tainted array → innerHTML', () => {
  const { findings } = analyze(`
    var parts = [location.hash, 'safe'];
    var result = parts.reduce(function(acc, s) { return acc + s; }, '');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Promise.all / Promise.race ──
console.log('\n--- Promise.all/race ---');

test('Promise.all then destructure tainted → innerHTML', () => {
  const { findings } = analyze(`
    var p = Promise.resolve(location.hash);
    Promise.all([p]).then(function(results) {
      document.body.innerHTML = results[0];
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Array.from with mapping ──
console.log('\n--- Array.from ---');

test('Array.from(tainted) preserves taint → innerHTML', () => {
  const { findings } = analyze(`
    var x = Array.from(location.hash);
    document.body.innerHTML = x.join('');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Optional chaining call ──
console.log('\n--- Optional chaining call ---');

test('obj?.method?.(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    var obj = { render: render };
    obj?.render?.(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Computed property access with tainted key (safe: returns value not key) ──
console.log('\n--- Computed property access ---');

test('obj[taintedKey] → innerHTML (tainted value accessed via tainted key)', () => {
  const { findings } = analyze(`
    var templates = { x: location.hash };
    var key = 'x';
    document.body.innerHTML = templates[key];
  `);
  expect(findings).toHaveType('XSS');
});

// ── Event delegation: click handler with tainted target ──
console.log('\n--- DOM event edge cases ---');

test('hashchange: event.newURL through variable chain → innerHTML', () => {
  const { findings } = analyze(`
    window.addEventListener('hashchange', function(e) {
      var url = e.newURL;
      var path = url.split('#')[1];
      document.body.innerHTML = path;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── iframe.src assignment ──
console.log('\n--- Navigation sink edge cases ---');

test('location.href = tainted via intermediate variable', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    location.href = url;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.location = tainted is XSS', () => {
  const { findings } = analyze(`
    document.location = location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Multiple message listeners ──
console.log('\n--- Multiple event listeners ---');

test('two message listeners, one without origin check → XSS', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin !== 'https://trusted.com') return;
      document.body.innerHTML = e.data;
    });
    window.addEventListener('message', function(e) {
      document.body.innerHTML = e.data;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Ternary with function call in branch ──
console.log('\n--- Ternary edge cases ---');

test('ternary: tainted in function call branch → innerHTML', () => {
  const { findings } = analyze(`
    function getContent() { return location.hash; }
    var x = true ? getContent() : 'safe';
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── String concatenation ordering ──
console.log('\n--- String concatenation variants ---');

test('tainted + "" (right side safe) → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash + "";
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('"" + tainted (left side safe) → innerHTML', () => {
  const { findings } = analyze(`
    var x = "" + location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Chained sanitizer ──
console.log('\n--- Chained sanitizer ---');

test('DOMPurify.sanitize(escapeHtml(tainted)) → safe', () => {
  const { findings } = analyze(`
    var x = DOMPurify.sanitize(escapeHtml(location.hash));
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Async patterns ──
console.log('\n--- Async patterns ---');

test('async function: multiple awaits preserve taint', () => {
  const { findings } = analyze(`
    async function process() {
      var x = await Promise.resolve(location.hash);
      var y = await Promise.resolve(x);
      document.body.innerHTML = y;
    }
    process();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Labeled break with tainted value ──
console.log('\n--- Labeled break/continue ---');

test('labeled break: tainted value escapes inner loop → innerHTML', () => {
  const { findings } = analyze(`
    var result;
    outer: for (var i = 0; i < 3; i++) {
      for (var j = 0; j < 3; j++) {
        result = location.hash;
        break outer;
      }
    }
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Nullish coalescing with taint ──
console.log('\n--- Nullish coalescing ---');

test('tainted ?? safe → innerHTML is tainted', () => {
  const { findings } = analyze(`
    var x = location.hash ?? 'default';
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('null ?? tainted → innerHTML is tainted', () => {
  const { findings } = analyze(`
    var x = null ?? location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Dynamic property name in object literal ──
console.log('\n--- Computed property in object ---');

test('object with computed key containing tainted value → innerHTML', () => {
  const { findings } = analyze(`
    var key = 'content';
    var obj = { [key]: location.hash };
    document.body.innerHTML = obj.content;
  `);
  expect(findings).toHaveType('XSS');
});

// ── WeakRef / FinalizationRegistry (safe — not taint vectors) ──

// ── Spread in function call ──
console.log('\n--- Spread in function call ---');

test('function called with ...taintedArray → innerHTML inside', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    var args = [location.hash];
    render(...args);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Map.get with tainted value ──
console.log('\n--- Map with tainted values ---');

test('Map.set(key, tainted) then Map.get(key) → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('html', location.hash);
    document.body.innerHTML = m.get('html');
  `);
  expect(findings).toHaveType('XSS');
});

test('Map.set(key, safe) then Map.get(key) → no finding', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('html', 'safe');
    document.body.innerHTML = m.get('html');
  `);
  expect(findings).toBeEmpty();
});

// ── Conditional function definition ──
console.log('\n--- Conditional function definition ---');

test('function defined conditionally, always sinks tainted', () => {
  const { findings } = analyze(`
    var fn;
    if (true) {
      fn = function(x) { document.body.innerHTML = x; };
    } else {
      fn = function(x) { document.body.innerHTML = x; };
    }
    fn(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Multi-level destructuring ──
console.log('\n--- Multi-level destructuring ---');

test('nested destructuring extracts tainted deep property → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { a: { b: location.hash } };
    var { a: { b } } = obj;
    document.body.innerHTML = b;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: comparison operators return boolean ──
console.log('\n--- Safe: comparison results ---');

test('safe: tainted.length → innerHTML is safe (number)', () => {
  const { findings } = analyze(`
    var x = location.hash.length;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Callback in setTimeout (non-string) ──
console.log('\n--- setTimeout/setInterval with callbacks ---');

test('setTimeout(callback, 0) with tainted closure → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    setTimeout(function() {
      document.body.innerHTML = x;
    }, 0);
  `);
  expect(findings).toHaveType('XSS');
});

test('setTimeout(callback) is safe when callback uses safe data', () => {
  const { findings } = analyze(`
    var x = 'safe';
    setTimeout(function() {
      document.body.innerHTML = x;
    }, 0);
  `);
  expect(findings).toBeEmpty();
});

// ── Logical OR assignment with taint ──
console.log('\n--- Logical assignment operators ---');

test('x ||= tainted → innerHTML', () => {
  const { findings } = analyze(`
    var x;
    x ||= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('x &&= tainted → innerHTML', () => {
  const { findings } = analyze(`
    var x = 'initial';
    x &&= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('x ??= tainted → innerHTML', () => {
  const { findings } = analyze(`
    var x;
    x ??= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through default export (cross-file) ──
console.log('\n--- Cross-file: default parameter taint ---');

test('function with default param from global tainted var', () => {
  const { findings } = analyze(`
    var src = location.hash;
    function render(html = src) {
      document.body.innerHTML = html;
    }
    render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: hardcoded protocol check ──
console.log('\n--- Safe: protocol validation ---');

test('safe: URL validated via new URL().protocol before navigation', () => {
  const { findings } = analyze(`
    var input = location.hash.slice(1);
    var url = new URL(input);
    if (url.protocol === 'https:') {
      location.href = input;
    }
  `);
  expect(findings).not.toHaveType('XSS');
});

// ── setAttribute with dangerous attributes ──
console.log('\n--- setAttribute patterns ---');

test('setAttribute("onclick", tainted) → XSS', () => {
  const { findings } = analyze(`
    var el = document.createElement('div');
    el.setAttribute('onclick', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('setAttribute("href", tainted) → XSS', () => {
  const { findings } = analyze(`
    var el = document.createElement('a');
    el.setAttribute('href', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('setAttribute("class", tainted) → safe', () => {
  const { findings } = analyze(`
    var el = document.createElement('div');
    el.setAttribute('class', location.hash);
  `);
  expect(findings).toBeEmpty();
});

// ── String.raw tagged template ──
console.log('\n--- String.raw ---');

test('String.raw with tainted value → innerHTML', () => {
  const { findings } = analyze(`
    var x = String.raw\`\${location.hash}\`;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── for-in with tainted object values ──
console.log('\n--- for-in edge cases ---');

test('for-in: iterate tainted object, access values → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { a: location.hash };
    for (var key in obj) {
      document.body.innerHTML = obj[key];
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: Array.isArray / Number.isNaN ──
console.log('\n--- Safe: type checking functions ---');

test('safe: Array.isArray(tainted) → innerHTML (boolean result)', () => {
  const { findings } = analyze(`
    var x = Array.isArray(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});


// ╔═══════════════════════════════════════════════════════╗
// ║  ROUND 5 — Deep AST edge cases & real-world patterns   ║
// ╚═══════════════════════════════════════════════════════╝

// ── Destructuring assignment (not declaration) ──
console.log('\n--- Destructuring assignment ---');

test('destructuring assignment extracts tainted property → innerHTML', () => {
  const { findings } = analyze(`
    var a;
    var obj = { x: location.hash };
    ({ x: a } = obj);
    document.body.innerHTML = a;
  `);
  expect(findings).toHaveType('XSS');
});

test('array destructuring assignment from tainted → innerHTML', () => {
  const { findings } = analyze(`
    var first;
    [first] = location.hash.split('#');
    document.body.innerHTML = first;
  `);
  expect(findings).toHaveType('XSS');
});

// ── arguments object ──
console.log('\n--- arguments object ---');

test('arguments[0] receives tainted value → innerHTML', () => {
  const { findings } = analyze(`
    function render() {
      document.body.innerHTML = arguments[0];
    }
    render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Chained new URL operations ──
console.log('\n--- URL constructor chained operations ---');

test('new URL(tainted).pathname → innerHTML is XSS', () => {
  const { findings } = analyze(`
    var path = new URL(location.href).pathname;
    document.body.innerHTML = path;
  `);
  expect(findings).toHaveType('XSS');
});

test('new URL(tainted).origin → innerHTML is XSS', () => {
  const { findings } = analyze(`
    var o = new URL(location.href).origin;
    document.body.innerHTML = o;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Object.keys/values iteration ──
console.log('\n--- Object.keys/values iteration ---');

test('Object.values(tainted).forEach → innerHTML', () => {
  const { findings } = analyze(`
    var cfg = { template: location.hash };
    Object.values(cfg).forEach(function(v) {
      document.body.innerHTML = v;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('Object.keys of tainted object → innerHTML is safe (keys are strings)', () => {
  const { findings } = analyze(`
    var cfg = { template: location.hash };
    var keys = Object.keys(cfg);
    document.body.innerHTML = keys.join(',');
  `);
  expect(findings).toBeEmpty();
});

// ── Prototype pollution edge cases ──
console.log('\n--- Prototype pollution advanced ---');

test('nested bracket assignment from URLSearchParams → prototype pollution', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    var key1 = params.get('key1');
    var key2 = params.get('key2');
    var val = params.get('val');
    var obj = {};
    obj[key1][key2] = val;
  `);
  expect(findings).toHaveType('Prototype Pollution');
});

// ── Cross-file with class instantiation and method calls ──
console.log('\n--- Cross-file class methods ---');

test('class defined in file A, method called with taint in file B', () => {
  const findings = analyzeMultiple([
    { source: `
      class Renderer {
        show(html) { document.body.innerHTML = html; }
      }
    `, file: 'renderer.js' },
    { source: `
      var r = new Renderer();
      r.show(location.hash);
    `, file: 'app.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Default parameter with tainted fallback ──
console.log('\n--- Default parameter edge cases ---');

test('default parameter: tainted default used when arg is undefined', () => {
  const { findings } = analyze(`
    function render(html = location.hash) {
      document.body.innerHTML = html;
    }
    render(undefined);
  `);
  expect(findings).toHaveType('XSS');
});

test('default parameter: safe arg overrides tainted default → safe', () => {
  const { findings } = analyze(`
    function render(html = location.hash) {
      document.body.innerHTML = html;
    }
    render('safe content');
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through Array constructor / Array.of ──
console.log('\n--- Array.of / Array constructor ---');

test('Array.of(tainted).join() → innerHTML', () => {
  const { findings } = analyze(`
    var arr = Array.of(location.hash);
    document.body.innerHTML = arr.join('');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through string concatenation in loop ──
console.log('\n--- Loop accumulation patterns ---');

test('for loop concatenating tainted array elements → innerHTML', () => {
  const { findings } = analyze(`
    var items = [location.hash, 'safe'];
    var result = '';
    for (var i = 0; i < items.length; i++) {
      result += items[i];
    }
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('while loop reading from tainted source accumulates → innerHTML', () => {
  const { findings } = analyze(`
    var parts = location.hash.split('&');
    var out = '';
    var i = 0;
    while (i < parts.length) {
      out += parts[i];
      i++;
    }
    document.body.innerHTML = out;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Multiple return paths in function ──
console.log('\n--- Multiple return paths ---');

test('function with early return of tainted, later return of safe → tainted', () => {
  const { findings } = analyze(`
    function get(flag) {
      if (flag) return location.hash;
      return 'safe';
    }
    document.body.innerHTML = get(true);
  `);
  expect(findings).toHaveType('XSS');
});

test('function always returns sanitized → safe', () => {
  const { findings } = analyze(`
    function get(data) {
      if (!data) return '';
      return DOMPurify.sanitize(data);
    }
    document.body.innerHTML = get(location.hash);
  `);
  expect(findings).toBeEmpty();
});

// ── Comma operator in for-loop ──
console.log('\n--- Comma in for-loop ---');

test('for-loop with tainted init via comma → innerHTML', () => {
  const { findings } = analyze(`
    var x;
    for (x = location.hash, i = 0; i < 1; i++) {}
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through string replace with function callback ──
console.log('\n--- String replace with callback ---');

test('tainted.replace(regex, callback) preserves taint → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash.replace(/./g, function(m) { return m; });
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through JSON.parse of constructed string ──
console.log('\n--- JSON.parse edge cases ---');

test('JSON.parse("{\\"key\\":\\"" + tainted + "\\"}") → innerHTML', () => {
  const { findings } = analyze(`
    var json = '{"key":"' + location.hash + '"}';
    var obj = JSON.parse(json);
    document.body.innerHTML = obj.key;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array spread in new context ──
console.log('\n--- Array spread patterns advanced ---');

test('[...tainted] preserves taint → join → innerHTML', () => {
  const { findings } = analyze(`
    var arr = location.hash.split('');
    var copy = [...arr];
    document.body.innerHTML = copy.join('');
  `);
  expect(findings).toHaveType('XSS');
});

test('Object spread: {...taintedObj} preserves property taint → innerHTML', () => {
  const { findings } = analyze(`
    var src = { html: location.hash };
    var copy = { ...src };
    document.body.innerHTML = copy.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── this.method() delegation chains ──
console.log('\n--- Method delegation chains ---');

test('method calls this.transform() then this.render() with tainted data', () => {
  const { findings } = analyze(`
    class Widget {
      setContent(html) { this.content = html; this.render(); }
      render() { document.body.innerHTML = this.content; }
    }
    var w = new Widget();
    w.setContent(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Event emitter pattern ──
console.log('\n--- Event emitter pattern ---');

test('event emitter: on/emit with tainted data → innerHTML', () => {
  const { findings } = analyze(`
    var handlers = {};
    function on(event, fn) { handlers[event] = fn; }
    function emit(event, data) { if (handlers[event]) handlers[event](data); }
    on('render', function(html) { document.body.innerHTML = html; });
    emit('render', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: numeric operations on tainted ──
console.log('\n--- Safe: numeric operations ---');

test('safe: tainted * 1 is numeric → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash * 1;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted | 0 is numeric → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash | 0;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted >>> 0 is numeric → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash >>> 0;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: comparison operators return booleans ──
console.log('\n--- Safe: comparison results ---');

test('safe: tainted > 0 → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = location.hash > 0;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted === "foo" → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = location.hash === 'foo';
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted instanceof Array → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = location.hash instanceof Array;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: "key" in tainted → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var obj = JSON.parse(location.hash);
    var x = "key" in obj;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Promise.allSettled / Promise.any ──
console.log('\n--- Promise.allSettled/any ---');

test('Promise.allSettled with tainted → then → innerHTML', () => {
  const { findings } = analyze(`
    var p = Promise.resolve(location.hash);
    Promise.allSettled([p]).then(function(results) {
      document.body.innerHTML = results[0].value;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Template literal in eval ──
console.log('\n--- Template literal in sinks ---');

test('eval(template literal with tainted) → XSS', () => {
  const { findings } = analyze(`
    var x = location.hash;
    eval(\`var y = "\${x}";\`);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Chained ternary ──
console.log('\n--- Chained ternary ---');

test('chained ternary: a ? b : c ? tainted : safe → innerHTML', () => {
  const { findings } = analyze(`
    var mode = 1;
    var content = mode === 0 ? 'a' : mode === 1 ? location.hash : 'c';
    document.body.innerHTML = content;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Property access on function return ──
console.log('\n--- Property access on return value ---');

test('func().prop where prop is tainted → innerHTML', () => {
  const { findings } = analyze(`
    function getData() { return { html: location.hash }; }
    document.body.innerHTML = getData().html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: overwritten in catch block ──
console.log('\n--- Safe: error recovery patterns ---');

test('safe: tainted in try overwritten by safe in catch → innerHTML', () => {
  const { findings } = analyze(`
    var x;
    try {
      x = location.hash;
      throw new Error();
    } catch(e) {
      x = 'fallback';
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Dynamic import / import() ──
console.log('\n--- Async import patterns ---');

test('dynamic import().then callback with tainted arg → innerHTML', () => {
  const { findings } = analyze(`
    var mod = { render: function(h) { document.body.innerHTML = h; } };
    Promise.resolve(mod).then(function(m) {
      m.render(location.hash);
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Nested function declarations ──
console.log('\n--- Nested function declarations ---');

test('inner function declared inside outer, called with tainted arg', () => {
  const { findings } = analyze(`
    function outer(data) {
      function inner(html) {
        document.body.innerHTML = html;
      }
      inner(data);
    }
    outer(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Map.forEach ──
console.log('\n--- Map.forEach ---');

test('Map with tainted values → forEach → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('key', location.hash);
    m.forEach(function(val) {
      document.body.innerHTML = val;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: taint consumed by non-sink ──
console.log('\n--- Safe: taint consumed by non-sink ---');

test('safe: tainted used only as Map key, not value → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set(location.hash, 'safe');
    document.body.innerHTML = m.get(location.hash);
  `);
  expect(findings).toBeEmpty();
});

// ── Multiple assignment targets ──
console.log('\n--- Multiple assignment targets ---');

test('a = b = c = tainted → all three tainted → innerHTML via a', () => {
  const { findings } = analyze(`
    var a, b, c;
    a = b = c = location.hash;
    document.body.innerHTML = a;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Conditional spread ──
console.log('\n--- Conditional spread ---');

test('conditional spread: {...(flag && taintedObj)} → innerHTML', () => {
  const { findings } = analyze(`
    var src = { html: location.hash };
    var result = { ...(true && src) };
    document.body.innerHTML = result.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: sanitizer in .then() chain ──
console.log('\n--- Safe: sanitized promise chain ---');

test('safe: fetch(tainted).then(sanitize).then(render)', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash)
      .then(function(data) { return DOMPurify.sanitize(data); })
      .then(function(safe) { document.body.innerHTML = safe; });
  `);
  expect(findings).toBeEmpty();
});

// ── setAttribute with tainted src on any element ──
console.log('\n--- setAttribute src on elements ---');

test('img.setAttribute("src", tainted) → XSS', () => {
  const { findings } = analyze(`
    var img = document.createElement('img');
    img.setAttribute('src', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: div.setAttribute("id", tainted) → no finding', () => {
  const { findings } = analyze(`
    var div = document.createElement('div');
    div.setAttribute('id', location.hash);
  `);
  expect(findings).toBeEmpty();
});

// ── Cross-file taint through global object method ──
console.log('\n--- Cross-file global object method ---');

test('global object method defined in file A, taint from file B to sink', () => {
  const findings = analyzeMultiple([
    { source: `
      var app = {};
      app.render = function(html) { document.body.innerHTML = html; };
    `, file: 'init.js' },
    { source: `
      app.render(location.hash);
    `, file: 'main.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Taint through template literal method ──
console.log('\n--- Template literal method ---');

test('tainted.toString() in template literal → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    document.body.innerHTML = \`\${x.toString()}\`;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: encodeURIComponent in template ──
console.log('\n--- Safe: encoded template ---');

test('safe: encodeURIComponent(tainted) in template → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    document.body.innerHTML = \`<a href="?q=\${encodeURIComponent(x)}">link</a>\`;
  `);
  expect(findings).toBeEmpty();
});

// ── Nested arrow functions ──
console.log('\n--- Nested arrow functions ---');

test('nested arrows: outer captures tainted, inner sinks it', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var outer = () => {
      var inner = () => { document.body.innerHTML = x; };
      inner();
    };
    outer();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Open redirect via fetch redirect ──
console.log('\n--- Open Redirect: additional patterns ---');

test('tainted → window.open without scheme check → XSS', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    window.open(url);
  `);
  expect(findings).toHaveType('XSS');
});

test('startsWith("https://") → window.open → Open Redirect', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    if (url.startsWith('https://')) {
      window.open(url);
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

// ── Taint through property shorthand in return ──
console.log('\n--- Property shorthand in return ---');

test('function returns {tainted} shorthand → destructured → innerHTML', () => {
  const { findings } = analyze(`
    function wrap(html) { return { html }; }
    var { html } = wrap(location.hash);
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted in dead code path ──
console.log('\n--- Safe: dead code ---');

test('safe: tainted overwritten unconditionally before sink → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    x = 'safe';
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through Array.prototype.concat ──
console.log('\n--- Array.concat ---');

test('arr.concat(taintedArr) → join → innerHTML', () => {
  const { findings } = analyze(`
    var safe = ['hello'];
    var tainted = [location.hash];
    var combined = safe.concat(tainted);
    document.body.innerHTML = combined.join(' ');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: RegExp test returns boolean ──
console.log('\n--- Safe: RegExp results ---');

test('safe: /pattern/.test(tainted) → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = /^[a-z]+$/.test(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through Symbol.toPrimitive (coercion edge case) ──
// Not supported but should not crash

// ── Taint through async generator (basic) ──
console.log('\n--- Async patterns advanced ---');

test('async IIFE with tainted closure → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    (async function() {
      document.body.innerHTML = x;
    })();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: Number.isNaN / Number.isFinite ──
console.log('\n--- Safe: Number static methods ---');

test('safe: Number.isNaN(tainted) → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = Number.isNaN(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: Number.isFinite(tainted) → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = Number.isFinite(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Assignment in condition ──
console.log('\n--- Assignment in condition ---');

test('if (x = tainted) then innerHTML x → XSS', () => {
  const { findings } = analyze(`
    var x;
    if (x = location.hash) {
      document.body.innerHTML = x;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through global var aliasing ──
console.log('\n--- Variable aliasing ---');

test('window.location.search via direct access → innerHTML', () => {
  const { findings } = analyze(`
    var search = window.location.search;
    var decoded = decodeURIComponent(search);
    document.body.innerHTML = decoded;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: Math.max/min ──
console.log('\n--- Safe: Math functions ---');

test('safe: Math.max(tainted, 0) → innerHTML (number)', () => {
  const { findings } = analyze(`
    var x = Math.max(location.hash, 0);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: Math.min(tainted, 100) → innerHTML (number)', () => {
  const { findings } = analyze(`
    var x = Math.min(location.hash, 100);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});


// ╔═══════════════════════════════════════════════════════╗
// ║  ROUND 6 — Regex methods, bind, deep chains, edge     ║
// ╚═══════════════════════════════════════════════════════╝

// ── String.match / String.search / RegExp.test / RegExp.exec ──
console.log('\n--- Regex method taint propagation ---');

test('tainted.match(regex) preserves taint → join → innerHTML', () => {
  const { findings } = analyze(`
    var matches = location.hash.match(/\\w+/g);
    document.body.innerHTML = matches.join(' ');
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.search(regex) returns number → safe', () => {
  const { findings } = analyze(`
    var idx = location.hash.search(/test/);
    document.body.innerHTML = idx;
  `);
  expect(findings).toBeEmpty();
});

test('regex.exec(tainted) preserves taint → innerHTML', () => {
  const { findings } = analyze(`
    var result = /(.+)/.exec(location.hash);
    document.body.innerHTML = result[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('regex.test(tainted) returns boolean → safe', () => {
  const { findings } = analyze(`
    var valid = /^[a-z]+$/.test(location.hash);
    document.body.innerHTML = valid;
  `);
  expect(findings).toBeEmpty();
});

test('tainted.matchAll(regex) → for-of → innerHTML', () => {
  const { findings } = analyze(`
    var matches = location.hash.matchAll(/\\w+/g);
    for (var m of matches) {
      document.body.innerHTML += m[0];
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Function.bind ──
console.log('\n--- Function.bind ---');

test('fn.bind(thisArg) called with tainted → innerHTML', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    var bound = render.bind(null);
    bound(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('method.bind(obj) preserves method resolution', () => {
  const { findings } = analyze(`
    var obj = { html: location.hash };
    function show() { document.body.innerHTML = this.html; }
    var bound = show.bind(obj);
    bound();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through new RegExp(tainted) ──
console.log('\n--- Dynamic RegExp ---');

test('new RegExp(tainted) → source → eval is XSS', () => {
  const { findings } = analyze(`
    var pattern = new RegExp(location.hash);
    eval(pattern.source);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array.splice ──
console.log('\n--- Array.splice ---');

test('arr.splice returns removed tainted elements → join → innerHTML', () => {
  const { findings } = analyze(`
    var arr = [location.hash, 'safe'];
    var removed = arr.splice(0, 1);
    document.body.innerHTML = removed.join('');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through structuredClone / JSON round-trip ──
console.log('\n--- Deep copy patterns ---');

test('JSON.parse(JSON.stringify({html: tainted})) → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { html: location.hash };
    var clone = JSON.parse(JSON.stringify(obj));
    document.body.innerHTML = clone.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through WeakRef ──
// WeakRef isn't tracked but shouldn't crash
console.log('\n--- WeakRef/Symbol edge cases ---');

test('tainted stored then read from simple wrapper → innerHTML', () => {
  const { findings } = analyze(`
    function Ref(val) { this.val = val; }
    Ref.prototype.deref = function() { return this.val; };
    var ref = new Ref(location.hash);
    document.body.innerHTML = ref.deref();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array.flat / flatMap ──
console.log('\n--- Array.flat/flatMap ---');

test('nested tainted array.flat() → join → innerHTML', () => {
  const { findings } = analyze(`
    var nested = [[location.hash], ['safe']];
    var flat = nested.flat();
    document.body.innerHTML = flat.join('');
  `);
  expect(findings).toHaveType('XSS');
});

test('arr.flatMap with tainted callback → innerHTML', () => {
  const { findings } = analyze(`
    var items = ['a', 'b'];
    var result = items.flatMap(function(x) { return [x, location.hash]; });
    document.body.innerHTML = result.join('');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Object.fromEntries ──
console.log('\n--- Object.fromEntries ---');

test('Object.fromEntries with tainted value → innerHTML', () => {
  const { findings } = analyze(`
    var entries = [['key', location.hash]];
    var obj = Object.fromEntries(entries);
    document.body.innerHTML = obj.key;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Chained assignment with MemberExpression ──
console.log('\n--- Chained member assignment ---');

test('a.x = b.y = tainted then a.x → innerHTML', () => {
  const { findings } = analyze(`
    var a = {}, b = {};
    a.x = b.y = location.hash;
    document.body.innerHTML = a.x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through template literal in function return ──
console.log('\n--- Template literal in return ---');

test('function returns template with tainted → innerHTML', () => {
  const { findings } = analyze(`
    function wrap(data) { return \`<div>\${data}</div>\`; }
    document.body.innerHTML = wrap(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted.split()[safe_index] still tainted ──
console.log('\n--- Split and index ---');

test('tainted.split("#")[1] preserves taint → innerHTML', () => {
  const { findings } = analyze(`
    var frag = location.href.split('#')[1];
    document.body.innerHTML = frag;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Multiple function overloads / reassignment ──
console.log('\n--- Function reassignment ---');

test('function reassigned then called → uses latest version', () => {
  const { findings } = analyze(`
    function render(html) { document.body.textContent = html; }
    render = function(html) { document.body.innerHTML = html; };
    render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through catch with re-throw error.message ──
console.log('\n--- Error message taint ---');

test('throw new Error(tainted) → catch e.message → innerHTML', () => {
  const { findings } = analyze(`
    try {
      throw new Error(location.hash);
    } catch (e) {
      document.body.innerHTML = e.message;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Cross-file: shared global array ──
console.log('\n--- Cross-file shared arrays ---');

test('file A pushes tainted to global array, file B reads and sinks', () => {
  const findings = analyzeMultiple([
    { source: `
      var items = [];
      items.push(location.hash);
    `, file: 'collect.js' },
    { source: `
      document.body.innerHTML = items.join('');
    `, file: 'render.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Safe: taint killed by string method that returns fixed-length ──
console.log('\n--- Safe: fixed-length string methods ---');

test('safe: tainted.substring(0, 1) is still tainted (not safe!)', () => {
  const { findings } = analyze(`
    var x = location.hash.substring(0, 1);
    document.body.innerHTML = x;
  `);
  // substring preserves taint — it's still attacker controlled
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array destructuring with skip ──
console.log('\n--- Array destructuring with holes ---');

test('array destructuring: [,second] from tainted split → innerHTML', () => {
  const { findings } = analyze(`
    var parts = location.hash.split('/');
    var [, second] = parts;
    document.body.innerHTML = second;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through for-of with Map.entries ──
console.log('\n--- Map.entries iteration ---');

test('for-of over Map.entries with tainted values → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('key', location.hash);
    for (var [k, v] of m) {
      document.body.innerHTML = v;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: short-circuit prevents tainted path ──
console.log('\n--- Safe: short-circuit evaluation ---');

test('safe: false && tainted → innerHTML (short-circuit prevents taint)', () => {
  const { findings } = analyze(`
    var x = false && location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through property descriptor ──
console.log('\n--- Object.defineProperty ---');

test('Object.defineProperty with tainted value → innerHTML', () => {
  const { findings } = analyze(`
    var obj = {};
    Object.defineProperty(obj, 'html', { value: location.hash });
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Deep chain: factory → constructor → method → helper → sink ──
console.log('\n--- Deep interprocedural chains ---');

test('4-hop chain: factory → class → method → helper → sink', () => {
  const { findings } = analyze(`
    function createWidget(html) {
      return new Widget(html);
    }
    class Widget {
      constructor(h) { this.h = h; }
      render() { show(this.h); }
    }
    function show(content) { document.body.innerHTML = content; }
    var w = createWidget(location.hash);
    w.render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: early return pattern ──
console.log('\n--- Safe: early return guard ---');

test('safe: function returns early if tainted, only safe reaches sink', () => {
  const { findings } = analyze(`
    function render(html) {
      if (html === location.hash) return;
      document.body.innerHTML = html;
    }
    render('safe');
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through Symbol property (should still propagate via object taint) ──

// ── Taint through chained .then().catch().then() ──
console.log('\n--- Promise chain: then-catch-then ---');

test('promise: tainted flows through .then().catch().then() → innerHTML', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash)
      .then(function(x) { return x; })
      .catch(function(e) { return e; })
      .then(function(val) { document.body.innerHTML = val; });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted consumed by JSON.stringify → textContent ──
console.log('\n--- Safe: JSON.stringify to safe sink ---');

test('safe: JSON.stringify(tainted) → textContent', () => {
  const { findings } = analyze(`
    var x = JSON.stringify(location.hash);
    document.body.textContent = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through multiple destructuring levels from function return ──
console.log('\n--- Deep destructuring from return ---');

test('function returns nested object, destructured deep → innerHTML', () => {
  const { findings } = analyze(`
    function getData() {
      return { page: { title: location.hash } };
    }
    var { page: { title } } = getData();
    document.body.innerHTML = title;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array constructor ──
console.log('\n--- Array constructor ---');

test('new Array(tainted) element access → innerHTML', () => {
  const { findings } = analyze(`
    var arr = [location.hash];
    document.body.innerHTML = arr[0];
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through ternary inside template ──
console.log('\n--- Ternary inside template literal ---');

test('template literal with ternary: tainted in one branch → innerHTML', () => {
  const { findings } = analyze(`
    var unsafe = location.hash;
    var html = \`<div>\${true ? unsafe : 'safe'}</div>\`;
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: ternary with sanitize in both branches ──
test('safe: template with sanitized ternary → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var html = \`<div>\${true ? encodeURIComponent(x) : ''}</div>\`;
    document.body.innerHTML = html;
  `);
  expect(findings).toBeEmpty();
});

// ── Cross-file: taint through exported class static method ──
console.log('\n--- Cross-file static methods ---');

test('class static method in file A returns tainted, file B sinks', () => {
  const findings = analyzeMultiple([
    { source: `
      class Config {
        static get(key) { return location.hash; }
      }
    `, file: 'config.js' },
    { source: `
      document.body.innerHTML = Config.get('theme');
    `, file: 'app.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Taint through closure returned from .then ──
console.log('\n--- Promise returning closure ---');

test('promise.then returns function that closes over tainted → called → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    Promise.resolve().then(function() {
      return function() { document.body.innerHTML = x; };
    }).then(function(fn) { fn(); });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through string.replace with tainted replacement ──
console.log('\n--- String replace with tainted replacement ---');

test('safe.replace("x", tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var template = '<div>PLACEHOLDER</div>';
    var html = template.replace('PLACEHOLDER', location.hash);
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: location used only for URL construction, not sunk ──
console.log('\n--- Safe: location used safely ---');

test('safe: location.pathname used only as fetch URL', () => {
  const { findings } = analyze(`
    var path = location.pathname;
    fetch('/api' + path).then(function(r) { return r.json(); });
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through callback in Array.reduce ──
console.log('\n--- Array.reduce callback ---');

test('reduce callback accumulates taint from array → innerHTML', () => {
  const { findings } = analyze(`
    var items = [location.hash];
    var html = items.reduce(function(acc, item) {
      return acc + '<li>' + item + '</li>';
    }, '<ul>');
    document.body.innerHTML = html + '</ul>';
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: Number conversion chain ──
console.log('\n--- Safe: Number conversion chain ---');

test('safe: parseInt(tainted, 10).toString() → innerHTML', () => {
  const { findings } = analyze(`
    var x = parseInt(location.hash, 10).toString();
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through dynamic property name from source ──
console.log('\n--- Dynamic property access with source ---');

test('obj[location.hash] reads potentially unsafe property → innerHTML', () => {
  const { findings } = analyze(`
    var templates = { admin: '<script>alert(1)</script>' };
    var key = location.hash.slice(1);
    document.body.innerHTML = templates[key];
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through self.postMessage ──
console.log('\n--- self.addEventListener message ---');

test('self.addEventListener message without origin check → innerHTML', () => {
  const { findings } = analyze(`
    self.addEventListener('message', function(e) {
      document.body.innerHTML = e.data;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: addEventListener for non-message events ──
console.log('\n--- Safe: non-message event listeners ---');

test('safe: click event handler does not taint data', () => {
  const { findings } = analyze(`
    document.addEventListener('click', function(e) {
      document.body.innerHTML = 'clicked';
    });
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through chained string methods preserving taint ──
console.log('\n--- Chained string methods ---');

test('tainted.trim().toLowerCase().split(",").join(";") → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash.trim().toLowerCase().split(',').join(';');
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through conditional import-like pattern ──
console.log('\n--- Conditional require pattern ---');

test('conditional function selection based on runtime check → tainted arg', () => {
  const { findings } = analyze(`
    function renderHTML(html) { document.body.innerHTML = html; }
    function renderText(text) { document.body.textContent = text; }
    var render = true ? renderHTML : renderText;
    render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: all paths sanitize ──
console.log('\n--- Safe: all paths sanitize ---');

test('safe: if/else both sanitize before sink', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var safe;
    if (x.length > 10) {
      safe = DOMPurify.sanitize(x);
    } else {
      safe = encodeURIComponent(x);
    }
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through class field initializer ──
console.log('\n--- Class field patterns ---');

test('class with tainted field from constructor arg → method sinks', () => {
  const { findings } = analyze(`
    class View {
      constructor(data) {
        this.template = data.html;
      }
      mount() {
        document.body.innerHTML = this.template;
      }
    }
    var v = new View({ html: location.hash });
    v.mount();
  `);
  expect(findings).toHaveType('XSS');
});


// ╔═══════════════════════════════════════════════════════╗
// ║  BASELINE — production libraries should have 0 FPs    ║
// ╚═══════════════════════════════════════════════════════╝

console.log('\n--- Baseline: production libraries ---');

const libs = readdirSync(libsDir).filter(f => f.endsWith('.js'));
console.log(`Scanning ${libs.length} libraries\n`);

for (const lib of libs) {
  test(lib, () => {
    const source = readFileSync(resolve(libsDir, lib), 'utf8');
    const start = Date.now();

    let result;
    try {
      result = analyze(source, { file: lib });
    } catch (e) {
      throw new Error(`Analysis crashed: ${e.message}`);
    }

    const elapsed = Date.now() - start;
    const { findings } = result;

    if (findings.length > 0) {
      const summary = findings.map(f =>
        `  ${f.type}: ${f.title} (${f.sink?.file}:${f.sink?.line})`
      ).join('\n');
      throw new Error(`${findings.length} false positive(s) in ${elapsed}ms:\n${summary}`);
    }

    console.log(`          (${(source.length / 1024).toFixed(0)}KB, ${elapsed}ms)`);
  });
}


// ═══════════════════════════════════════════════════════
console.log(`\n${'='.repeat(50)}`);
console.log(`RESULTS: ${passed} passed, ${failed} failed out of ${passed + failed}`);
if (failed > 0) process.exit(1);
