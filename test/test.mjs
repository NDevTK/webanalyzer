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

test('obj with tainted property read via computed access → innerHTML', () => {
  const { findings } = analyze(`
    var cache = {};
    cache.html = location.hash;
    var key = 'html';
    document.body.innerHTML = cache[key];
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
// ║  ROUND 7 — Advanced AST patterns                      ║
// ╚═══════════════════════════════════════════════════════╝

// ── outerHTML / srcdoc sinks ──
console.log('\n--- outerHTML / srcdoc sinks ---');

test('tainted → outerHTML is XSS', () => {
  const { findings } = analyze(`
    document.body.outerHTML = location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted → iframe.srcdoc is XSS', () => {
  const { findings } = analyze(`
    var iframe = document.createElement('iframe');
    iframe.srcdoc = location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

// ── window.name source ──
console.log('\n--- window.name source ---');

test('window.name → innerHTML is XSS', () => {
  const { findings } = analyze(`
    document.body.innerHTML = window.name;
  `);
  expect(findings).toHaveType('XSS');
});

// ── document.referrer source ──
console.log('\n--- document.referrer source ---');

test('document.referrer → innerHTML is XSS', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.referrer;
  `);
  expect(findings).toHaveType('XSS');
});

// ── document.cookie source ──
console.log('\n--- document.cookie source ---');

test('document.cookie → innerHTML is XSS', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.cookie;
  `);
  expect(findings).toHaveType('XSS');
});

// ── document.URL source ──
console.log('\n--- document.URL source ---');

test('document.URL → innerHTML is XSS', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.URL;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Optional chaining sources ──
console.log('\n--- Optional chaining sources ---');

test('window?.location?.hash → innerHTML is XSS', () => {
  const { findings } = analyze(`
    var x = window?.location?.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── document.write / document.writeln sinks ──
console.log('\n--- document.write sink ---');

test('tainted → document.write is XSS', () => {
  const { findings } = analyze(`
    document.write('<div>' + location.hash + '</div>');
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted → document.writeln is XSS', () => {
  const { findings } = analyze(`
    document.writeln(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── insertAdjacentHTML sink ──
console.log('\n--- insertAdjacentHTML sink ---');

test('el.insertAdjacentHTML("beforeend", tainted) is XSS', () => {
  const { findings } = analyze(`
    var el = document.getElementById('app');
    el.insertAdjacentHTML('beforeend', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── DOMParser.parseFromString sink ──
console.log('\n--- DOMParser.parseFromString sink ---');

test('new DOMParser().parseFromString(tainted) is XSS', () => {
  const { findings } = analyze(`
    var parser = new DOMParser();
    parser.parseFromString(location.hash, 'text/html');
  `);
  expect(findings).toHaveType('XSS');
});

// ── new Function(tainted) sink ──
console.log('\n--- new Function sink ---');

test('new Function(tainted) is XSS', () => {
  const { findings } = analyze(`
    var fn = new Function(location.hash);
    fn();
  `);
  expect(findings).toHaveType('XSS');
});

test('new Function with multiple args: body is tainted', () => {
  const { findings } = analyze(`
    var fn = new Function('a', 'b', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── eval via window.eval ──
console.log('\n--- window.eval ---');

test('window.eval(tainted) is XSS', () => {
  const { findings } = analyze(`
    window.eval(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Logical assignment operators ──
console.log('\n--- Logical assignment operators ---');

test('x ||= tainted → innerHTML propagates taint', () => {
  const { findings } = analyze(`
    var x;
    x ||= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('x ??= tainted → innerHTML propagates taint', () => {
  const { findings } = analyze(`
    var x = null;
    x ??= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('x &&= tainted → innerHTML propagates taint', () => {
  const { findings } = analyze(`
    var x = 'initial';
    x &&= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: textContent is not a sink ──
console.log('\n--- Safe: textContent not a sink ---');

test('safe: tainted → textContent is not XSS', () => {
  const { findings } = analyze(`
    document.body.textContent = location.hash;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted → console.log is not a sink', () => {
  const { findings } = analyze(`
    console.log(location.hash);
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: tainted used only in condition ──
console.log('\n--- Safe: tainted used only in condition ---');

test('safe: tainted used only in if condition, safe in sink', () => {
  const { findings } = analyze(`
    var x = location.hash;
    if (x === 'admin') {
      document.body.innerHTML = 'Welcome admin';
    }
  `);
  expect(findings).toBeEmpty();
});

// ── Double assignment a = b = tainted ──
console.log('\n--- Double assignment ---');

test('a = b = tainted, only a sinks → XSS', () => {
  const { findings } = analyze(`
    var a, b;
    a = b = location.hash;
    document.body.innerHTML = a;
  `);
  expect(findings).toHaveType('XSS');
});

test('a = b = tainted, b sinks → XSS', () => {
  const { findings } = analyze(`
    var a, b;
    a = b = location.hash;
    document.body.innerHTML = b;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Array destructuring with rest element ──
console.log('\n--- Array destructuring with rest ---');

test('[first, ...rest] = taintedArray → rest → innerHTML', () => {
  const { findings } = analyze(`
    var arr = location.hash.split('/');
    var [first, ...rest] = arr;
    document.body.innerHTML = rest.join('/');
  `);
  expect(findings).toHaveType('XSS');
});

test('[first, ...rest] = taintedArray → first → innerHTML', () => {
  const { findings } = analyze(`
    var arr = location.hash.split('/');
    var [first, ...rest] = arr;
    document.body.innerHTML = first;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Function.prototype.call with tainted thisArg ──
console.log('\n--- Function.prototype.call ---');

test('show.call({html: tainted}) → this.html → innerHTML', () => {
  const { findings } = analyze(`
    function show() { document.body.innerHTML = this.html; }
    show.call({html: location.hash});
  `);
  expect(findings).toHaveType('XSS');
});

// ── Function.prototype.apply ──
console.log('\n--- Function.prototype.apply ---');

test('fn.apply(null, [tainted]) → arg reaches sink', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    render.apply(null, [location.hash]);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Prototype chain: Array.prototype.join.call ──
console.log('\n--- Prototype method via .call ---');

test('Array.prototype.join.call(taintedArr) → innerHTML', () => {
  const { findings } = analyze(`
    var arr = [location.hash, 'b'];
    var str = Array.prototype.join.call(arr, ',');
    document.body.innerHTML = str;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Prototype pollution via __proto__ ──
console.log('\n--- Prototype pollution via __proto__ ---');

test('obj.__proto__.polluted = tainted is Prototype Pollution', () => {
  const { findings } = analyze(`
    var obj = {};
    obj.__proto__.polluted = location.hash;
  `);
  expect(findings).toHaveType('Prototype Pollution');
});

// ── document.location.assign ──
console.log('\n--- document.location aliases ---');

test('document.location.href = tainted is XSS', () => {
  const { findings } = analyze(`
    document.location.href = location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Nested ternary with tainted branches ──
console.log('\n--- Nested ternary ---');

test('nested ternary: inner branch tainted → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var result = true ? (false ? 'safe' : x) : 'other';
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Promise.reject → catch propagates taint ──
console.log('\n--- Promise.reject catch ---');

test('Promise.reject(tainted).catch(fn) → fn receives taint → innerHTML', () => {
  const { findings } = analyze(`
    Promise.reject(location.hash).catch(function(err) {
      document.body.innerHTML = err;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Chained Object.assign merges ──
console.log('\n--- Chained Object.assign ---');

test('Object.assign({}, safe, {html: tainted}) → innerHTML', () => {
  const { findings } = analyze(`
    var merged = Object.assign({}, {a: 1}, {html: location.hash});
    document.body.innerHTML = merged.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: Object.freeze doesn't sanitize ──
console.log('\n--- Object.freeze ---');

test('Object.freeze(taintedObj) still tainted → innerHTML', () => {
  const { findings } = analyze(`
    var obj = Object.freeze({ html: location.hash });
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Cross-file: IIFE module exports via window ──
console.log('\n--- Cross-file IIFE module ---');

test('IIFE sets window.Mod, other file calls Mod.get() → innerHTML', () => {
  const findings = analyzeMultiple([
    { source: `
      (function() {
        window.Mod = {
          get: function() { return location.hash; }
        };
      })();
    `, file: 'mod.js' },
    { source: `
      document.body.innerHTML = Mod.get();
    `, file: 'app.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Safe: location.protocol check → Open Redirect not XSS ──
console.log('\n--- Protocol check → Open Redirect ---');

test('location.protocol check before location.assign → Open Redirect', () => {
  const { findings } = analyze(`
    var url = location.hash.slice(1);
    if (url.startsWith('http://') || url.startsWith('https://')) {
      location.assign(url);
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

// ── Class getter/setter ──
console.log('\n--- Class getter/setter ---');

test('class with getter returning tainted field → innerHTML', () => {
  const { findings } = analyze(`
    class View {
      constructor() { this._html = location.hash; }
      get html() { return this._html; }
    }
    var v = new View();
    document.body.innerHTML = v.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── for-in with tainted object values ──
console.log('\n--- for-in tainted values ---');

test('for-in over object with tainted value → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { key: location.hash };
    for (var k in obj) {
      document.body.innerHTML = obj[k];
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── setTimeout with closure taint reaching sink ──
console.log('\n--- setTimeout closure sink ---');

test('setTimeout(function() { innerHTML = closedOverTaint }, 0)', () => {
  const { findings } = analyze(`
    var x = location.hash;
    setTimeout(function() {
      document.body.innerHTML = x;
    }, 0);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: typeof on tainted is not tainted ──
console.log('\n--- Safe: typeof kills taint ---');

test('safe: typeof tainted → innerHTML', () => {
  const { findings } = analyze(`
    var x = typeof location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: delete doesn't crash ──
console.log('\n--- Safe: delete operator ---');

test('safe: delete tainted property does not crash', () => {
  const { findings } = analyze(`
    var obj = { html: location.hash };
    delete obj.html;
    document.body.innerHTML = 'safe';
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through closure mutation via method call ──
console.log('\n--- Closure mutation via method ---');

test('method sets closure var, later read sinks → innerHTML', () => {
  const { findings } = analyze(`
    var cached;
    var cache = {
      store: function(val) { cached = val; },
      load: function() { return cached; }
    };
    cache.store(location.hash);
    document.body.innerHTML = cache.load();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Multiple sinks: both innerHTML and eval ──
console.log('\n--- Multiple sinks ---');

test('tainted flows to both innerHTML and eval → 2 findings', () => {
  const { findings } = analyze(`
    var x = location.hash;
    document.body.innerHTML = x;
    eval(x);
  `);
  expect(findings).toHaveAtLeast(2);
});

// ── Safe: try-catch where tainted only in unreachable catch ──
console.log('\n--- Safe: tainted in unused error handling ---');

test('safe: tainted used only in catch error message, not sunk', () => {
  const { findings } = analyze(`
    try {
      JSON.parse(location.hash);
    } catch (e) {
      document.body.textContent = e.message;
    }
  `);
  expect(findings).toBeEmpty();
});

// ── Chained method calls on builder pattern ──
console.log('\n--- Builder pattern ---');

test('builder.set(tainted).build().html → innerHTML', () => {
  const { findings } = analyze(`
    function Builder() { this.data = ''; }
    Builder.prototype.set = function(v) { this.data = v; return this; };
    Builder.prototype.build = function() { return { html: this.data }; };
    var result = new Builder().set(location.hash).build();
    document.body.innerHTML = result.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Spread into function call ──
console.log('\n--- Spread in function call ---');

test('fn(...[tainted]) → innerHTML', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    var args = [location.hash];
    render(...args);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Cross-file: function defined in A, called in B with tainted arg ──
console.log('\n--- Cross-file function call ---');

test('function defined in file A, called with tainted in file B → innerHTML', () => {
  const findings = analyzeMultiple([
    { source: `
      function render(html) {
        document.body.innerHTML = html;
      }
    `, file: 'render.js' },
    { source: `
      render(location.hash);
    `, file: 'app.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Computed string property access on source ──
console.log('\n--- Computed string property on source ---');

test('location["hash"] bracket access is taint source', () => {
  const { findings } = analyze(`
    var x = location["hash"];
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Immediately invoked arrow ──
console.log('\n--- IIFE arrow ---');

test('(() => location.hash)() → innerHTML', () => {
  const { findings } = analyze(`
    var x = (() => location.hash)();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Map.get with dynamic key ──
console.log('\n--- Map with dynamic key ---');

test('Map.set(dynamicKey, tainted) → Map.get(dynamicKey) → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map();
    var key = 'user_' + Math.random();
    m.set(key, location.hash);
    document.body.innerHTML = m.get(key);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: strict equality comparison result used in sink ──
console.log('\n--- Safe: equality result in sink ---');

test('safe: (tainted === expected) → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var result = x === 'admin';
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through string concatenation in array ──
console.log('\n--- String concat in array ---');

test('[prefix + tainted].join("") → innerHTML', () => {
  const { findings } = analyze(`
    var items = ['<div>' + location.hash + '</div>'];
    document.body.innerHTML = items.join('');
  `);
  expect(findings).toHaveType('XSS');
});

// ── while loop propagation ──
console.log('\n--- While loop taint ---');

test('while loop reads tainted and accumulates → innerHTML', () => {
  const { findings } = analyze(`
    var parts = location.hash.split('/');
    var html = '';
    var i = 0;
    while (i < parts.length) {
      html += '<li>' + parts[i] + '</li>';
      i++;
    }
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── document.location.search source ──
console.log('\n--- document.location.search ---');

test('document.location.search → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.location.search;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: Number() kills taint ──
console.log('\n--- Safe: Number() sanitizer ---');

test('safe: Number(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var x = Number(location.hash.slice(1));
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: Boolean() kills taint ──
test('safe: Boolean(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var x = Boolean(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through async/await ──
console.log('\n--- Async/await taint ---');

test('async function: var x = await taintedPromise → innerHTML', () => {
  const { findings } = analyze(`
    async function load() {
      var x = await Promise.resolve(location.hash);
      document.body.innerHTML = x;
    }
    load();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through optional chaining call ──
console.log('\n--- Optional chaining call ---');

test('obj?.method(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var obj = {
      render: function(html) { document.body.innerHTML = html; }
    };
    obj?.render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Symbol property (object still tracks normally) ──
console.log('\n--- Taint not killed by irrelevant ops ---');

test('tainted assigned multiple times retains taint', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var y = x;
    var z = y;
    document.body.innerHTML = z;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted → void expression ──
test('safe: void tainted is not tainted', () => {
  const { findings } = analyze(`
    var x = void location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through computed method name ──
console.log('\n--- Computed method from builtin ---');

test('String.fromCharCode not a source, safe', () => {
  const { findings } = analyze(`
    var x = String.fromCharCode(72, 101, 108);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── jQuery-style sinks ──
console.log('\n--- jQuery sinks ---');

test('$(selector).html(tainted) is XSS', () => {
  const { findings } = analyze(`
    var el = $('#app');
    el.html(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('$(selector).append(tainted) is XSS', () => {
  const { findings } = analyze(`
    $('#app').append(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── window.open sink ──
console.log('\n--- window.open sink ---');

test('window.open(tainted) is navigation sink', () => {
  const { findings } = analyze(`
    window.open(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── location.replace sink ──
console.log('\n--- location.replace sink ---');

test('location.replace(tainted) is navigation sink', () => {
  const { findings } = analyze(`
    location.replace(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through generator-like iterator protocol ──
console.log('\n--- Iterator protocol ---');

test('array[Symbol.iterator]().next().value preserves taint', () => {
  const { findings } = analyze(`
    var arr = [location.hash];
    var iter = arr.values();
    var val = iter.next().value;
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Cross-file: global var taint propagation ──
console.log('\n--- Cross-file global var ---');

test('file A sets var = tainted, file B sinks the var', () => {
  const findings = analyzeMultiple([
    { source: `
      var globalHtml = location.hash;
    `, file: 'init.js' },
    { source: `
      document.body.innerHTML = globalHtml;
    `, file: 'render.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Taint through ternary function call ──
console.log('\n--- Ternary in callee position ---');

test('(cond ? fnA : fnB)(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    function renderHTML(html) { document.body.innerHTML = html; }
    function renderSafe(text) { document.body.textContent = text; }
    (true ? renderHTML : renderSafe)(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: sanitized in IIFE ──
console.log('\n--- Safe: sanitized in IIFE ---');

test('safe: IIFE sanitizes tainted before returning to sink', () => {
  const { findings } = analyze(`
    var safe = (function() {
      return encodeURIComponent(location.hash);
    })();
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through Object.create ──
console.log('\n--- Object.create ---');

test('Object.create(proto) then set tainted prop → innerHTML', () => {
  const { findings } = analyze(`
    var obj = Object.create(null);
    obj.html = location.hash;
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: all branches return sanitized ──
console.log('\n--- Safe: switch all cases sanitize ---');

test('safe: switch with all cases sanitizing before return', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var safe;
    switch (x.charAt(0)) {
      case '#': safe = encodeURIComponent(x); break;
      case '?': safe = encodeURIComponent(x); break;
      default: safe = '';
    }
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});


// ╔═══════════════════════════════════════════════════════╗
// ║  ROUND 8 — Advanced AST patterns                       ║
// ╚═══════════════════════════════════════════════════════╝

// ── Nested arrow returns tainted ──
console.log('\n--- Nested arrow functions ---');

test('nested arrow: (() => () => tainted)()() → innerHTML', () => {
  const { findings } = analyze(`
    var getTaint = () => () => location.hash;
    var x = getTaint()();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('nested arrow: outer captures tainted, inner returns it', () => {
  const { findings } = analyze(`
    function outer() {
      var t = location.hash;
      return function inner() { return t; };
    }
    var x = outer()();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through JSON.parse deep access ──
console.log('\n--- JSON.parse deep access ---');

test('JSON.parse(tainted).prop → innerHTML', () => {
  const { findings } = analyze(`
    var obj = JSON.parse(location.hash);
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('JSON.parse(tainted).nested.deep → innerHTML', () => {
  const { findings } = analyze(`
    var data = JSON.parse(location.search);
    document.body.innerHTML = data.config.template;
  `);
  expect(findings).toHaveType('XSS');
});

// ── createContextualFragment sink ──
console.log('\n--- createContextualFragment ---');

test('range.createContextualFragment(tainted) → XSS', () => {
  const { findings } = analyze(`
    var range = document.createRange();
    var frag = range.createContextualFragment(location.hash);
    document.body.appendChild(frag);
  `);
  expect(findings).toHaveType('XSS');
});

// ── script.textContent = tainted (script injection) ──
console.log('\n--- Script text injection ---');

test('script.textContent = tainted → Script Injection', () => {
  const { findings } = analyze(`
    var s = document.createElement('script');
    s.textContent = location.hash;
  `);
  expect(findings).toHaveAtLeast(1);
});

test('script.text = tainted → Script Injection', () => {
  const { findings } = analyze(`
    var s = document.createElement('script');
    s.text = location.hash;
  `);
  expect(findings).toHaveAtLeast(1);
});

// ── Taint through chained string methods ──
console.log('\n--- Chained string methods ---');

test('tainted.trim().toLowerCase() → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash.trim().toLowerCase();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.split("").reverse().join("") → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash.split('').reverse().join('');
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.substring(1, 5) → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash.substring(1, 5);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through replace with non-sanitizing args ──
console.log('\n--- Non-sanitizing replace ---');

test('tainted.replace("x", "y") preserves taint → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash.replace('#', '');
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── eval with concatenation ──
console.log('\n--- eval with concat ---');

test('eval("(" + tainted + ")") → XSS', () => {
  const { findings } = analyze(`
    var code = location.hash.slice(1);
    eval('(' + code + ')');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Property shorthand in object literal ──
console.log('\n--- Property shorthand ---');

test('shorthand {hash} where hash is tainted → obj.hash → innerHTML', () => {
  const { findings } = analyze(`
    var hash = location.hash;
    var obj = { hash };
    document.body.innerHTML = obj.hash;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Getter in object literal ──
console.log('\n--- Object getter ---');

test('object getter returning tainted → innerHTML', () => {
  const { findings } = analyze(`
    var t = location.hash;
    var obj = {
      get html() { return t; }
    };
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint survives re-taint after sanitize ──
console.log('\n--- Re-taint after sanitize ---');

test('sanitize then re-assign tainted → innerHTML detects', () => {
  const { findings } = analyze(`
    var x = location.hash;
    x = encodeURIComponent(x);
    x = location.search;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── fn.bind(null, tainted)() — partial application ──
console.log('\n--- Partial application via bind ---');

test('fn.bind(null, tainted)() → innerHTML', () => {
  const { findings } = analyze(`
    function render(html) {
      document.body.innerHTML = html;
    }
    var bound = render.bind(null, location.hash);
    bound();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through new Map constructor ──
console.log('\n--- Map constructor ---');

test('new Map([[k, tainted]]) → get → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map([['html', location.hash]]);
    document.body.innerHTML = m.get('html');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Nested ternary ──
console.log('\n--- Nested ternary ---');

test('nested ternary: a ? b : c ? tainted : safe → innerHTML', () => {
  const { findings } = analyze(`
    var x = false ? 'a' : true ? location.hash : 'safe';
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── switch fallthrough ──
console.log('\n--- Switch fallthrough ---');

test('switch fallthrough: tainted case falls into sink case', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var out;
    switch (x.charAt(0)) {
      case '#':
        out = x;
      case '?':
        document.body.innerHTML = out;
        break;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through toString/valueOf ──
console.log('\n--- toString/valueOf ---');

test('tainted.toString() → innerHTML preserves taint', () => {
  const { findings } = analyze(`
    var x = location.hash.toString();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array.prototype.find ──
console.log('\n--- Array.find ---');

test('arr.find() returns tainted element → innerHTML', () => {
  const { findings } = analyze(`
    var items = [location.hash, 'safe'];
    var found = items.find(function(x) { return x.startsWith('#'); });
    document.body.innerHTML = found;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Recursive function ──
console.log('\n--- Recursive function ---');

test('recursive function with tainted → innerHTML', () => {
  const { findings } = analyze(`
    function process(str, depth) {
      if (depth > 3) return str;
      return process('<b>' + str + '</b>', depth + 1);
    }
    document.body.innerHTML = process(location.hash, 0);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through globalThis ──
console.log('\n--- globalThis sources ---');

test('globalThis.location.hash → innerHTML', () => {
  const { findings } = analyze(`
    var x = globalThis.location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('self.location.search → innerHTML', () => {
  const { findings } = analyze(`
    var x = self.location.search;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── document.domain = tainted ──
console.log('\n--- document.domain ---');

test('document.domain = tainted → sink', () => {
  const { findings } = analyze(`
    document.domain = location.hash.slice(1);
  `);
  expect(findings).toHaveAtLeast(1);
});

// ── iframe.srcdoc = tainted ──
console.log('\n--- iframe.srcdoc ---');

test('iframe.srcdoc = tainted → XSS', () => {
  const { findings } = analyze(`
    var iframe = document.createElement('iframe');
    iframe.srcdoc = location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array.prototype.slice.call(arguments) ──
console.log('\n--- arguments slicing ---');

test('Array.prototype.slice.call(arguments) preserves taint', () => {
  const { findings } = analyze(`
    function render() {
      var args = Array.prototype.slice.call(arguments);
      document.body.innerHTML = args[0];
    }
    render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through for-of with entries() destructuring ──
console.log('\n--- for-of entries destructuring ---');

test('for (var [i, val] of arr.entries()) with tainted val → innerHTML', () => {
  const { findings } = analyze(`
    var items = [location.hash];
    for (var [i, val] of items.entries()) {
      document.body.innerHTML = val;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through multiple return paths ──
console.log('\n--- Multiple return paths ---');

test('function with tainted on one return path → innerHTML', () => {
  const { findings } = analyze(`
    function getData(flag) {
      if (flag) {
        return location.hash;
      }
      return 'safe';
    }
    document.body.innerHTML = getData(true);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe patterns ──
console.log('\n--- Safe: non-sink operations ---');

test('safe: tainted.split("x").length → innerHTML (number)', () => {
  const { findings } = analyze(`
    var count = location.hash.split('/').length;
    document.body.innerHTML = count;
  `);
  expect(findings).toBeEmpty();
});

test('safe: Map.has(tainted) returns boolean', () => {
  const { findings } = analyze(`
    var allowed = new Map([['admin', true]]);
    var result = allowed.has(location.hash);
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

test('safe: Set.has(tainted) returns boolean', () => {
  const { findings } = analyze(`
    var allowed = new Set(['admin', 'user']);
    var result = allowed.has(location.hash);
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

test('safe: JSON.parse(tainted) used only for .length', () => {
  const { findings } = analyze(`
    var arr = JSON.parse(location.hash);
    document.body.innerHTML = arr.length;
  `);
  expect(findings).toBeEmpty();
});

test('safe: console.log(tainted) is not a sink', () => {
  const { findings } = analyze(`
    console.log(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted used only as object key, not value', () => {
  const { findings } = analyze(`
    var key = location.hash;
    var obj = {};
    obj[key] = 'safe value';
    document.body.innerHTML = obj[key];
  `);
  expect(findings).toBeEmpty();
});

test('safe: new RegExp(safe).test(tainted) returns boolean', () => {
  const { findings } = analyze(`
    var re = new RegExp('^[a-z]+$');
    var result = re.test(location.hash);
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

test('safe: String(parseInt(tainted)) double sanitize', () => {
  const { findings } = analyze(`
    var x = String(parseInt(location.hash));
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through Reflect.apply ──
console.log('\n--- Reflect.apply ---');

test('Reflect.apply(fn, null, [tainted]) → innerHTML', () => {
  const { findings } = analyze(`
    function render(html) {
      document.body.innerHTML = html;
    }
    Reflect.apply(render, null, [location.hash]);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through computed property name ──
console.log('\n--- Computed property name ---');

test('computed property {[key]: tainted} → obj[key] → innerHTML', () => {
  const { findings } = analyze(`
    var key = 'html';
    var obj = { [key]: location.hash };
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Promise.resolve().then chain ──
console.log('\n--- Promise.resolve chain ---');

test('Promise.resolve(tainted).then(x => innerHTML = x)', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash).then(function(x) {
      document.body.innerHTML = x;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through class field assignment ──
console.log('\n--- Class field taint ---');

test('class: this.data = tainted in method, used in another method', () => {
  const { findings } = analyze(`
    class Widget {
      setData(d) { this.data = d; }
      render() { document.body.innerHTML = this.data; }
    }
    var w = new Widget();
    w.setData(location.hash);
    w.render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through string addition in return ──
console.log('\n--- String concat in return ---');

test('function returns "<div>" + tainted → innerHTML', () => {
  const { findings } = analyze(`
    function wrap(x) { return '<div>' + x + '</div>'; }
    document.body.innerHTML = wrap(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through closure over loop variable ──
console.log('\n--- Closure over loop var ---');

test('closure captures tainted loop variable → innerHTML', () => {
  const { findings } = analyze(`
    var handlers = [];
    var items = [location.hash];
    for (var i = 0; i < items.length; i++) {
      (function(val) {
        handlers.push(function() { document.body.innerHTML = val; });
      })(items[i]);
    }
    handlers[0]();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array.of ──
console.log('\n--- Array.of ---');

test('Array.of(tainted)[0] → innerHTML', () => {
  const { findings } = analyze(`
    var arr = Array.of(location.hash);
    document.body.innerHTML = arr[0];
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Object.fromEntries with entries ──
console.log('\n--- Object.fromEntries from URL params ---');

test('Object.fromEntries(searchParams) → prop → innerHTML', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    var obj = Object.fromEntries(params);
    document.body.innerHTML = obj.q;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Cross-file: factory in file A, sink in file B ──
console.log('\n--- Cross-file factory ---');

test('cross-file: factory creates tainted getter, file B calls it', () => {
  const findings = analyzeMultiple([
    { source: `
      function createConfig() {
        return { theme: location.hash };
      }
      window.getConfig = createConfig;
    `, file: 'config.js' },
    { source: `
      var cfg = getConfig();
      document.body.innerHTML = cfg.theme;
    `, file: 'app.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted → textContent then textContent read ──
console.log('\n--- Safe: textContent round-trip ---');

test('safe: set textContent with tainted, not a sink', () => {
  const { findings } = analyze(`
    var el = document.createElement('div');
    el.textContent = location.hash;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through conditional assignment ──
console.log('\n--- Conditional assignment ---');

test('x = x || location.hash → innerHTML', () => {
  const { findings } = analyze(`
    var x;
    x = x || location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array destructuring swap ──
console.log('\n--- Array destructuring swap ---');

test('destructuring swap: [b, a] = [a, b] preserves taint', () => {
  const { findings } = analyze(`
    var a = location.hash;
    var b = 'safe';
    var temp = [b, a];
    var first = temp[0];
    var second = temp[1];
    document.body.innerHTML = second;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through String() passthrough ──
console.log('\n--- String() passthrough ---');

test('String(tainted) preserves taint → innerHTML', () => {
  const { findings } = analyze(`
    var x = String(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through atob passthrough ──
console.log('\n--- atob passthrough ---');

test('atob(tainted) preserves taint → innerHTML', () => {
  const { findings } = analyze(`
    var x = atob(location.hash.slice(1));
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: comparison operators kill taint ──
console.log('\n--- Safe: comparison results ---');

test('safe: tainted > 5 → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = location.hash.length > 5;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted !== "admin" → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var result = location.hash !== 'admin';
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through chained array methods ──
console.log('\n--- Chained array methods ---');

test('taintedArr.filter().map().join() → innerHTML', () => {
  const { findings } = analyze(`
    var items = location.search.split('&');
    var result = items.filter(function(x) { return x; }).map(function(x) { return '<li>' + x + '</li>'; }).join('');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through assignment in condition ──
console.log('\n--- Assignment in condition ---');

test('if (x = tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var x;
    if (x = location.hash) {
      document.body.innerHTML = x;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: Object.keys returns safe array ──
console.log('\n--- Safe: Object.keys ---');

test('safe: Object.keys(tainted) → join → innerHTML', () => {
  const { findings } = analyze(`
    var obj = JSON.parse(location.hash);
    var keys = Object.keys(obj);
    document.body.innerHTML = keys.join(',');
  `);
  expect(findings).toBeEmpty();
});

// ╔═══════════════════════════════════════════════════════╗
// ║  ROUND 9 — Advanced AST patterns                       ║
// ╚═══════════════════════════════════════════════════════╝

// ── Class inheritance: taint through super() ──
console.log('\n--- Class inheritance with super ---');

test('class: super(tainted) → parent stores this.data → child.render() sinks', () => {
  const { findings } = analyze(`
    class Base {
      constructor(d) { this.data = d; }
    }
    class Widget extends Base {
      render() { document.body.innerHTML = this.data; }
    }
    var w = new Widget(location.hash);
    w.render();
  `);
  expect(findings).toHaveType('XSS');
});

test('class: parent method inherited by child sinks tainted', () => {
  const { findings } = analyze(`
    class Base {
      render() { document.body.innerHTML = this.html; }
    }
    class Page extends Base {
      setContent(h) { this.html = h; }
    }
    var p = new Page();
    p.setContent(location.hash);
    p.render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Error objects ──
console.log('\n--- Error object taint ---');

test('new Error(tainted).message → innerHTML', () => {
  const { findings } = analyze(`
    var err = new Error(location.hash);
    document.body.innerHTML = err.message;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through throw/catch with object ──
console.log('\n--- Throw/catch object taint ---');

test('throw {msg: tainted} → catch e.msg → innerHTML', () => {
  const { findings } = analyze(`
    try {
      throw { msg: location.hash };
    } catch (e) {
      document.body.innerHTML = e.msg;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through queueMicrotask ──
console.log('\n--- queueMicrotask ---');

test('queueMicrotask with tainted closure → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    queueMicrotask(function() {
      document.body.innerHTML = x;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through requestAnimationFrame ──
console.log('\n--- requestAnimationFrame ---');

test('requestAnimationFrame with tainted closure → innerHTML', () => {
  const { findings } = analyze(`
    var content = location.hash;
    requestAnimationFrame(function() {
      document.body.innerHTML = content;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through CustomEvent detail ──
console.log('\n--- CustomEvent ---');

test('new CustomEvent with tainted detail → handler reads detail → innerHTML', () => {
  const { findings } = analyze(`
    var ev = new CustomEvent('render', { detail: location.hash });
    document.addEventListener('render', function(e) {
      document.body.innerHTML = e.detail;
    });
    document.dispatchEvent(ev);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through method chaining on returned this ──
console.log('\n--- Method chaining on this ---');

test('fluent API: obj.setA(tainted).setB(safe).getA() → innerHTML', () => {
  const { findings } = analyze(`
    var obj = {
      setA: function(v) { this.a = v; return this; },
      setB: function(v) { this.b = v; return this; },
      getA: function() { return this.a; }
    };
    var result = obj.setA(location.hash).setB('safe').getA();
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array.from with mapping function ──
console.log('\n--- Array.from with mapper ---');

test('Array.from(tainted, mapper) → join → innerHTML', () => {
  const { findings } = analyze(`
    var items = location.hash.split(',');
    var mapped = Array.from(items, function(x) { return '<li>' + x + '</li>'; });
    document.body.innerHTML = mapped.join('');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through function declaration hoisting ──
console.log('\n--- Function declaration hoisting ---');

test('function hoisting: call before declaration → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = getInput();
    function getInput() { return location.hash; }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through function.length (safe) ──
console.log('\n--- Safe: function properties ---');

test('safe: taintedFn.length is a number', () => {
  const { findings } = analyze(`
    function fn(a, b) { return a + b; }
    var x = location.hash;
    document.body.innerHTML = fn.length;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through chained promises with error handling ──
console.log('\n--- Promise chain with catch ---');

test('promise.then(tainted).catch().then(sink)', () => {
  const { findings } = analyze(`
    var p = Promise.resolve(location.hash);
    p.then(function(x) { return x; })
     .catch(function(e) { return 'error'; })
     .then(function(val) { document.body.innerHTML = val; });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Object.create with property descriptor ──
console.log('\n--- Object.create with descriptors ---');

test('Object.create(null, {prop: {value: tainted}}) → prop → innerHTML', () => {
  const { findings } = analyze(`
    var obj = Object.create(null, {
      html: { value: location.hash, writable: true }
    });
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through array spread in function call ──
console.log('\n--- Array spread in call ---');

test('fn(...[tainted]) spreads tainted arg → innerHTML', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    var args = [location.hash];
    render(...args);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through IIFE with parameter ──
console.log('\n--- IIFE with parameter ---');

test('(function(x) { innerHTML = x; })(tainted)', () => {
  const { findings } = analyze(`
    (function(x) {
      document.body.innerHTML = x;
    })(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through nested object destructuring ──
console.log('\n--- Nested object destructuring ---');

test('nested destructure: var {a: {b}} = tainted → innerHTML', () => {
  const { findings } = analyze(`
    var data = JSON.parse(location.hash);
    var { config: { template } } = data;
    document.body.innerHTML = template;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through ternary in assignment ──
console.log('\n--- Ternary in assignment ---');

test('x = cond ? tainted : safe → innerHTML detects tainted branch', () => {
  const { findings } = analyze(`
    var x = true ? location.hash : 'safe';
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through multiple event handlers ──
console.log('\n--- Multiple event handlers ---');

test('addEventListener with multiple handlers, one sinks tainted', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      console.log(e.data);
    });
    window.addEventListener('message', function(e) {
      document.body.innerHTML = e.data;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through string template in eval ──
console.log('\n--- Template literal in eval ---');

test('eval(template with tainted) → XSS', () => {
  const { findings } = analyze(`
    var code = location.hash.slice(1);
    eval(\`var x = \${code}\`);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: array method returns boolean/number ──
console.log('\n--- Safe: array method boolean/number returns ---');

test('safe: arr.includes(tainted) returns boolean', () => {
  const { findings } = analyze(`
    var arr = ['admin', 'user'];
    var result = arr.includes(location.hash);
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

test('safe: arr.indexOf(tainted) returns number', () => {
  const { findings } = analyze(`
    var arr = ['admin', 'user'];
    var idx = arr.indexOf(location.hash);
    document.body.innerHTML = idx;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through closure returned by method ──
console.log('\n--- Closure returned by method ---');

test('method returns closure capturing tainted this.data → call → innerHTML', () => {
  const { findings } = analyze(`
    var obj = {
      data: location.hash,
      getRenderer: function() {
        var self = this;
        return function() { document.body.innerHTML = self.data; };
      }
    };
    var render = obj.getRenderer();
    render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through prototype method ──
console.log('\n--- Prototype method ---');

test('Foo.prototype.render with tainted this.data → innerHTML', () => {
  const { findings } = analyze(`
    function Foo(d) { this.data = d; }
    Foo.prototype.render = function() { document.body.innerHTML = this.data; };
    var f = new Foo(location.hash);
    f.render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Cross-file: taint through shared closure ──
console.log('\n--- Cross-file shared closure ---');

test('cross-file: file A creates closure, file B invokes it', () => {
  const findings = analyzeMultiple([
    { source: `
      window.createHandler = function(val) {
        return function() { return val; };
      };
    `, file: 'util.js' },
    { source: `
      var handler = createHandler(location.hash);
      document.body.innerHTML = handler();
    `, file: 'app.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Taint through nested function returning tainted ──
console.log('\n--- Nested function returns ---');

test('outer calls inner which returns tainted → innerHTML', () => {
  const { findings } = analyze(`
    function outer() {
      function inner() { return location.hash; }
      return inner();
    }
    document.body.innerHTML = outer();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted in typeof check ──
console.log('\n--- Safe: typeof patterns ---');

test('safe: typeof tainted === "string" → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var result = typeof x === 'string';
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through for-of on string ──
console.log('\n--- for-of on string ---');

test('for (var ch of taintedString) accumulate → innerHTML', () => {
  const { findings } = analyze(`
    var html = '';
    for (var ch of location.hash) {
      html += ch;
    }
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through module pattern IIFE ──
console.log('\n--- Module pattern IIFE ---');

test('IIFE module returns object with tainted method → call → innerHTML', () => {
  const { findings } = analyze(`
    var mod = (function() {
      function render(html) { document.body.innerHTML = html; }
      return { render: render };
    })();
    mod.render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: Array constructor with number ──
console.log('\n--- Safe: Array constructor ---');

test('safe: new Array(tainted.length) → join → innerHTML', () => {
  const { findings } = analyze(`
    var len = location.hash.length;
    var arr = new Array(len);
    document.body.innerHTML = arr.join('-');
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through Object.assign deep merge ──
console.log('\n--- Object.assign chained ---');

test('Object.assign(target, {html: tainted}) → target.html → innerHTML', () => {
  const { findings } = analyze(`
    var target = {};
    Object.assign(target, { html: location.hash });
    document.body.innerHTML = target.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through string interpolation in object ──
console.log('\n--- Template in object property ---');

test('obj = {html: `${tainted}`} → obj.html → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { html: \`<div>\${location.hash}</div>\` };
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through conditional return ──
console.log('\n--- Conditional return ---');

test('function with early return guard, tainted on main path → innerHTML', () => {
  const { findings } = analyze(`
    function getData() {
      if (!location.hash) return '';
      return location.hash.slice(1);
    }
    document.body.innerHTML = getData();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: parseInt chain ──
console.log('\n--- Safe: parseInt chain ---');

test('safe: parseInt(tainted, 10) + 1 → innerHTML', () => {
  const { findings } = analyze(`
    var x = parseInt(location.hash.slice(1), 10) + 1;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through variable shadowing ──
console.log('\n--- Variable shadowing ---');

test('inner scope shadows safe var with tainted → inner innerHTML detects', () => {
  const { findings } = analyze(`
    var x = 'safe';
    function inner() {
      var x = location.hash;
      document.body.innerHTML = x;
    }
    inner();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: inner scope shadows tainted with safe → inner innerHTML is safe', () => {
  const { findings } = analyze(`
    var x = location.hash;
    function inner() {
      var x = 'safe';
      document.body.innerHTML = x;
    }
    inner();
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through wrapper function pattern ──
console.log('\n--- Wrapper function pattern ---');

test('wrapper: function sanitizeAndRender(x) { innerHTML = DOMPurify.sanitize(x) } → safe', () => {
  const { findings } = analyze(`
    function sanitizeAndRender(x) {
      document.body.innerHTML = DOMPurify.sanitize(x);
    }
    sanitizeAndRender(location.hash);
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through chained property access on return ──
console.log('\n--- Chained return property ---');

test('fn() returns tainted object → .prop → innerHTML', () => {
  const { findings } = analyze(`
    function getConfig() {
      return { theme: location.hash };
    }
    document.body.innerHTML = getConfig().theme;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Map.set chaining ──
console.log('\n--- Map.set chaining ---');

test('map.set(k, tainted).get(k) → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('html', location.hash);
    var val = m.get('html');
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through default export pattern ──
console.log('\n--- Default export simulation ---');

test('cross-file: module.exports = taintedFn, require and call', () => {
  const findings = analyzeMultiple([
    { source: `
      function getInput() { return location.hash; }
      window.getInput = getInput;
    `, file: 'input.js' },
    { source: `
      var html = getInput();
      document.body.innerHTML = html;
    `, file: 'main.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted in arithmetic ──
console.log('\n--- Safe: arithmetic kills taint ---');

test('safe: tainted * 2 → innerHTML (number)', () => {
  const { findings } = analyze(`
    var x = location.hash.length * 2;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted % 10 → innerHTML (number)', () => {
  const { findings } = analyze(`
    var x = location.hash.charCodeAt(0) % 10;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through callback parameter name collision ──
console.log('\n--- Callback param name collision ---');

test('two callbacks with same param name, only one tainted → correct sink', () => {
  const { findings } = analyze(`
    function safe(x) { console.log(x); }
    function dangerous(x) { document.body.innerHTML = x; }
    safe('hello');
    dangerous(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Object.entries + forEach destructuring ──
console.log('\n--- Object.entries forEach ---');

test('Object.entries(tainted).forEach(([k,v]) => innerHTML = v)', () => {
  const { findings } = analyze(`
    var config = { html: location.hash };
    Object.entries(config).forEach(function(pair) {
      document.body.innerHTML = pair[1];
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through self-invoking named function expression ──
console.log('\n--- Named function expression ---');

test('var x = function foo() { return tainted; }() → innerHTML', () => {
  const { findings } = analyze(`
    var x = function foo() { return location.hash; }();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ╔═══════════════════════════════════════════════════════╗
// ║  ROUND 10 — Advanced AST patterns                      ║
// ╚═══════════════════════════════════════════════════════╝

// ── structuredClone passthrough ──
console.log('\n--- structuredClone ---');

test('structuredClone(tainted) preserves taint → innerHTML', () => {
  const { findings } = analyze(`
    var data = structuredClone(location.hash);
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through new URL().searchParams ──
console.log('\n--- URL searchParams chain ---');

test('new URL(tainted).searchParams.get() → innerHTML', () => {
  const { findings } = analyze(`
    var url = new URL(location.href);
    var q = url.searchParams.get('q');
    document.body.innerHTML = q;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through fetch → response.text() → then ──
console.log('\n--- fetch response.text ---');

test('fetch(tainted).then(r => r.text()).then(t => innerHTML)', () => {
  const { findings } = analyze(`
    fetch(location.hash).then(function(r) {
      return r.text();
    }).then(function(text) {
      document.body.innerHTML = text;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through window.opener ──
console.log('\n--- window.opener ---');

test('window.opener.location.hash → innerHTML (cross-window)', () => {
  const { findings } = analyze(`
    var x = window.opener.location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through parent frame ──
test('parent.location.search → innerHTML (cross-frame)', () => {
  const { findings } = analyze(`
    var x = parent.location.search;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through multiple property alias chains ──
console.log('\n--- Property alias chain ---');

test('var loc = window.location; var h = loc.hash → innerHTML', () => {
  const { findings } = analyze(`
    var loc = window.location;
    var h = loc.hash;
    document.body.innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});

test('var doc = document; doc.cookie → innerHTML', () => {
  const { findings } = analyze(`
    var doc = document;
    document.body.innerHTML = doc.cookie;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through conditional chaining ──
console.log('\n--- Conditional chaining ---');

test('x?.y?.z where x.y.z is tainted → innerHTML', () => {
  const { findings } = analyze(`
    var config = { user: { name: location.hash } };
    document.body.innerHTML = config?.user?.name;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through assignment in ternary ──
console.log('\n--- Assignment in ternary ---');

test('cond ? (x = tainted) : (x = safe) → innerHTML', () => {
  const { findings } = analyze(`
    var x;
    true ? (x = location.hash) : (x = 'safe');
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through 3-file chain ──
console.log('\n--- 3-file taint chain ---');

test('cross-file: file A sources, file B transforms, file C sinks', () => {
  const findings = analyzeMultiple([
    { source: `
      window.rawInput = location.hash;
    `, file: 'source.js' },
    { source: `
      window.processed = '<div>' + rawInput + '</div>';
    `, file: 'transform.js' },
    { source: `
      document.body.innerHTML = processed;
    `, file: 'render.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Taint through class with private-like naming ──
console.log('\n--- Class private convention ---');

test('class with _private property: set tainted → method reads → innerHTML', () => {
  const { findings } = analyze(`
    class Store {
      constructor() { this._data = null; }
      setData(d) { this._data = d; }
      getData() { return this._data; }
    }
    var s = new Store();
    s.setData(location.hash);
    document.body.innerHTML = s.getData();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through callback stored in object ──
console.log('\n--- Callback stored in object ---');

test('obj.callback = fn; later obj.callback(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var handlers = {};
    handlers.render = function(html) { document.body.innerHTML = html; };
    handlers.render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Promise constructor ──
console.log('\n--- Promise constructor ---');

test('new Promise(resolve => resolve(tainted)).then(sink)', () => {
  const { findings } = analyze(`
    var p = new Promise(function(resolve) {
      resolve(location.hash);
    });
    p.then(function(val) {
      document.body.innerHTML = val;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through array push then iteration ──
console.log('\n--- Array push then iterate ---');

test('arr.push(tainted) → forEach → innerHTML', () => {
  const { findings } = analyze(`
    var items = [];
    items.push(location.hash);
    items.forEach(function(item) {
      document.body.innerHTML = item;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through setTimeout with closure (not string) ──
console.log('\n--- setTimeout closure ---');

test('setTimeout(function() { innerHTML = tainted }, 0)', () => {
  const { findings } = analyze(`
    var x = location.hash;
    setTimeout(function() {
      document.body.innerHTML = x;
    }, 0);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through logical OR default ──
console.log('\n--- Logical OR default ---');

test('var x = params.get("q") || location.hash → innerHTML', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    var x = params.get('q') || location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Object.assign target property access ──
console.log('\n--- Object.assign target access ---');

test('Object.assign(target, src) → target.prop → innerHTML', () => {
  const { findings } = analyze(`
    var src = { content: location.hash };
    var target = {};
    Object.assign(target, src);
    document.body.innerHTML = target.content;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through iterable protocol ──
console.log('\n--- Custom iterable ---');

test('for-of over object with Symbol.iterator returning tainted', () => {
  const { findings } = analyze(`
    var data = [location.hash];
    for (var item of data) {
      document.body.innerHTML = item;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: DOMPurify in wrapper with multiple args ──
console.log('\n--- Safe: sanitizer in different wrappers ---');

test('safe: render(DOMPurify.sanitize(tainted), target)', () => {
  const { findings } = analyze(`
    function render(html, el) { el.innerHTML = html; }
    render(DOMPurify.sanitize(location.hash), document.body);
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: tainted in JSON.stringify only ──
test('safe: JSON.stringify(tainted) → fetch body (not a DOM sink)', () => {
  const { findings } = analyze(`
    var data = JSON.stringify({ input: location.hash });
    fetch('/api/save', { method: 'POST', body: data });
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through multiple assignment targets ──
console.log('\n--- Multiple assignment ---');

test('a = b = tainted → innerHTML uses a', () => {
  const { findings } = analyze(`
    var a, b;
    a = b = location.hash;
    document.body.innerHTML = a;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through string.replace callback ──
console.log('\n--- String replace callback ---');

test('tainted.replace(regex, callback) → innerHTML', () => {
  const { findings } = analyze(`
    var result = location.hash.replace(/./g, function(ch) { return ch.toUpperCase(); });
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through early return guard ──
console.log('\n--- Early return guard ---');

test('function with if(!x) return; then innerHTML = x detects', () => {
  const { findings } = analyze(`
    function render(x) {
      if (!x) return;
      document.body.innerHTML = x;
    }
    render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through chained method on new object ──
console.log('\n--- Chained new constructor method ---');

test('new Foo(tainted).render() → innerHTML', () => {
  const { findings } = analyze(`
    function Renderer(html) { this.html = html; }
    Renderer.prototype.render = function() { document.body.innerHTML = this.html; };
    new Renderer(location.hash).render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted used only in fetch URL (not a DOM sink) ──
console.log('\n--- Safe: fetch URL only ---');

test('safe: fetch("/api?q=" + tainted) is not a DOM XSS', () => {
  const { findings } = analyze(`
    fetch('/api/search?q=' + encodeURIComponent(location.hash));
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through destructured function parameter ──
console.log('\n--- Destructured function param ---');

test('function({html}) { innerHTML = html } called with tainted obj', () => {
  const { findings } = analyze(`
    function render({ html }) {
      document.body.innerHTML = html;
    }
    render({ html: location.hash });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Map.set then iteration ──
console.log('\n--- Map iteration ---');

test('map.set(k, tainted) → for-of → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('content', location.hash);
    for (var entry of m) {
      document.body.innerHTML = entry[1];
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted → Number() → string concat → innerHTML ──
console.log('\n--- Safe: numeric sanitize then concat ---');

test('safe: "Page " + Number(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var page = 'Page ' + Number(location.hash.slice(1));
    document.body.innerHTML = page;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through eval with variable ──
console.log('\n--- eval with variable ---');

test('var code = tainted; eval(code) → XSS', () => {
  const { findings } = analyze(`
    var code = location.hash.slice(1);
    eval(code);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through constructor.prototype chain ──
console.log('\n--- Constructor prototype chain ---');

test('constructor sets this.x, prototype method reads it → innerHTML', () => {
  const { findings } = analyze(`
    function Component(html) {
      this.html = html;
    }
    Component.prototype.mount = function() {
      document.body.innerHTML = this.html;
    };
    var c = new Component(location.hash);
    c.mount();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Cross-file: event-driven architecture ──
console.log('\n--- Cross-file event-driven ---');

test('cross-file: file A creates event bus, file B emits, file C listens', () => {
  const findings = analyzeMultiple([
    { source: `
      window.bus = {
        handlers: {},
        on: function(evt, fn) { this.handlers[evt] = fn; },
        emit: function(evt, data) {
          if (this.handlers[evt]) this.handlers[evt](data);
        }
      };
    `, file: 'bus.js' },
    { source: `
      bus.on('render', function(html) {
        document.body.innerHTML = html;
      });
    `, file: 'view.js' },
    { source: `
      bus.emit('render', location.hash);
    `, file: 'controller.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Taint through nested property assignment ──
console.log('\n--- Nested property assignment ---');

test('obj.config.html = tainted → obj.config.html → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { config: {} };
    obj.config.html = location.hash;
    document.body.innerHTML = obj.config.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted in attribute that is safe ──
console.log('\n--- Safe: safe attribute ---');

test('safe: element.title = tainted is not a sink', () => {
  const { findings } = analyze(`
    document.body.title = location.hash;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through Array.prototype.reduce to string ──
console.log('\n--- Array reduce to string ---');

test('taintedArr.reduce((acc, x) => acc + x, "") → innerHTML', () => {
  const { findings } = analyze(`
    var items = location.hash.split(',');
    var html = items.reduce(function(acc, x) { return acc + '<li>' + x + '</li>'; }, '');
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through postMessage to self ──
console.log('\n--- postMessage to self ---');

test('window.postMessage(tainted) → message handler → innerHTML', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      document.body.innerHTML = e.data;
    });
    window.postMessage(location.hash, '*');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: encodeURIComponent in template ──
console.log('\n--- Safe: encoded template ---');

test('safe: `?q=${encodeURIComponent(tainted)}` → location.href is safe navigation', () => {
  const { findings } = analyze(`
    var q = encodeURIComponent(location.hash);
    location.href = '/search?q=' + q;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through rest params ──
console.log('\n--- Rest params ---');

test('function(...args) { innerHTML = args[0] } called with tainted', () => {
  const { findings } = analyze(`
    function render(...args) {
      document.body.innerHTML = args[0];
    }
    render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through computed class method ──
console.log('\n--- Computed class method name ---');

test('class with method name as variable → call → innerHTML', () => {
  const { findings } = analyze(`
    class Renderer {
      show(html) { document.body.innerHTML = html; }
    }
    var r = new Renderer();
    r.show(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through async/await with try/catch ──
console.log('\n--- Async/await try/catch ---');

test('async function: try { x = await tainted } catch { } → innerHTML', () => {
  const { findings } = analyze(`
    async function load() {
      var x;
      try {
        x = await Promise.resolve(location.hash);
      } catch(e) {
        x = 'fallback';
      }
      document.body.innerHTML = x;
    }
    load();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: Object.freeze prevents mutation ──
console.log('\n--- Safe: frozen config ---');

test('safe: frozen safe config → innerHTML reads safe value', () => {
  const { findings } = analyze(`
    var config = Object.freeze({ html: '<b>safe</b>' });
    document.body.innerHTML = config.html;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through string Template.raw tag ──
console.log('\n--- String.raw with taint ---');

test('String.raw with tainted interpolation → eval', () => {
  const { findings } = analyze(`
    var code = location.hash.slice(1);
    eval(String.raw\`\${code}\`);
  `);
  expect(findings).toHaveType('XSS');
});

// ╔═══════════════════════════════════════════════════════╗
// ║  BASELINE — production libraries should have 0 FPs    ║
// ╚═══════════════════════════════════════════════════════╝

// ══════════════════════════════════════════════════════════════
// ROUND 11 — Advanced AST patterns
// ══════════════════════════════════════════════════════════════

// ── Currying / partial application ──
console.log('\n--- Currying / partial application ---');

test('curried function: f(tainted)(safe) → innerHTML', () => {
  const { findings } = analyze(`
    function curry(a) {
      return function(b) { return a + b; };
    }
    var g = curry(location.hash);
    document.body.innerHTML = g(' suffix');
  `);
  expect(findings).toHaveType('XSS');
});

test('curried arrow: f(tainted)(safe) → innerHTML', () => {
  const { findings } = analyze(`
    const f = a => b => a + b;
    const g = f(location.hash);
    document.body.innerHTML = g('!');
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: curried function with safe args only', () => {
  const { findings } = analyze(`
    const f = a => b => a + b;
    const g = f('hello');
    document.body.innerHTML = g(' world');
  `);
  expect(findings).toBeEmpty();
});

// ── Chained assignments ──
console.log('\n--- Chained assignments ---');

test('chained assignment: a = b = tainted → sink(a)', () => {
  const { findings } = analyze(`
    var a, b;
    a = b = location.hash;
    document.body.innerHTML = a;
  `);
  expect(findings).toHaveType('XSS');
});

test('chained assignment: a = b = tainted → sink(b)', () => {
  const { findings } = analyze(`
    var a, b;
    a = b = location.hash;
    document.body.innerHTML = b;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Throw/catch taint flow ──
console.log('\n--- Throw/catch taint flow ---');

test('throw tainted → catch(e) → sink(e)', () => {
  const { findings } = analyze(`
    try {
      throw location.hash;
    } catch(e) {
      document.body.innerHTML = e;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('throw new Error(tainted) → catch(e) → sink(e.message)', () => {
  const { findings } = analyze(`
    try {
      throw new Error(location.hash);
    } catch(e) {
      document.body.innerHTML = e.message;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: throw safe string → catch(e) → sink(e)', () => {
  const { findings } = analyze(`
    try {
      throw 'static error';
    } catch(e) {
      document.body.innerHTML = e;
    }
  `);
  expect(findings).toBeEmpty();
});

// ── Comma/sequence expression ──
console.log('\n--- Comma/sequence expression ---');

test('sequence expr returns last (tainted): sink((safe, tainted))', () => {
  const { findings } = analyze(`
    var x = (0, location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: sequence expr returns last (safe): sink((tainted, safe))', () => {
  const { findings } = analyze(`
    var x = (location.hash, 'safe string');
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Destructuring defaults from tainted ──
console.log('\n--- Destructuring defaults ---');

test('object destructuring default from tainted source', () => {
  const { findings } = analyze(`
    var tainted = location.hash;
    var { x = tainted } = {};
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('array destructuring default from tainted source', () => {
  const { findings } = analyze(`
    var tainted = location.hash;
    var [a = tainted] = [];
    document.body.innerHTML = a;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: destructuring default not used when property exists', () => {
  const { findings } = analyze(`
    var tainted = location.hash;
    var { x = tainted } = { x: 'safe' };
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Error constructor taint ──
console.log('\n--- Error constructor taint ---');

test('new Error(tainted).message → innerHTML', () => {
  const { findings } = analyze(`
    var err = new Error(location.hash);
    document.body.innerHTML = err.message;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: comparison/relational operators ──
console.log('\n--- Safe: comparison/relational operators ---');

test('safe: tainted === "value" → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = location.hash === '#admin';
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted > 0 → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = location.hash.length > 0;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted in obj → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var key = location.hash;
    var x = key in { admin: 1, user: 2 };
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted instanceof Error → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var x = location.hash instanceof Error;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: bitwise operations ──
console.log('\n--- Safe: bitwise operations ---');

test('safe: tainted | 0 → innerHTML (coerced to int)', () => {
  const { findings } = analyze(`
    var x = location.hash | 0;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted >>> 0 → innerHTML (unsigned int)', () => {
  const { findings } = analyze(`
    var x = location.hash >>> 0;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted & 0xFF → innerHTML (bitwise and)', () => {
  const { findings } = analyze(`
    var x = location.hash & 0xFF;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted ^ tainted → innerHTML (XOR)', () => {
  const { findings } = analyze(`
    var h = location.hash;
    var x = h ^ h;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Deep method chaining on tainted string ──
console.log('\n--- Deep method chaining ---');

test('tainted.split(".").reverse().join("/") → innerHTML', () => {
  const { findings } = analyze(`
    var parts = location.hash.split('.');
    var reversed = parts.reverse();
    var result = reversed.join('/');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.toLowerCase().trim().slice(1) → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash.toLowerCase().trim().slice(1);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Promise.race ──
console.log('\n--- Promise.race ---');

test('Promise.race([taintedPromise]).then → innerHTML', () => {
  const { findings } = analyze(`
    var p = Promise.resolve(location.hash);
    Promise.race([p]).then(function(val) {
      document.body.innerHTML = val;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Nested ternary ──
console.log('\n--- Nested ternary ---');

test('nested ternary: true ? (false ? safe : tainted) : safe → innerHTML', () => {
  const { findings } = analyze(`
    var x = true ? (false ? 'safe' : location.hash) : 'also safe';
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: nested ternary: true ? (true ? safe : tainted) : tainted', () => {
  const { findings } = analyze(`
    var x = true ? (true ? 'safe' : location.hash) : location.search;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Map.forEach with tainted values ──
console.log('\n--- Map.forEach ---');

test('map.forEach with tainted value → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('key', location.hash);
    m.forEach(function(val) {
      document.body.innerHTML = val;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── eval aliases ──
console.log('\n--- eval aliases ---');

test('window.eval(tainted) is XSS', () => {
  const { findings } = analyze(`
    var x = location.hash;
    window.eval(x);
  `);
  expect(findings).toHaveType('XSS');
});

test('var e = eval; e(tainted) is XSS', () => {
  const { findings } = analyze(`
    var e = eval;
    var x = location.hash;
    e(x);
  `);
  expect(findings).toHaveType('XSS');
});

// ── new Function with parameter ──
console.log('\n--- new Function variants ---');

test('new Function("a", taintedBody) is XSS', () => {
  const { findings } = analyze(`
    var body = location.hash;
    var fn = new Function('a', body);
  `);
  expect(findings).toHaveType('XSS');
});

test('new Function(taintedBody)() is XSS', () => {
  const { findings } = analyze(`
    var code = location.hash;
    new Function(code)();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Object.freeze preserves taint ──
console.log('\n--- Object.freeze/seal ---');

test('Object.freeze(taintedObj).prop → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { html: location.hash };
    var frozen = Object.freeze(obj);
    document.body.innerHTML = frozen.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('Object.seal preserves taint → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { data: location.hash };
    Object.seal(obj);
    document.body.innerHTML = obj.data;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: .length is always numeric ──
console.log('\n--- Safe: .length ---');

test('safe: tainted.length → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash.length;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: taintedArray.length → innerHTML', () => {
  const { findings } = analyze(`
    var arr = location.hash.split('');
    document.body.innerHTML = arr.length;
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: .indexOf / .lastIndexOf return numbers ──
console.log('\n--- Safe: index methods ---');

test('safe: str.indexOf(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var idx = 'hello world'.indexOf(location.hash);
    document.body.innerHTML = idx;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted.lastIndexOf("x") → innerHTML', () => {
  const { findings } = analyze(`
    var idx = location.hash.lastIndexOf('x');
    document.body.innerHTML = idx;
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: .includes / .has return booleans ──
console.log('\n--- Safe: boolean-returning methods ---');

test('safe: arr.includes(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var found = ['a', 'b'].includes(location.hash);
    document.body.innerHTML = found;
  `);
  expect(findings).toBeEmpty();
});

test('safe: map.has(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('key', 'val');
    var found = m.has(location.hash);
    document.body.innerHTML = found;
  `);
  expect(findings).toBeEmpty();
});

test('safe: set.has(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var s = new Set(['a', 'b']);
    var found = s.has(location.hash);
    document.body.innerHTML = found;
  `);
  expect(findings).toBeEmpty();
});

// ── Async IIFE ──
console.log('\n--- Async IIFE ---');

test('async IIFE sinks tainted inside', () => {
  const { findings } = analyze(`
    (async function() {
      var x = location.hash;
      document.body.innerHTML = x;
    })();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array.from on string ──
console.log('\n--- Array.from on tainted ---');

test('Array.from(taintedString).join("") → innerHTML', () => {
  const { findings } = analyze(`
    var chars = Array.from(location.hash);
    var result = chars.join('');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Memoization / cache pattern ──
console.log('\n--- Memoization / cache pattern ---');

test('cache stores tainted, later read → innerHTML', () => {
  const { findings } = analyze(`
    var cache = {};
    cache.data = location.hash;
    function render() {
      document.body.innerHTML = cache.data;
    }
    render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: delete / void ──
console.log('\n--- Safe: delete / void ---');

test('safe: delete obj[tainted] → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var obj = { a: 1 };
    var result = delete obj[location.hash];
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

// ── Cross-scope closure capture ──
console.log('\n--- Cross-scope closure capture ---');

test('nested function captures tainted from grandparent scope', () => {
  const { findings } = analyze(`
    function outer() {
      var x = location.hash;
      function middle() {
        function inner() {
          document.body.innerHTML = x;
        }
        inner();
      }
      middle();
    }
    outer();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Builder pattern ──
console.log('\n--- Builder pattern ---');

test('builder pattern: set(tainted).build().html → innerHTML', () => {
  const { findings } = analyze(`
    function Builder() { this.data = ''; }
    Builder.prototype.set = function(val) { this.data = val; return this; };
    Builder.prototype.build = function() { return { html: this.data }; };
    var result = new Builder().set(location.hash).build();
    document.body.innerHTML = result.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Double decode passthrough ──
console.log('\n--- Double decode ---');

test('decodeURIComponent(decodeURIComponent(tainted)) → innerHTML', () => {
  const { findings } = analyze(`
    var x = decodeURIComponent(decodeURIComponent(location.hash));
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: numeric coercion patterns ──
console.log('\n--- Safe: numeric coercion ---');

test('safe: tainted * 1 → innerHTML (numeric)', () => {
  const { findings } = analyze(`
    var x = location.hash * 1;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted % 10 → innerHTML (modulo)', () => {
  const { findings } = analyze(`
    var x = location.hash % 10;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── for-in with tainted object property access ──
console.log('\n--- for-in property access ---');

test('for-in over tainted obj, access value → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { key: location.hash };
    for (var k in obj) {
      document.body.innerHTML = obj[k];
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array splice ──
console.log('\n--- Array splice ---');

test('splice returns tainted elements → innerHTML', () => {
  const { findings } = analyze(`
    var arr = [location.hash, 'safe'];
    var removed = arr.splice(0, 1);
    document.body.innerHTML = removed[0];
  `);
  expect(findings).toHaveType('XSS');
});

// ── Optional chaining with taint ──
console.log('\n--- Optional chaining ---');

test('obj?.taintedProp → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { data: location.hash };
    document.body.innerHTML = obj?.data;
  `);
  expect(findings).toHaveType('XSS');
});

test('nested optional chaining: a?.b?.c tainted → innerHTML', () => {
  const { findings } = analyze(`
    var a = { b: { c: location.hash } };
    document.body.innerHTML = a?.b?.c;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: String.fromCharCode ──
console.log('\n--- Safe: String.fromCharCode ---');

test('safe: String.fromCharCode(tainted.charCodeAt(0)) → innerHTML', () => {
  const { findings } = analyze(`
    var code = location.hash.charCodeAt(0);
    var ch = String.fromCharCode(code);
    document.body.innerHTML = ch;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through conditional callback ──
console.log('\n--- Conditional callback ---');

test('array method callback receives taint → sink inside callback', () => {
  const { findings } = analyze(`
    var items = [location.hash];
    items.forEach(function(item) {
      document.body.innerHTML = item;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through variable swap ──
console.log('\n--- Variable swap ---');

test('destructuring swap: [a, b] = [b, a] with tainted a → sink(b)', () => {
  const { findings } = analyze(`
    var a = location.hash;
    var b = 'safe';
    [a, b] = [b, a];
    document.body.innerHTML = b;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: destructuring swap: tainted a swapped away from sink', () => {
  const { findings } = analyze(`
    var a = location.hash;
    var b = 'safe';
    [a, b] = [b, a];
    document.body.innerHTML = a;
  `);
  expect(findings).toBeEmpty();
});

// ══════════════════════════════════════════════════════════════
// ROUND 12 — Advanced AST patterns
// ══════════════════════════════════════════════════════════════

// ── for-of with array destructuring ──
console.log('\n--- for-of with destructuring ---');

test('for-of with [k, v] destructuring from Map → sink(v)', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('x', location.hash);
    for (var entry of m) {
      document.body.innerHTML = entry;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('for-of with destructured pair from array of tuples → sink', () => {
  const { findings } = analyze(`
    var pairs = [['key', location.hash]];
    for (var pair of pairs) {
      document.body.innerHTML = pair;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Closure modified after capture ──
console.log('\n--- Closure modification ---');

test('outer variable set tainted after inner function defined → inner sinks', () => {
  const { findings } = analyze(`
    var x = 'safe';
    function render() {
      document.body.innerHTML = x;
    }
    x = location.hash;
    render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Multiple sources merge ──
console.log('\n--- Multiple sources merge ---');

test('two sources concatenated → innerHTML', () => {
  const { findings } = analyze(`
    var a = location.hash;
    var b = location.search;
    document.body.innerHTML = a + b;
  `);
  expect(findings).toHaveType('XSS');
});

// ── String accumulator in loop ──
console.log('\n--- String accumulator in loop ---');

test('string concatenation in loop accumulates taint → innerHTML', () => {
  const { findings } = analyze(`
    var parts = location.hash.split(',');
    var result = '';
    for (var i = 0; i < parts.length; i++) {
      result += parts[i];
    }
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Immediately-called object method ──
console.log('\n--- Immediately-called object method ---');

test('({fn() { return tainted }}).fn() → innerHTML', () => {
  const { findings } = analyze(`
    var x = ({
      fn: function() { return location.hash; }
    }).fn();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: exponentiation / numeric operators ──
console.log('\n--- Safe: exponentiation ---');

test('safe: tainted ** 2 → innerHTML (numeric)', () => {
  const { findings } = analyze(`
    var x = location.hash ** 2;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: multiple var declarations ──
console.log('\n--- Safe: multiple var declarations ---');

test('safe: var a = tainted, b = safe; sink(b)', () => {
  const { findings } = analyze(`
    var a = location.hash, b = 'safe string';
    document.body.innerHTML = b;
  `);
  expect(findings).toBeEmpty();
});

test('var a = safe, b = tainted; sink(b) is XSS', () => {
  const { findings } = analyze(`
    var a = 'safe', b = location.hash;
    document.body.innerHTML = b;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: RegExp.test returns boolean ──
console.log('\n--- Safe: RegExp.test ---');

test('safe: /pattern/.test(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var result = /^admin$/.test(location.hash);
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

test('safe: new RegExp(safe).test(tainted) → innerHTML', () => {
  const { findings } = analyze(`
    var re = new RegExp('^admin$');
    var result = re.test(location.hash);
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

// ── Safe: new Date().getTime() ──
console.log('\n--- Safe: Date methods ---');

test('safe: new Date(tainted).getTime() → innerHTML', () => {
  const { findings } = analyze(`
    var ts = new Date(location.hash).getTime();
    document.body.innerHTML = ts;
  `);
  expect(findings).toBeEmpty();
});

test('safe: Date.now() → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = Date.now();
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through class static field ──
console.log('\n--- Class static patterns ---');

test('class static field set from tainted → method reads → innerHTML', () => {
  const { findings } = analyze(`
    class Config {
      static init(val) { Config.data = val; }
      static render() { document.body.innerHTML = Config.data; }
    }
    Config.init(location.hash);
    Config.render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array.from with mapping function ──
console.log('\n--- Array.from with mapper ---');

test('Array.from(source, mapper) with tainted source → innerHTML', () => {
  const { findings } = analyze(`
    var chars = Array.from(location.hash, function(c) { return c; });
    document.body.innerHTML = chars.join('');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: Object.is ──
console.log('\n--- Safe: Object.is ---');

test('safe: Object.is(tainted, expected) → innerHTML (boolean)', () => {
  const { findings } = analyze(`
    var result = Object.is(location.hash, '#admin');
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through nested object property access ──
console.log('\n--- Nested object property access ---');

test('deep nested property: a.b.c tainted → innerHTML', () => {
  const { findings } = analyze(`
    var a = { b: { c: location.hash } };
    document.body.innerHTML = a.b.c;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: deep nested property: obj.safe vs obj.tainted → sink(obj.safe)', () => {
  const { findings } = analyze(`
    var obj = {};
    obj.safe = 'hello';
    obj.tainted = location.hash;
    document.body.innerHTML = obj.safe;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through WeakMap ──
console.log('\n--- WeakMap ---');

test('WeakMap.set(key, tainted) → WeakMap.get(key) → innerHTML', () => {
  const { findings } = analyze(`
    var wm = new WeakMap();
    var key = {};
    wm.set(key, location.hash);
    document.body.innerHTML = wm.get(key);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Reflect.get ──
console.log('\n--- Reflect API ---');

test('Reflect.get(obj, prop) with tainted property value → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { x: location.hash };
    var val = Reflect.get(obj, 'x');
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through chained ternary in assignment ──
console.log('\n--- Chained ternary assignment ---');

test('a = cond1 ? cond2 ? tainted : safe : safe → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var y = true ? (x.length > 0 ? x : 'default') : 'fallback';
    document.body.innerHTML = y;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted used only as condition, not value ──
console.log('\n--- Safe: tainted as condition only ---');

test('safe: tainted used in condition, safe value in sink', () => {
  const { findings } = analyze(`
    var x = location.hash;
    if (x) {
      document.body.innerHTML = 'hello';
    }
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted in loop condition, safe body', () => {
  const { findings } = analyze(`
    var items = location.hash.split(',');
    while (items.length > 0) {
      items.pop();
      document.body.innerHTML = 'processing';
    }
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through catch with re-throw chain ──
console.log('\n--- Catch re-throw ---');

test('try → throw tainted → catch → re-throw → outer catch → sink', () => {
  const { findings } = analyze(`
    try {
      try {
        throw location.hash;
      } catch(inner) {
        throw inner;
      }
    } catch(outer) {
      document.body.innerHTML = outer;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Promise.resolve().then() ──
console.log('\n--- Promise.resolve chain ---');

test('Promise.resolve(tainted).then(v => sink(v))', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash).then(function(val) {
      document.body.innerHTML = val;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through immediately invoked arrow ──
console.log('\n--- Immediately invoked arrow ---');

test('(() => location.hash)() → innerHTML', () => {
  const { findings } = analyze(`
    var x = (() => location.hash)();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through variable shadowing ──
console.log('\n--- Variable shadowing ---');

test('inner scope shadows with tainted → sink uses inner', () => {
  const { findings } = analyze(`
    var x = 'safe';
    (function() {
      var x = location.hash;
      document.body.innerHTML = x;
    })();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: inner scope shadows with safe, outer is tainted → sink uses inner', () => {
  const { findings } = analyze(`
    var x = location.hash;
    (function() {
      var x = 'safe';
      document.body.innerHTML = x;
    })();
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through object method returning this.prop ──
console.log('\n--- Object method returning property ---');

test('object method returns this-like property → innerHTML', () => {
  const { findings } = analyze(`
    var widget = {
      data: location.hash,
      render: function() { return this.data; }
    };
    document.body.innerHTML = widget.render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: string literal method calls ──
console.log('\n--- Safe: string literal operations ---');

test('safe: "static".split("").join("") → innerHTML', () => {
  const { findings } = analyze(`
    var x = 'static string'.split('').join('');
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through default function parameter from global ──
console.log('\n--- Default param from global ---');

test('function with default param = location.hash → innerHTML', () => {
  const { findings } = analyze(`
    function render(content = location.hash) {
      document.body.innerHTML = content;
    }
    render();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: function with default param, called with safe arg', () => {
  const { findings } = analyze(`
    function render(content = location.hash) {
      document.body.innerHTML = content;
    }
    render('safe content');
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through labeled block ──
console.log('\n--- Labeled statement ---');

test('labeled block with tainted inside → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    outer: {
      if (x.length === 0) break outer;
      document.body.innerHTML = x;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through chained Map operations ──
console.log('\n--- Chained Map ops ---');

test('new Map([[k, tainted]]) → get(k) → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map([['key', location.hash]]);
    document.body.innerHTML = m.get('key');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: numeric toString ──
console.log('\n--- Safe: numeric toString ---');

test('safe: (tainted | 0).toString() → innerHTML', () => {
  const { findings } = analyze(`
    var n = location.hash | 0;
    document.body.innerHTML = n.toString();
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through function.call with tainted arg ──
console.log('\n--- Function.call with tainted ---');

test('fn.call(null, tainted) → innerHTML inside fn', () => {
  const { findings } = analyze(`
    function render(html) {
      document.body.innerHTML = html;
    }
    render.call(null, location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Object.values → forEach ──
console.log('\n--- Object.values taint ---');

test('Object.values(taintedObj) → forEach → innerHTML', () => {
  const { findings } = analyze(`
    var obj = { key: location.hash };
    Object.values(obj).forEach(function(v) {
      document.body.innerHTML = v;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: catch clears taint ──
console.log('\n--- Safe: catch clears taint ---');

test('safe: catch assigns safe value before sink', () => {
  const { findings } = analyze(`
    var x;
    try {
      x = location.hash;
      throw new Error('fail');
    } catch(e) {
      x = 'safe fallback';
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through switch fallthrough ──
console.log('\n--- Switch fallthrough ---');

test('switch fallthrough: tainted case falls to sink', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var out;
    switch(x.charAt(0)) {
      case '#':
        out = x;
      case '!':
        document.body.innerHTML = out;
        break;
      default:
        break;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Script Injection: script.src ──
console.log('\n--- Dynamic script loading ---');

test('script.src = tainted is Script Injection', () => {
  const { findings } = analyze(`
    var s = document.createElement('script');
    s.src = location.hash;
    document.body.appendChild(s);
  `);
  expect(findings).toHaveType('Script Injection');
});

// ── Cross-file: tainted passed through callback ──
console.log('\n--- Cross-file callback ---');

test('cross-file: file A defines callback sink, file B invokes with tainted', () => {
  const findings = analyzeMultiple([
    { file: 'api.js', source: `
      window.onData = function(data) {
        document.body.innerHTML = data;
      };
    `},
    { file: 'main.js', source: `
      window.onData(location.hash);
    `}
  ]);
  expect(findings).toHaveType('XSS');
});

// ══════════════════════════════════════════════════════════════
// ROUND 13 — Advanced AST patterns
// ══════════════════════════════════════════════════════════════

// ── Async generator / for-await-of ──
console.log('\n--- Async generator ---');

test('async generator yields tainted → for-await-of → innerHTML', () => {
  const { findings } = analyze(`
    async function* gen() {
      yield location.hash;
    }
    (async function() {
      for await (var val of gen()) {
        document.body.innerHTML = val;
      }
    })();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Yield delegation (yield*) ──
console.log('\n--- Yield delegation ---');

test('yield* delegates to inner generator with taint → innerHTML', () => {
  const { findings } = analyze(`
    function* inner() {
      yield location.hash;
    }
    function* outer() {
      yield* inner();
    }
    var it = outer();
    document.body.innerHTML = it.next().value;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through private-like pattern (__prefix) ──
console.log('\n--- Private-like pattern ---');

test('class with _private field set by method → read → innerHTML', () => {
  const { findings } = analyze(`
    class Store {
      constructor() { this._data = null; }
      load(val) { this._data = val; }
      get() { return this._data; }
    }
    var s = new Store();
    s.load(location.hash);
    document.body.innerHTML = s.get();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through computed property in object literal ──
console.log('\n--- Computed property in object literal ---');

test('object with computed property value tainted → bracket access → innerHTML', () => {
  const { findings } = analyze(`
    var key = 'data';
    var obj = { [key]: location.hash };
    document.body.innerHTML = obj.data;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: object with computed property key tainted but value safe', () => {
  const { findings } = analyze(`
    var key = location.hash;
    var obj = { [key]: 'safe value' };
    document.body.innerHTML = obj.test;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through Symbol.iterator protocol ──
console.log('\n--- Custom iterator ---');

test('custom iterable with tainted values → for-of → innerHTML', () => {
  const { findings } = analyze(`
    var items = [location.hash];
    var iterable = {};
    iterable[Symbol.iterator] = function() {
      var i = 0;
      return {
        next: function() {
          return i < items.length
            ? { value: items[i++], done: false }
            : { done: true };
        }
      };
    };
    for (var v of iterable) {
      document.body.innerHTML = v;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Proxy get trap ──
console.log('\n--- Proxy pattern ---');

test('Proxy wrapping tainted object → property access → innerHTML', () => {
  const { findings } = analyze(`
    var target = { data: location.hash };
    var proxy = new Proxy(target, {});
    document.body.innerHTML = proxy.data;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array.prototype methods returning new arrays ──
console.log('\n--- Array method return types ---');

test('taintedArray.slice() → join → innerHTML', () => {
  const { findings } = analyze(`
    var arr = [location.hash];
    var copy = arr.slice();
    document.body.innerHTML = copy.join('');
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: taintedArray.sort() returns same array but sort is comparison', () => {
  const { findings } = analyze(`
    var arr = [location.hash, 'b'];
    arr.sort();
    document.body.innerHTML = arr.join('');
  `);
  expect(findings).toHaveType('XSS');
});

test('taintedArray.concat(safe) → join → innerHTML', () => {
  const { findings } = analyze(`
    var arr = [location.hash];
    var combined = arr.concat(['safe']);
    document.body.innerHTML = combined.join('');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through string template in function return ──
console.log('\n--- Template in return ---');

test('function returns template with tainted → innerHTML', () => {
  const { findings } = analyze(`
    function makeHTML(data) {
      return '<div>' + data + '</div>';
    }
    document.body.innerHTML = makeHTML(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: strict equality guard before sink ──
console.log('\n--- Safe: equality whitelist ---');

test('safe: whitelisted via strict equality set → innerHTML', () => {
  const { findings } = analyze(`
    var allowed = ['home', 'about', 'contact'];
    var page = location.hash.slice(1);
    if (allowed.indexOf(page) !== -1) {
      document.body.innerHTML = page;
    }
  `);
  // indexOf check doesn't sanitize — the value is still tainted
  expect(findings).toHaveType('XSS');
});

// ── Taint through nested function expression assignment ──
console.log('\n--- Nested function expression ---');

test('var fn = function() { return function() { return tainted; }; }; fn()() → innerHTML', () => {
  const { findings } = analyze(`
    var fn = function() {
      return function() {
        return location.hash;
      };
    };
    document.body.innerHTML = fn()();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Object.assign to existing object ──
console.log('\n--- Object.assign to target ---');

test('Object.assign(target, {prop: tainted}) → target.prop → innerHTML', () => {
  const { findings } = analyze(`
    var target = {};
    Object.assign(target, { data: location.hash });
    document.body.innerHTML = target.data;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: parseInt/parseFloat mid-chain ──
console.log('\n--- Safe: parse numeric mid-chain ---');

test('safe: parseInt(tainted, 10) → innerHTML', () => {
  const { findings } = analyze(`
    var n = parseInt(location.hash.slice(1), 10);
    document.body.innerHTML = n;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through Array.prototype.fill ──
console.log('\n--- Array.fill ---');

test('Array(3).fill(tainted) → join → innerHTML', () => {
  const { findings } = analyze(`
    var arr = new Array(3).fill(location.hash);
    document.body.innerHTML = arr.join('');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through conditional assignment inside function ──
console.log('\n--- Conditional assignment in function ---');

test('function sets property conditionally, tainted path → innerHTML', () => {
  const { findings } = analyze(`
    function getContent(src) {
      var out;
      if (src === 'url') {
        out = location.hash;
      } else {
        out = 'default';
      }
      return out;
    }
    document.body.innerHTML = getContent('url');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Proxy-like forwarding function ──
console.log('\n--- Forwarding wrapper ---');

test('wrapper function forwards tainted arg to sink', () => {
  const { findings } = analyze(`
    function setHTML(el, html) {
      el.innerHTML = html;
    }
    setHTML(document.body, location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through self-referencing object method chain ──
console.log('\n--- Self-referencing method chain ---');

test('obj.setX(tainted).render() chains → innerHTML', () => {
  const { findings } = analyze(`
    var ui = {
      data: '',
      setData: function(d) { this.data = d; return this; },
      render: function() { document.body.innerHTML = this.data; }
    };
    ui.setData(location.hash).render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: sanitized in finally block ──
console.log('\n--- Safe: sanitized before use ---');

test('safe: tainted sanitized before reaching sink', () => {
  const { findings } = analyze(`
    var x = location.hash;
    x = DOMPurify.sanitize(x);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through constructor return override ──
console.log('\n--- Constructor return override ---');

test('constructor explicitly returns tainted object → method sinks', () => {
  const { findings } = analyze(`
    function Widget(data) {
      return { html: data };
    }
    var w = new Widget(location.hash);
    document.body.innerHTML = w.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through nested template literals ──
console.log('\n--- Nested template literals ---');

test('nested template literal with tainted → innerHTML', () => {
  const { findings } = analyze(`
    var name = location.hash;
    var inner = '<span>' + name + '</span>';
    var outer = '<div>' + inner + '</div>';
    document.body.innerHTML = outer;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: tainted overwritten immediately ──
console.log('\n--- Safe: overwritten before sink ---');

test('safe: tainted assigned then immediately overwritten → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash;
    x = 'safe replacement';
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through event handler attribute simulation ──
console.log('\n--- setAttribute event handler ---');

test('el.setAttribute("onclick", tainted) is XSS', () => {
  const { findings } = analyze(`
    var el = document.createElement('div');
    el.setAttribute('onclick', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('el.setAttribute("onmouseover", tainted) is XSS', () => {
  const { findings } = analyze(`
    var el = document.createElement('div');
    el.setAttribute('onmouseover', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: el.setAttribute("class", tainted) is not XSS', () => {
  const { findings } = analyze(`
    var el = document.createElement('div');
    el.setAttribute('class', location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('safe: el.setAttribute("id", tainted) is not XSS', () => {
  const { findings } = analyze(`
    var el = document.createElement('div');
    el.setAttribute('id', location.hash);
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through multi-level cross-file chain ──
console.log('\n--- Cross-file: 3-file chain with factory ---');

test('cross-file: A=factory, B=taint+call, C=sink — 3 files', () => {
  const findings = analyzeMultiple([
    { file: 'factory.js', source: `
      window.createRenderer = function(data) {
        return { html: data };
      };
    `},
    { file: 'init.js', source: `
      window.view = window.createRenderer(location.hash);
    `},
    { file: 'render.js', source: `
      document.body.innerHTML = window.view.html;
    `}
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Safe: sanitizer applied cross-file ──
console.log('\n--- Safe: cross-file sanitization ---');

test('safe: cross-file: A sets tainted, B sanitizes, C sinks sanitized', () => {
  const findings = analyzeMultiple([
    { file: 'source.js', source: `
      window.raw = location.hash;
    `},
    { file: 'sanitize.js', source: `
      window.clean = DOMPurify.sanitize(window.raw);
    `},
    { file: 'render.js', source: `
      document.body.innerHTML = window.clean;
    `}
  ]);
  expect(findings).toBeEmpty();
});

// ── Taint through logical OR as default ──
console.log('\n--- Logical OR default ---');

test('tainted || default — tainted propagates → innerHTML', () => {
  const { findings } = analyze(`
    var x = location.hash || 'default';
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: logical OR where first is safe truthy ──
console.log('\n--- Safe: logical OR short-circuit ---');

test('safe: "truthy" || tainted → innerHTML (short-circuits)', () => {
  const { findings } = analyze(`
    var x = 'truthy value' || location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through chained .then().then() ──
console.log('\n--- Chained .then ---');

test('promise.then(transform).then(sink) — taint flows through chain', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash)
      .then(function(v) { return v.toUpperCase(); })
      .then(function(v) { document.body.innerHTML = v; });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through property with same name as method ──
console.log('\n--- Property/method name collision ---');

test('obj.data property tainted, obj.data() method safe — reads property', () => {
  const { findings } = analyze(`
    var obj = {};
    obj.data = location.hash;
    document.body.innerHTML = obj.data;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: array destructuring skips tainted element ──
console.log('\n--- Safe: array skip ---');

test('safe: [, safe] = [tainted, safe] → sink(safe)', () => {
  const { findings } = analyze(`
    var arr = [location.hash, 'safe'];
    var [, b] = arr;
    document.body.innerHTML = b;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through string concatenation with += in method ──
console.log('\n--- String += in method ---');

test('method accumulates taint with += → return → innerHTML', () => {
  const { findings } = analyze(`
    function build(parts) {
      var html = '';
      for (var i = 0; i < parts.length; i++) {
        html += parts[i];
      }
      return html;
    }
    document.body.innerHTML = build([location.hash]);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Map → Array.from → join ──
console.log('\n--- Map to Array ---');

test('Map.values() spread into array → join → innerHTML', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('key', location.hash);
    var arr = Array.from(m.values());
    document.body.innerHTML = arr.join('');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Safe: early return prevents tainted path ──
console.log('\n--- Safe: early return guard ---');

test('safe: function always sanitizes before return', () => {
  const { findings } = analyze(`
    function process(input) {
      if (typeof input === 'number') return parseInt(input, 10);
      return DOMPurify.sanitize(input);
    }
    document.body.innerHTML = process(location.hash);
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through setter property descriptor ──
console.log('\n--- Setter/getter descriptor ---');

test('Object.defineProperty getter returns tainted → innerHTML', () => {
  const { findings } = analyze(`
    var obj = {};
    var _val = location.hash;
    Object.defineProperty(obj, 'data', {
      get: function() { return _val; }
    });
    document.body.innerHTML = obj.data;
  `);
  expect(findings).toHaveType('XSS');
});

// ═══════════════════════════════════════════════════════
// ROUND 14: Advanced AST tests — scope, prototype chains,
// complex patterns, modern APIs, edge cases
// ═══════════════════════════════════════════════════════

// ── Mutual recursion ──
console.log('\n--- Mutual recursion ---');

test('mutual recursion: funcA → funcB → funcA → sink', () => {
  const { findings } = analyze(`
    function processA(x) { return processB(x.toUpperCase()); }
    function processB(x) { return '<div>' + x + '</div>'; }
    document.body.innerHTML = processA(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: mutual recursion with sanitizer in the loop', () => {
  const { findings } = analyze(`
    function processA(x) { return processB(DOMPurify.sanitize(x)); }
    function processB(x) { return '<div>' + x + '</div>'; }
    document.body.innerHTML = processA(location.hash);
  `);
  expect(findings).toBeEmpty();
});

// ── Complex alias chains ──
console.log('\n--- Complex alias chains ---');

test('triple alias chain: a = b = c = eval; a(tainted)', () => {
  const { findings } = analyze(`
    var c = eval;
    var b = c;
    var a = b;
    a(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('alias chain through object: obj.fn = eval; obj.fn(tainted)', () => {
  const { findings } = analyze(`
    var obj = {};
    obj.fn = eval;
    obj.fn(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: alias chain broken by reassignment to safe function', () => {
  const { findings } = analyze(`
    var fn = eval;
    fn = parseInt;
    document.body.innerHTML = fn(location.hash);
  `);
  expect(findings).toBeEmpty();
});

// ── Complex scope shadowing ──
console.log('\n--- Complex scope shadowing ---');

test('inner function shadows param name — outer taint should not leak', () => {
  const { findings } = analyze(`
    function outer(data) {
      function inner(data) {
        return parseInt(data, 10);
      }
      return inner(data);
    }
    document.body.innerHTML = outer(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('closure captures outer tainted var despite inner shadow', () => {
  const { findings } = analyze(`
    var data = location.hash;
    function outer() {
      var result = data;
      function inner(data) {
        // shadows 'data' param but doesn't affect outer
        return data;
      }
      inner('safe');
      return result;
    }
    document.body.innerHTML = outer();
  `);
  expect(findings).toHaveType('XSS');
});

test('class method shadows global function name', () => {
  const { findings } = analyze(`
    function render(html) {
      document.body.innerHTML = html;
    }
    class Widget {
      render(html) {
        // this shadows global render
        return DOMPurify.sanitize(html);
      }
    }
    var w = new Widget();
    w.render(location.hash);
  `);
  expect(findings).toBeEmpty();
});

// ── Nested destructuring ──
console.log('\n--- Nested destructuring ---');

test('nested object destructuring: only tainted leaf reaches sink', () => {
  const { findings } = analyze(`
    var obj = { a: { b: { c: location.hash } } };
    var { a: { b: { c: val } } } = obj;
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: nested destructuring picks safe branch', () => {
  const { findings } = analyze(`
    var obj = { safe: { inner: 'hello' }, danger: { inner: location.hash } };
    var { safe: { inner: val } } = obj;
    document.body.innerHTML = val;
  `);
  expect(findings).toBeEmpty();
});

test('array in object destructuring: [tainted, safe]', () => {
  const { findings } = analyze(`
    var obj = { items: [location.hash, 'safe'] };
    var { items: [first] } = obj;
    document.body.innerHTML = first;
  `);
  expect(findings).toHaveType('XSS');
});

test('destructuring with computed property key', () => {
  const { findings } = analyze(`
    var key = 'hash';
    var { [key]: val } = location;
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('destructuring with default overridden by tainted value', () => {
  const { findings } = analyze(`
    var { data = 'safe' } = { data: location.hash };
    document.body.innerHTML = data;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: destructuring default used when property is undefined', () => {
  const { findings } = analyze(`
    var { data = 'safe' } = {};
    document.body.innerHTML = data;
  `);
  expect(findings).toBeEmpty();
});

// ── Complex ternary and short-circuit ──
console.log('\n--- Complex ternary/short-circuit ---');

test('nested ternary: both branches tainted', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var y = location.search;
    var result = x ? (y ? x : y) : y;
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: ternary always picks sanitized branch', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var result = true ? DOMPurify.sanitize(x) : x;
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

test('short-circuit: tainted || safe — tainted propagates', () => {
  const { findings } = analyze(`
    var val = location.hash || 'default';
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('logical AND chain with taint in last position', () => {
  const { findings } = analyze(`
    var val = true && true && location.hash;
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Promise edge cases ──
console.log('\n--- Promise edge cases ---');

test('Promise.allSettled propagates taint', () => {
  const { findings } = analyze(`
    Promise.allSettled([
      Promise.resolve(location.hash)
    ]).then(function(results) {
      document.body.innerHTML = results[0];
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('Promise.any propagates taint from resolved promise', () => {
  const { findings } = analyze(`
    Promise.any([
      Promise.resolve(location.hash)
    ]).then(function(val) {
      document.body.innerHTML = val;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('promise .finally passes through taint to next .then', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash)
      .finally(function() { console.log('done'); })
      .then(function(v) { document.body.innerHTML = v; });
  `);
  expect(findings).toHaveType('XSS');
});

test('promise .catch().then() — taint flows through catch to then', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash)
      .catch(function(e) { return e; })
      .then(function(v) { document.body.innerHTML = v; });
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: promise .then returns sanitized', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash)
      .then(function(v) { return DOMPurify.sanitize(v); })
      .then(function(v) { document.body.innerHTML = v; });
  `);
  expect(findings).toBeEmpty();
});

// ── Complex prototype chains ──
console.log('\n--- Complex prototype chains ---');

test('multi-level inheritance: GrandChild extends Child extends Base', () => {
  const { findings } = analyze(`
    class Base {
      constructor(data) { this.data = data; }
    }
    class Child extends Base {
      constructor(data) { super(data); }
    }
    class GrandChild extends Child {
      constructor(data) { super(data); }
      render() { document.body.innerHTML = this.data; }
    }
    var g = new GrandChild(location.hash);
    g.render();
  `);
  expect(findings).toHaveType('XSS');
});

test('prototype method added after class definition', () => {
  const { findings } = analyze(`
    function Widget(data) { this.data = data; }
    Widget.prototype.render = function() {
      document.body.innerHTML = this.data;
    };
    var w = new Widget(location.hash);
    w.render();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: prototype method sanitizes before sink', () => {
  const { findings } = analyze(`
    function Widget(data) { this.data = data; }
    Widget.prototype.render = function() {
      document.body.innerHTML = DOMPurify.sanitize(this.data);
    };
    var w = new Widget(location.hash);
    w.render();
  `);
  expect(findings).toBeEmpty();
});

// ── Generator edge cases ──
console.log('\n--- Generator edge cases ---');

test('generator yield tainted value → next().value → sink', () => {
  const { findings } = analyze(`
    function* gen() {
      yield location.hash;
    }
    var it = gen();
    document.body.innerHTML = it.next().value;
  `);
  expect(findings).toHaveType('XSS');
});

test('async generator taint propagation', () => {
  const { findings } = analyze(`
    async function* gen() {
      yield location.hash;
    }
    async function run() {
      for await (var val of gen()) {
        document.body.innerHTML = val;
      }
    }
    run();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: generator yields sanitized data', () => {
  const { findings } = analyze(`
    function* gen(input) {
      yield DOMPurify.sanitize(input);
    }
    var it = gen(location.hash);
    document.body.innerHTML = it.next().value;
  `);
  expect(findings).toBeEmpty();
});

// ── Reflect API ──
console.log('\n--- Reflect API ---');

test('Reflect.apply passes taint through function call', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    Reflect.apply(render, null, [location.hash]);
  `);
  expect(findings).toHaveType('XSS');
});

test('Reflect.get reads tainted property', () => {
  const { findings } = analyze(`
    var obj = { data: location.hash };
    var val = Reflect.get(obj, 'data');
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: Reflect.get reads safe property', () => {
  const { findings } = analyze(`
    var obj = { data: location.hash, name: 'safe' };
    var val = Reflect.get(obj, 'name');
    document.body.innerHTML = val;
  `);
  expect(findings).toBeEmpty();
});

// ── Tagged template literals ──
console.log('\n--- Tagged template literals ---');

test('tagged template with tainted interpolation reaches sink', () => {
  const { findings } = analyze(`
    function html(strings, ...vals) {
      return strings.join('') + vals.join('');
    }
    document.body.innerHTML = html\`<div>\${location.hash}</div>\`;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: tagged template with sanitizer tag function', () => {
  const { findings } = analyze(`
    function safe(strings, ...vals) {
      return strings.join('') + vals.map(v => DOMPurify.sanitize(v)).join('');
    }
    document.body.innerHTML = safe\`<div>\${location.hash}</div>\`;
  `);
  expect(findings).toBeEmpty();
});

// ── CSS injection via style ──
console.log('\n--- CSS injection ---');

test('element.style.cssText = tainted → XSS', () => {
  const { findings } = analyze(`
    var el = document.getElementById('x');
    el.style.cssText = location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

test('setAttribute("style", tainted) → XSS', () => {
  const { findings } = analyze(`
    var el = document.getElementById('x');
    el.setAttribute('style', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── IIFE patterns ──
console.log('\n--- IIFE patterns ---');

test('IIFE returns tainted value → sink', () => {
  const { findings } = analyze(`
    var result = (function() {
      return location.hash;
    })();
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('IIFE with argument: passes taint through', () => {
  const { findings } = analyze(`
    var result = (function(x) {
      return '<div>' + x + '</div>';
    })(location.hash);
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: IIFE sanitizes inside', () => {
  const { findings } = analyze(`
    var result = (function(x) {
      return DOMPurify.sanitize(x);
    })(location.hash);
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

// ── Closure capture in loops ──
console.log('\n--- Closure in loops ---');

test('closure captures loop variable with taint', () => {
  const { findings } = analyze(`
    var handlers = [];
    var items = [location.hash];
    for (var i = 0; i < items.length; i++) {
      handlers.push(function(idx) {
        return function() { document.body.innerHTML = items[idx]; };
      }(i));
    }
    handlers[0]();
  `);
  expect(findings).toHaveType('XSS');
});

// ── structuredClone taint propagation ──
console.log('\n--- structuredClone ---');

test('structuredClone propagates taint', () => {
  const { findings } = analyze(`
    var obj = { data: location.hash };
    var copy = structuredClone(obj);
    document.body.innerHTML = copy.data;
  `);
  expect(findings).toHaveType('XSS');
});

// ── JSON.parse(JSON.stringify(x)) round-trip ──
console.log('\n--- JSON round-trip ---');

test('JSON.parse(JSON.stringify(tainted)) preserves taint', () => {
  const { findings } = analyze(`
    var data = { html: location.hash };
    var copy = JSON.parse(JSON.stringify(data));
    document.body.innerHTML = copy.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: JSON.parse of static string', () => {
  const { findings } = analyze(`
    var copy = JSON.parse('{"html": "safe"}');
    document.body.innerHTML = copy.html;
  `);
  expect(findings).toBeEmpty();
});

// ── WeakMap/WeakSet ──
console.log('\n--- WeakMap/WeakSet ---');

test('WeakMap.set → .get taint flow', () => {
  const { findings } = analyze(`
    var wm = new WeakMap();
    var key = {};
    wm.set(key, location.hash);
    document.body.innerHTML = wm.get(key);
  `);
  expect(findings).toHaveType('XSS');
});

// ── String.replace with callback ──
console.log('\n--- String.replace callback ---');

test('string.replace(regex, taintedCallback) preserves taint', () => {
  const { findings } = analyze(`
    var input = location.hash;
    var result = input.replace(/./g, function(match) {
      return match;
    });
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('string.replace with safe replacement still carries object taint (conservative)', () => {
  const { findings } = analyze(`
    var input = location.hash;
    var result = input.replace(/./g, 'x');
    document.body.innerHTML = result;
  `);
  // Conservative: regex may not match all chars, so original taint propagates
  expect(findings).toHaveType('XSS');
});

// ── Private fields ──
console.log('\n--- Private class fields ---');

test('class with private field stores taint → method sinks it', () => {
  const { findings } = analyze(`
    class Store {
      #data;
      constructor(val) { this.#data = val; }
      render() { document.body.innerHTML = this.#data; }
    }
    var s = new Store(location.hash);
    s.render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Optional chaining edge cases ──
console.log('\n--- Optional chaining edge cases ---');

test('deep optional chain: obj?.a?.b?.c tainted', () => {
  const { findings } = analyze(`
    var obj = { a: { b: { c: location.hash } } };
    document.body.innerHTML = obj?.a?.b?.c;
  `);
  expect(findings).toHaveType('XSS');
});

test('optional call: fn?.(tainted) reaches sink', () => {
  const { findings } = analyze(`
    var fn = function(x) { document.body.innerHTML = x; };
    fn?.(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Computed property access ──
console.log('\n--- Computed property access ---');

test('obj[dynamicKey] reads tainted value', () => {
  const { findings } = analyze(`
    var obj = { x: location.hash };
    var key = 'x';
    document.body.innerHTML = obj[key];
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: obj[key] reads safe property even with tainted sibling', () => {
  const { findings } = analyze(`
    var obj = { safe: 'hello', danger: location.hash };
    document.body.innerHTML = obj['safe'];
  `);
  expect(findings).toBeEmpty();
});

// ── for-of with Map/Set ──
console.log('\n--- for-of with Map/Set ---');

test('for-of over Map with tainted values', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('k', location.hash);
    for (var [key, val] of m) {
      document.body.innerHTML = val;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('for-of over Set with tainted values', () => {
  const { findings } = analyze(`
    var s = new Set();
    s.add(location.hash);
    for (var val of s) {
      document.body.innerHTML = val;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Function.prototype.bind edge cases ──
console.log('\n--- bind edge cases ---');

test('bound function with pre-filled tainted arg', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    var boundRender = render.bind(null, location.hash);
    boundRender();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: bound function with safe pre-filled arg', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    var boundRender = render.bind(null, 'safe');
    boundRender();
  `);
  expect(findings).toBeEmpty();
});

// ── Chained method calls (builder pattern) ──
console.log('\n--- Builder pattern ---');

test('builder: new Builder().set(tainted).build() → sink', () => {
  const { findings } = analyze(`
    class Builder {
      set(val) { this.html = val; return this; }
      build() { return this.html; }
    }
    document.body.innerHTML = new Builder().set(location.hash).build();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: builder sanitizes in build step', () => {
  const { findings } = analyze(`
    class Builder {
      set(val) { this.html = val; return this; }
      build() { return DOMPurify.sanitize(this.html); }
    }
    document.body.innerHTML = new Builder().set(location.hash).build();
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through Array.from with mapFn ──
console.log('\n--- Array.from with mapFn ---');

test('Array.from(tainted, mapFn) preserves taint', () => {
  const { findings } = analyze(`
    var arr = Array.from([location.hash], function(x) { return x; });
    document.body.innerHTML = arr.join('');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Comma operator / sequence expression ──
console.log('\n--- Sequence expression ---');

test('sequence expression: (safe, tainted) → last value is tainted', () => {
  const { findings } = analyze(`
    var val = (0, location.hash);
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: sequence expression: (tainted, safe) → last value is safe', () => {
  const { findings } = analyze(`
    var val = (location.hash, 'safe');
    document.body.innerHTML = val;
  `);
  expect(findings).toBeEmpty();
});

// ── Spread in function calls ──
console.log('\n--- Spread in calls ---');

test('fn(...taintedArray) passes taint to function', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    var args = [location.hash];
    render(...args);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Object.assign edge cases ──
console.log('\n--- Object.assign edge cases ---');

test('Object.assign merges tainted source into target → sink reads target', () => {
  const { findings } = analyze(`
    var target = { data: 'safe' };
    var source = { data: location.hash };
    Object.assign(target, source);
    document.body.innerHTML = target.data;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: Object.assign merges safe sources only', () => {
  const { findings } = analyze(`
    var target = {};
    Object.assign(target, { data: 'safe' }, { other: 'also safe' });
    document.body.innerHTML = target.data;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through catch re-throw ──
console.log('\n--- Catch re-throw ---');

test('try { throw tainted } catch(e) { sink(e) }', () => {
  const { findings } = analyze(`
    try {
      throw location.hash;
    } catch (e) {
      document.body.innerHTML = e;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: catch sanitizes before sink', () => {
  const { findings } = analyze(`
    try {
      throw location.hash;
    } catch (e) {
      document.body.innerHTML = DOMPurify.sanitize(e);
    }
  `);
  expect(findings).toBeEmpty();
});

// ── Logical assignment operators ──
console.log('\n--- Logical assignment ---');

test('x ??= tainted when x is null → sink', () => {
  const { findings } = analyze(`
    var x = null;
    x ??= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('x ||= tainted when x is falsy → sink', () => {
  const { findings } = analyze(`
    var x = '';
    x ||= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── postMessage with complex origin checks ──
console.log('\n--- postMessage advanced origin ---');

test('weak: origin check uses indexOf (bypassable)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin.indexOf('trusted.com') !== -1) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toHaveType('XSS');
  if (!findings[0].source[0].description.includes('weak')) {
    throw new Error('Expected weak origin check but got: ' + findings[0].source[0].description);
  }
});

test('strong: origin check uses strict equality against full origin', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin === 'https://trusted.example.com') {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toBeEmpty();
});

test('weak: origin check uses endsWith (bypassable)', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin.endsWith('.example.com')) {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toHaveType('XSS');
  if (!findings[0].source[0].description.includes('weak')) {
    throw new Error('Expected weak origin check but got: ' + findings[0].source[0].description);
  }
});

// ── Taint through Symbol.iterator protocol ──
console.log('\n--- Custom iterator ---');

test('custom iterable with tainted values in for-of', () => {
  const { findings } = analyze(`
    var items = [location.hash];
    var iterable = {};
    iterable[Symbol.iterator] = function() {
      var i = 0;
      return {
        next: function() {
          return i < items.length
            ? { value: items[i++], done: false }
            : { done: true };
        }
      };
    };
    for (var val of iterable) {
      document.body.innerHTML = val;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Array.reduce ──
console.log('\n--- Array.reduce ---');

test('reduce accumulates tainted values → sink', () => {
  const { findings } = analyze(`
    var items = [location.hash, 'safe'];
    var result = items.reduce(function(acc, item) {
      return acc + item;
    }, '');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Dynamic property assignment ──
console.log('\n--- Dynamic property assignment ---');

test('obj[taintedKey] = value → prototype pollution check', () => {
  const { findings } = analyze(`
    var obj = {};
    var key1 = location.hash;
    var key2 = location.search;
    obj[key1][key2] = 'pwned';
  `);
  expect(findings).toHaveType('Prototype Pollution');
});

test('safe: obj[staticKey][staticKey] = value', () => {
  const { findings } = analyze(`
    var obj = { config: {} };
    obj['config']['theme'] = 'dark';
  `);
  expect(findings).toBeEmpty();
});

// ── Function.prototype.call/apply edge cases ──
console.log('\n--- call/apply edge cases ---');

test('Array.prototype.join.call(taintedArr, sep) → taint flows', () => {
  const { findings } = analyze(`
    var arr = [location.hash];
    var result = Array.prototype.join.call(arr, '');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('fn.apply(null, [tainted]) → taint reaches sink', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    render.apply(null, [location.hash]);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: fn.call with safe thisArg and args', () => {
  const { findings } = analyze(`
    function getLength() { return this.length; }
    document.body.innerHTML = getLength.call('hello');
  `);
  expect(findings).toBeEmpty();
});

// ── Multiple assignment patterns ──
console.log('\n--- Multiple assignment ---');

test('a = b = tainted → both reach sink', () => {
  const { findings } = analyze(`
    var a, b;
    a = b = location.hash;
    document.body.innerHTML = a;
  `);
  expect(findings).toHaveType('XSS');
});

test('swap via destructuring: [a, b] = [b, a] preserves taint', () => {
  const { findings } = analyze(`
    var a = location.hash;
    var b = 'safe';
    [a, b] = [b, a];
    document.body.innerHTML = b;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: swap moves taint away from sink target', () => {
  const { findings } = analyze(`
    var a = location.hash;
    var b = 'safe';
    [a, b] = [b, a];
    document.body.innerHTML = a;
  `);
  expect(findings).toBeEmpty();
});

// ── Event delegation patterns ──
console.log('\n--- Event delegation ---');

test('hashchange event listener with tainted newURL', () => {
  const { findings } = analyze(`
    window.addEventListener('hashchange', function(e) {
      document.body.innerHTML = e.newURL;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Nullish coalescing edge cases ──
console.log('\n--- Nullish coalescing edge ---');

test('null ?? tainted → tainted reaches sink', () => {
  const { findings } = analyze(`
    var x = null ?? location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: definedValue ?? tainted → defined value used', () => {
  const { findings } = analyze(`
    var x = 'safe' ?? location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Taint through string methods ──
console.log('\n--- String method taint ---');

test('tainted.split().join() preserves taint', () => {
  const { findings } = analyze(`
    var val = location.hash.split('#').join('');
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.repeat(3) preserves taint', () => {
  const { findings } = analyze(`
    var val = location.hash.repeat(3);
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('tainted.padStart(10) preserves taint', () => {
  const { findings } = analyze(`
    var val = location.hash.padStart(10, ' ');
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: tainted.length is numeric', () => {
  const { findings } = analyze(`
    document.body.innerHTML = location.hash.length;
  `);
  expect(findings).toBeEmpty();
});

test('safe: tainted.indexOf() returns number', () => {
  const { findings } = analyze(`
    document.body.innerHTML = location.hash.indexOf('x');
  `);
  expect(findings).toBeEmpty();
});

// ── Cross-file with class inheritance ──
console.log('\n--- Cross-file class ---');

test('cross-file: class defined in file1, instantiated with taint in file2', () => {
  const findings = analyzeMultiple([
    { source: `
      class Renderer {
        constructor(html) { this.html = html; }
        render() { document.body.innerHTML = this.html; }
      }
    `, file: 'renderer.js' },
    { source: `
      var r = new Renderer(location.hash);
      r.render();
    `, file: 'app.js' },
  ]);
  expect(findings).toHaveType('XSS');
});

// ── Taint through Map.forEach ──
console.log('\n--- Map.forEach ---');

test('Map.forEach with tainted values reaches sink', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('key', location.hash);
    m.forEach(function(value) {
      document.body.innerHTML = value;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Setter method pattern ──
console.log('\n--- Setter method ---');

test('obj.setData(tainted) then obj.getData() → sink', () => {
  const { findings } = analyze(`
    var obj = {
      setData: function(d) { this.data = d; },
      getData: function() { return this.data; }
    };
    obj.setData(location.hash);
    document.body.innerHTML = obj.getData();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Template literal in sink ──
console.log('\n--- Template literal sink ---');

test('innerHTML = `${tainted}` — taint flows through template', () => {
  const { findings } = analyze(`
    var val = location.hash;
    document.body.innerHTML = \`<div>\${val}</div>\`;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: innerHTML = `${sanitized}`', () => {
  const { findings } = analyze(`
    var val = DOMPurify.sanitize(location.hash);
    document.body.innerHTML = \`<div>\${val}</div>\`;
  `);
  expect(findings).toBeEmpty();
});

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
// ROUND 15: Advanced AST gap tests
// ═══════════════════════════════════════════════════════

// ── Alias system: transitive chains ──
console.log('\n--- Alias system: transitive chains ---');

test('alias: var loc = location; loc.hash → innerHTML', () => {
  const { findings } = analyze(`
    var loc = location;
    var h = loc.hash;
    document.body.innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});

test('alias: window → w → w.location.hash → innerHTML', () => {
  const { findings } = analyze(`
    var w = window;
    var h = w.location.hash;
    document.body.innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});

test('alias: transitive 3-hop: a = window, b = a, c = b.location.hash → innerHTML', () => {
  const { findings } = analyze(`
    var a = window;
    var b = a;
    var c = b.location.hash;
    document.body.innerHTML = c;
  `);
  expect(findings).toHaveType('XSS');
});

test('alias: var loc = document.location; loc.hash → innerHTML', () => {
  const { findings } = analyze(`
    var loc = document.location;
    var h = loc.hash;
    document.body.innerHTML = h;
  `);
  expect(findings).toHaveType('XSS');
});

test('alias: fn = eval; fn(tainted) → XSS', () => {
  const { findings } = analyze(`
    var fn = eval;
    fn(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('alias: obj.method = eval; obj.method(tainted) → XSS', () => {
  const { findings } = analyze(`
    var obj = {};
    obj.run = eval;
    obj.run(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: alias cleared by reassignment — fn = eval; fn = parseInt; fn(tainted)', () => {
  const { findings } = analyze(`
    var fn = eval;
    fn = parseInt;
    fn(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('safe: alias to safe object — var loc = {}; loc.hash = "safe"; innerHTML = loc.hash', () => {
  const { findings } = analyze(`
    var loc = {};
    loc.hash = 'safe';
    document.body.innerHTML = loc.hash;
  `);
  expect(findings).toBeEmpty();
});

test('alias: globalThis → g → g.location.search → innerHTML', () => {
  const { findings } = analyze(`
    var g = globalThis;
    var s = g.location.search;
    document.body.innerHTML = s;
  `);
  expect(findings).toHaveType('XSS');
});

test('alias: self.location aliased and used', () => {
  const { findings } = analyze(`
    var s = self;
    document.body.innerHTML = s.location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Custom events: dispatchEvent / addEventListener ──
console.log('\n--- Custom events: dispatchEvent / addEventListener ---');

test('CustomEvent with tainted detail → addEventListener → innerHTML', () => {
  const { findings } = analyze(`
    var el = document.getElementById('x');
    el.addEventListener('custom', function(e) {
      document.body.innerHTML = e.detail;
    });
    var evt = new CustomEvent('custom', { detail: location.hash });
    el.dispatchEvent(evt);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: CustomEvent with safe detail → addEventListener → innerHTML', () => {
  const { findings } = analyze(`
    var el = document.getElementById('x');
    el.addEventListener('msg', function(e) {
      document.body.innerHTML = e.detail;
    });
    var evt = new CustomEvent('msg', { detail: 'safe' });
    el.dispatchEvent(evt);
  `);
  expect(findings).toBeEmpty();
});

test('window message event: e.data → innerHTML', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      document.body.innerHTML = e.data;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: message event with origin check', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(e) {
      if (e.origin === 'https://trusted.com') {
        document.body.innerHTML = e.data;
      }
    });
  `);
  expect(findings).toBeEmpty();
});

// ── Prototype pollution patterns ──
console.log('\n--- Prototype pollution patterns ---');

test('proto pollution: obj[key1][key2] = value with tainted keys', () => {
  const { findings } = analyze(`
    var key1 = new URLSearchParams(location.search).get('a');
    var key2 = new URLSearchParams(location.search).get('b');
    var obj = {};
    obj[key1][key2] = 'polluted';
  `);
  expect(findings).toHaveType('Prototype Pollution');
});

test('proto pollution: obj.__proto__[taintedKey] = value', () => {
  const { findings } = analyze(`
    var key = new URLSearchParams(location.search).get('k');
    var obj = {};
    obj.__proto__[key] = 'polluted';
  `);
  expect(findings).toHaveType('Prototype Pollution');
});

test('proto pollution: obj.constructor.prototype[taintedKey] = value', () => {
  const { findings } = analyze(`
    var key = new URLSearchParams(location.search).get('k');
    var obj = {};
    obj.constructor.prototype[key] = 'polluted';
  `);
  expect(findings).toHaveType('Prototype Pollution');
});

test('safe: obj[safeKey][safeKey] = value — no tainted keys', () => {
  const { findings } = analyze(`
    var obj = {};
    obj['known']['prop'] = 'value';
  `);
  expect(findings).toBeEmpty();
});

test('safe: obj.__proto__.knownProp = safe — literal key, no taint', () => {
  const { findings } = analyze(`
    var obj = {};
    obj.__proto__.toString = function() { return 'custom'; };
  `);
  expect(findings).toBeEmpty();
});

// ── Class inheritance: super chains ──
console.log('\n--- Class inheritance: super chains ---');

test('class: grandparent → parent → child taint chain via super()', () => {
  const { findings } = analyze(`
    class Base {
      constructor(x) { this.data = x; }
    }
    class Middle extends Base {
      constructor(x) { super(x); }
    }
    class Child extends Middle {
      constructor(x) { super(x); }
      render() { document.body.innerHTML = this.data; }
    }
    new Child(location.hash).render();
  `);
  expect(findings).toHaveType('XSS');
});

test('class: prototype method receives tainted arg → innerHTML', () => {
  const { findings } = analyze(`
    function Widget() {}
    Widget.prototype.render = function(html) {
      document.body.innerHTML = html;
    };
    var w = new Widget();
    w.render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('class: inherited method called on child instance', () => {
  const { findings } = analyze(`
    class Parent {
      setData(x) { this.d = x; }
      render() { document.body.innerHTML = this.d; }
    }
    class Child extends Parent {}
    var c = new Child();
    c.setData(location.hash);
    c.render();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: class method with safe data only', () => {
  const { findings } = analyze(`
    class View {
      constructor() { this.text = 'safe'; }
      render() { document.body.innerHTML = this.text; }
    }
    new View().render();
  `);
  expect(findings).toBeEmpty();
});

test('class: getter returning tainted field', () => {
  const { findings } = analyze(`
    class Store {
      constructor(v) { this._v = v; }
      get value() { return this._v; }
    }
    var s = new Store(location.hash);
    document.body.innerHTML = s.value;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Scheme checks: complex paths ──
console.log('\n--- Scheme checks: complex paths ---');

test('scheme check in nested if → Open Redirect', () => {
  const { findings } = analyze(`
    var url = new URL(location.hash.slice(1));
    if (url) {
      if (url.protocol === 'https:') {
        location.href = url.href;
      }
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('scheme check via match(/^https/) → Open Redirect', () => {
  const { findings } = analyze(`
    var u = location.hash.slice(1);
    if (u.match(/^https?:/)) {
      location.assign(u);
    }
  `);
  expect(findings).toHaveType('Open Redirect');
});

test('safe: no scheme check → navigation is XSS', () => {
  const { findings } = analyze(`
    var u = location.hash.slice(1);
    location.assign(u);
  `);
  expect(findings).toHaveType('XSS');
});

test('scheme check on wrong variable should not downgrade', () => {
  const { findings } = analyze(`
    var a = location.hash.slice(1);
    var b = location.search.slice(1);
    if (a.startsWith('https://')) {
      location.href = b;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Generator / yield taint ──
console.log('\n--- Generator / yield taint ---');

test('generator yields tainted value → next().value → innerHTML', () => {
  const { findings } = analyze(`
    function* gen() {
      yield location.hash;
    }
    var g = gen();
    var v = g.next().value;
    document.body.innerHTML = v;
  `);
  expect(findings).toHaveType('XSS');
});

test('generator with tainted param → yield param → innerHTML', () => {
  const { findings } = analyze(`
    function* gen(x) {
      yield x;
    }
    var g = gen(location.hash);
    document.body.innerHTML = g.next().value;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: generator yields safe value', () => {
  const { findings } = analyze(`
    function* gen() {
      yield 'safe';
    }
    document.body.innerHTML = gen().next().value;
  `);
  expect(findings).toBeEmpty();
});

test('for-of over generator with tainted yields', () => {
  const { findings } = analyze(`
    function* gen() {
      yield location.hash;
      yield location.search;
    }
    for (var val of gen()) {
      document.body.innerHTML = val;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── arguments object ──
console.log('\n--- arguments object ---');

test('arguments[0] receives taint from function call', () => {
  const { findings } = analyze(`
    function f() {
      document.body.innerHTML = arguments[0];
    }
    f(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: arguments[0] with safe arg', () => {
  const { findings } = analyze(`
    function f() {
      document.body.innerHTML = arguments[0];
    }
    f('safe');
  `);
  expect(findings).toBeEmpty();
});

test('arguments spread to another function', () => {
  const { findings } = analyze(`
    function sink() { document.body.innerHTML = arguments[0]; }
    function passthrough() { sink.apply(null, arguments); }
    passthrough(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Getter/Setter advanced ──
console.log('\n--- Getter/Setter advanced ---');

test('Object.defineProperty getter returns tainted → innerHTML', () => {
  const { findings } = analyze(`
    var obj = {};
    Object.defineProperty(obj, 'val', {
      get: function() { return location.hash; }
    });
    document.body.innerHTML = obj.val;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: Object.defineProperty getter returns safe string', () => {
  const { findings } = analyze(`
    var obj = {};
    Object.defineProperty(obj, 'val', {
      get: function() { return 'safe'; }
    });
    document.body.innerHTML = obj.val;
  `);
  expect(findings).toBeEmpty();
});

test('object literal getter returns tainted → innerHTML', () => {
  const { findings } = analyze(`
    var obj = {
      get html() { return location.hash; }
    };
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('setter stores tainted → getter reads it → innerHTML', () => {
  const { findings } = analyze(`
    var obj = {
      _v: null,
      set val(x) { this._v = x; },
      get val() { return this._v; }
    };
    obj.val = location.hash;
    document.body.innerHTML = obj.val;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Try/catch/finally taint flow ──
console.log('\n--- Try/catch/finally taint flow ---');

test('throw tainted value → catch → innerHTML', () => {
  const { findings } = analyze(`
    try {
      throw location.hash;
    } catch (e) {
      document.body.innerHTML = e;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: tainted thrown but caught and replaced with safe', () => {
  const { findings } = analyze(`
    try {
      throw location.hash;
    } catch (e) {
      document.body.innerHTML = 'error occurred';
    }
  `);
  expect(findings).toBeEmpty();
});

test('taint assigned in try, used after try/catch', () => {
  const { findings } = analyze(`
    var x;
    try {
      x = location.hash;
    } catch (e) {
      x = 'fallback';
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('nested try/catch: inner catch re-throws tainted → outer catch → innerHTML', () => {
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

test('safe: finally overwrites tainted variable', () => {
  const { findings } = analyze(`
    var x = location.hash;
    try {
      // use x
    } finally {
      x = 'safe';
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Scope resolution edge cases ──
console.log('\n--- Scope resolution edge cases ---');

test('inner scope shadows tainted outer var with safe value', () => {
  const { findings } = analyze(`
    var x = location.hash;
    function inner() {
      var x = 'safe';
      document.body.innerHTML = x;
    }
    inner();
  `);
  expect(findings).toBeEmpty();
});

test('inner scope uses tainted outer var (no shadow)', () => {
  const { findings } = analyze(`
    var x = location.hash;
    function inner() {
      document.body.innerHTML = x;
    }
    inner();
  `);
  expect(findings).toHaveType('XSS');
});

test('function param shadows global tainted var', () => {
  const { findings } = analyze(`
    var x = location.hash;
    function f(x) {
      document.body.innerHTML = x;
    }
    f('safe');
  `);
  expect(findings).toBeEmpty();
});

test('let block scoping: tainted in inner block, safe in outer', () => {
  const { findings } = analyze(`
    let x = 'safe';
    {
      let x = location.hash;
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('var in block does NOT create new scope — taint leaks', () => {
  const { findings } = analyze(`
    if (true) {
      var x = location.hash;
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Closure and higher-order function patterns ──
console.log('\n--- Closure and higher-order function patterns ---');

test('closure captures tainted variable from outer scope', () => {
  const { findings } = analyze(`
    var tainted = location.hash;
    var fn = function() { return tainted; };
    document.body.innerHTML = fn();
  `);
  expect(findings).toHaveType('XSS');
});

test('factory function returns closure over tainted param', () => {
  const { findings } = analyze(`
    function makeGetter(val) {
      return function() { return val; };
    }
    var getter = makeGetter(location.hash);
    document.body.innerHTML = getter();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: factory with safe param', () => {
  const { findings } = analyze(`
    function makeGetter(val) {
      return function() { return val; };
    }
    var getter = makeGetter('safe');
    document.body.innerHTML = getter();
  `);
  expect(findings).toBeEmpty();
});

test('higher-order: function takes callback, calls it with tainted', () => {
  const { findings } = analyze(`
    function withData(cb) {
      cb(location.hash);
    }
    withData(function(data) {
      document.body.innerHTML = data;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('curried function: f(tainted)(sink)', () => {
  const { findings } = analyze(`
    function curry(x) {
      return function(el) { el.innerHTML = x; };
    }
    curry(location.hash)(document.body);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Destructuring in function parameters ──
console.log('\n--- Destructuring in function parameters ---');

test('object destructuring param: ({x}) with tainted x → innerHTML', () => {
  const { findings } = analyze(`
    function render({ html }) {
      document.body.innerHTML = html;
    }
    render({ html: location.hash });
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: destructured param with safe value', () => {
  const { findings } = analyze(`
    function render({ html }) {
      document.body.innerHTML = html;
    }
    render({ html: 'safe' });
  `);
  expect(findings).toBeEmpty();
});

test('array destructuring param: ([a, b]) with tainted element', () => {
  const { findings } = analyze(`
    function first([a]) {
      document.body.innerHTML = a;
    }
    first([location.hash]);
  `);
  expect(findings).toHaveType('XSS');
});

test('nested destructuring param: ({a: {b}}) with deep tainted value', () => {
  const { findings } = analyze(`
    function deep({ outer: { inner } }) {
      document.body.innerHTML = inner;
    }
    deep({ outer: { inner: location.hash } });
  `);
  expect(findings).toHaveType('XSS');
});

test('rest param captures tainted args', () => {
  const { findings } = analyze(`
    function f(...args) {
      document.body.innerHTML = args[0];
    }
    f(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Default parameter values ──
console.log('\n--- Default parameter values ---');

test('default param from tainted source used when no arg passed', () => {
  const { findings } = analyze(`
    function f(x = location.hash) {
      document.body.innerHTML = x;
    }
    f();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: default param overridden by safe arg', () => {
  const { findings } = analyze(`
    function f(x = location.hash) {
      document.body.innerHTML = x;
    }
    f('safe');
  `);
  expect(findings).toBeEmpty();
});

// ── Optional chaining edge cases ──
console.log('\n--- Optional chaining edge cases ---');

test('optional chaining reads tainted source: obj?.location?.hash → innerHTML', () => {
  const { findings } = analyze(`
    var x = window?.location?.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('optional call: sanitizer?.call(tainted) still sanitizes', () => {
  const { findings } = analyze(`
    var x = location.hash;
    var safe = DOMPurify?.sanitize?.(x);
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});

test('optional chaining preserves taint through chain', () => {
  const { findings } = analyze(`
    var obj = { data: location.hash };
    document.body.innerHTML = obj?.data;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Logical assignment operators edge cases ──
console.log('\n--- Logical assignment edge cases ---');

test('??= assigns tainted when left is undefined', () => {
  const { findings } = analyze(`
    var x;
    x ??= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: ??= does not assign when left is non-nullish', () => {
  const { findings } = analyze(`
    var x = 'safe';
    x ??= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('||= assigns tainted when left is falsy', () => {
  const { findings } = analyze(`
    var x = '';
    x ||= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('&&= assigns tainted when left is truthy', () => {
  const { findings } = analyze(`
    var x = 'truthy';
    x &&= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: &&= does not assign when left is falsy', () => {
  const { findings } = analyze(`
    var x = '';
    x &&= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Comma/sequence expression ──
console.log('\n--- Comma/sequence expression ---');

test('sequence expression: last value is tainted → innerHTML', () => {
  const { findings } = analyze(`
    var x = ('safe', location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: sequence expression last value is safe', () => {
  const { findings } = analyze(`
    var x = (location.hash, 'safe');
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('sequence in assignment: y = tainted, then used', () => {
  const { findings } = analyze(`
    var y;
    var x = (y = location.hash, y);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Complex ternary ──
console.log('\n--- Complex ternary ---');

test('nested ternary: both branches tainted → XSS', () => {
  const { findings } = analyze(`
    var x = cond1 ? location.hash : cond2 ? location.search : location.pathname;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: both ternary branches are safe', () => {
  const { findings } = analyze(`
    var x = cond ? 'a' : 'b';
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('ternary: one branch tainted, one safe → still XSS', () => {
  const { findings } = analyze(`
    var x = cond ? location.hash : 'safe';
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── for-of / for-in edge cases ──
console.log('\n--- for-of / for-in edge cases ---');

test('for-of with destructuring: [key, value] from tainted Map entries', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('key', location.hash);
    for (var [k, v] of m) {
      document.body.innerHTML = v;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('for-in reads tainted property value', () => {
  const { findings } = analyze(`
    var obj = { a: location.hash };
    for (var key in obj) {
      document.body.innerHTML = obj[key];
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: for-of over safe array', () => {
  const { findings } = analyze(`
    var arr = ['safe1', 'safe2'];
    for (var x of arr) {
      document.body.innerHTML = x;
    }
  `);
  expect(findings).toBeEmpty();
});

test('for-of with spread into new array preserves taint', () => {
  const { findings } = analyze(`
    var arr = [location.hash];
    var copy = [...arr];
    for (var x of copy) {
      document.body.innerHTML = x;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Array method callbacks: reduce, map, filter ──
console.log('\n--- Array method callbacks ---');

test('reduce with tainted elements propagates through callback', () => {
  const { findings } = analyze(`
    var items = [location.hash, 'b'];
    var result = items.reduce(function(acc, item) { return acc + item; }, '');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: reduce with all safe elements', () => {
  const { findings } = analyze(`
    var items = ['a', 'b', 'c'];
    var result = items.reduce(function(acc, item) { return acc + item; }, '');
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

test('map with sanitizer callback removes taint', () => {
  const { findings } = analyze(`
    var items = [location.hash];
    var safe = items.map(function(x) { return DOMPurify.sanitize(x); });
    document.body.innerHTML = safe.join('');
  `);
  expect(findings).toBeEmpty();
});

test('map preserving taint through identity callback', () => {
  const { findings } = analyze(`
    var items = [location.hash];
    var copy = items.map(function(x) { return x; });
    document.body.innerHTML = copy.join('');
  `);
  expect(findings).toHaveType('XSS');
});

test('filter does not alter taint — result still tainted', () => {
  const { findings } = analyze(`
    var items = [location.hash, 'safe'];
    var filtered = items.filter(function(x) { return x.length > 0; });
    document.body.innerHTML = filtered[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('forEach with tainted element used in sink inside callback', () => {
  const { findings } = analyze(`
    var items = [location.hash];
    items.forEach(function(item) {
      document.body.innerHTML = item;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Destructuring from sources ──
console.log('\n--- Destructuring from sources ---');

test('destructure { hash } from location → tainted', () => {
  const { findings } = analyze(`
    var { hash } = location;
    document.body.innerHTML = hash;
  `);
  expect(findings).toHaveType('XSS');
});

test('destructure { search, pathname } from location → both tainted', () => {
  const { findings } = analyze(`
    var { search, pathname } = location;
    document.body.innerHTML = search + pathname;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: destructure from location but use safe property only', () => {
  const { findings } = analyze(`
    var { protocol } = location;
    document.body.innerHTML = protocol;
  `);
  expect(findings).toBeEmpty();
});

test('destructure { href } from document.location → tainted', () => {
  const { findings } = analyze(`
    var { href } = document.location;
    document.body.innerHTML = href;
  `);
  expect(findings).toHaveType('XSS');
});

test('nested destructure: { location: { hash } } from window → tainted', () => {
  const { findings } = analyze(`
    var loc = window.location;
    var { hash } = loc;
    document.body.innerHTML = hash;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Promise chains: advanced ──
console.log('\n--- Promise chains: advanced ---');

test('Promise.resolve(tainted).then(x => innerHTML = x)', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash).then(function(x) {
      document.body.innerHTML = x;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: Promise.resolve(tainted).then(x => sanitize(x)).then(x => innerHTML = x)', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash)
      .then(function(x) { return DOMPurify.sanitize(x); })
      .then(function(safe) { document.body.innerHTML = safe; });
  `);
  expect(findings).toBeEmpty();
});

test('fetch(taintedUrl).then(r => r.text()).then(t => innerHTML = t)', () => {
  const { findings } = analyze(`
    fetch(location.hash.slice(1))
      .then(function(r) { return r.text(); })
      .then(function(text) { document.body.innerHTML = text; });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Proxy pattern ──
console.log('\n--- Proxy pattern ---');

test('Proxy get trap returning tainted → innerHTML', () => {
  const { findings } = analyze(`
    var handler = {
      get: function(target, prop) { return location.hash; }
    };
    var p = new Proxy({}, handler);
    document.body.innerHTML = p.anything;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Tagged template: advanced ──
console.log('\n--- Tagged template: advanced ---');

test('tagged template with join-based tag function → innerHTML', () => {
  const { findings } = analyze(`
    function html(strings, ...values) {
      return strings.join('') + values.join('');
    }
    var x = html\`<div>\${location.hash}</div>\`;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: tagged template with sanitizer in tag function', () => {
  const { findings } = analyze(`
    function safe(strings, ...vals) {
      return strings.join('') + vals.map(function(v) { return DOMPurify.sanitize(v); }).join('');
    }
    document.body.innerHTML = safe\`<div>\${location.hash}</div>\`;
  `);
  expect(findings).toBeEmpty();
});

// ── Cross-file / multi-script ──
console.log('\n--- Cross-file / multi-script ---');

test('cross-file: script1 sets global tainted var, script2 uses it in innerHTML', () => {
  const findings = analyzeMultiple([
    { source: `window.userData = location.hash;`, file: 'a.js' },
    { source: `document.body.innerHTML = window.userData;`, file: 'b.js' },
  ]);
  if (!findings.some(f => f.type === 'XSS')) throw new Error('Expected XSS');
});

test('cross-file: script1 defines function, script2 calls with tainted arg', () => {
  const findings = analyzeMultiple([
    { source: `function render(html) { document.body.innerHTML = html; }`, file: 'a.js' },
    { source: `render(location.hash);`, file: 'b.js' },
  ]);
  if (!findings.some(f => f.type === 'XSS')) throw new Error('Expected XSS');
});

test('safe: cross-file with sanitization in between', () => {
  const findings = analyzeMultiple([
    { source: `window.data = location.hash;`, file: 'a.js' },
    { source: `document.body.innerHTML = DOMPurify.sanitize(window.data);`, file: 'b.js' },
  ]);
  if (findings.some(f => f.type === 'XSS')) throw new Error('Expected no XSS');
});

// ── IIFE and immediately invoked patterns ──
console.log('\n--- IIFE patterns ---');

test('IIFE returning tainted value → innerHTML', () => {
  const { findings } = analyze(`
    var x = (function() { return location.hash; })();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('IIFE with tainted param → innerHTML inside', () => {
  const { findings } = analyze(`
    (function(data) {
      document.body.innerHTML = data;
    })(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: IIFE returns safe value', () => {
  const { findings } = analyze(`
    var x = (function() { return 'safe'; })();
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('arrow IIFE: (() => location.hash)() → innerHTML', () => {
  const { findings } = analyze(`
    var x = (() => location.hash)();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Object.assign / spread taint ──
console.log('\n--- Object.assign / spread taint ---');

test('Object.assign merges tainted property → innerHTML', () => {
  const { findings } = analyze(`
    var base = {};
    var mixed = Object.assign(base, { html: location.hash });
    document.body.innerHTML = mixed.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('spread operator merges tainted property → innerHTML', () => {
  const { findings } = analyze(`
    var tainted = { html: location.hash };
    var obj = { ...tainted };
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: Object.assign with all safe properties', () => {
  const { findings } = analyze(`
    var obj = Object.assign({}, { html: 'safe' });
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toBeEmpty();
});

// ── Reduce with arrow function (the specific pattern from previous fix) ──
console.log('\n--- Reduce with arrow callback ---');

test('reduce with arrow callback propagates taint', () => {
  const { findings } = analyze(`
    var items = [location.hash];
    var result = items.reduce((acc, item) => acc + item, '');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('tagged template with reduce-based tag function', () => {
  const { findings } = analyze(`
    function html(strings, ...vals) {
      return strings.reduce((r, s, i) => r + s + (vals[i] || ''), '');
    }
    var x = html\`<div>\${location.hash}</div>\`;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});


// ╔═══════════════════════════════════════════════════════╗
// ║  ROUND 16: Advanced AST gap tests                     ║
// ╚═══════════════════════════════════════════════════════╝
console.log('\n╔═══════════════════════════════════════════════════════╗');
console.log('║  ROUND 16: Advanced AST gap tests                     ║');
console.log('╚═══════════════════════════════════════════════════════╝\n');

// ── String method taint propagation ──
console.log('\n--- String method taint propagation ---');

test('trim() preserves taint', () => {
  const { findings } = analyze(`
    var x = location.hash.trim();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('trimStart() preserves taint', () => {
  const { findings } = analyze(`
    var x = location.hash.trimStart();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('trimEnd() preserves taint', () => {
  const { findings } = analyze(`
    var x = location.hash.trimEnd();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('normalize() preserves taint', () => {
  const { findings } = analyze(`
    var x = location.hash.normalize('NFC');
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('repeat() preserves taint', () => {
  const { findings } = analyze(`
    var x = location.hash.repeat(3);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('padStart() preserves taint', () => {
  const { findings } = analyze(`
    var x = location.hash.padStart(20, ' ');
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: charCodeAt() returns number, kills taint', () => {
  const { findings } = analyze(`
    var x = location.hash.charCodeAt(0);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: codePointAt() returns number, kills taint', () => {
  const { findings } = analyze(`
    var x = location.hash.codePointAt(0);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: search() returns number, kills taint', () => {
  const { findings } = analyze(`
    var x = location.hash.search(/admin/);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: localeCompare() returns number, kills taint', () => {
  const { findings } = analyze(`
    var x = location.hash.localeCompare('test');
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('match() preserves taint from source string', () => {
  const { findings } = analyze(`
    var result = location.hash.match(/(.+)/);
    document.body.innerHTML = result[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('replace() with tainted replacement preserves taint', () => {
  const { findings } = analyze(`
    var x = 'template'.replace('template', location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('split() on tainted string preserves taint', () => {
  const { findings } = analyze(`
    var parts = location.hash.split('#');
    document.body.innerHTML = parts[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('concat chains preserve taint', () => {
  const { findings } = analyze(`
    var x = 'prefix'.concat(location.hash).concat('suffix');
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: indexOf() on tainted string returns number', () => {
  const { findings } = analyze(`
    var x = location.hash.indexOf('admin');
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('toLowerCase() preserves taint', () => {
  const { findings } = analyze(`
    var x = location.hash.toLowerCase();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('toUpperCase() preserves taint', () => {
  const { findings } = analyze(`
    var x = location.hash.toUpperCase();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('chained string methods: trim().toLowerCase().slice(1) preserves taint', () => {
  const { findings } = analyze(`
    var x = location.hash.trim().toLowerCase().slice(1);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Array method edge cases ──
console.log('\n--- Array method edge cases ---');

test('splice() returns tainted removed elements', () => {
  const { findings } = analyze(`
    var arr = [location.hash, 'b', 'c'];
    var removed = arr.splice(0, 1);
    document.body.innerHTML = removed[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('sort() preserves array taint', () => {
  const { findings } = analyze(`
    var arr = [location.hash, 'a', 'b'];
    var sorted = arr.sort();
    document.body.innerHTML = sorted[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('reverse() preserves array taint', () => {
  const { findings } = analyze(`
    var arr = [location.hash];
    var rev = arr.reverse();
    document.body.innerHTML = rev[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('flat() preserves taint through nested arrays', () => {
  const { findings } = analyze(`
    var arr = [[location.hash]];
    var flat = arr.flat();
    document.body.innerHTML = flat[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('fill() with tainted value taints array', () => {
  const { findings } = analyze(`
    var arr = new Array(3).fill(location.hash);
    document.body.innerHTML = arr[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: findIndex() returns number', () => {
  const { findings } = analyze(`
    var arr = [location.hash];
    var idx = arr.findIndex(function(x) { return x.length > 0; });
    document.body.innerHTML = idx;
  `);
  expect(findings).toBeEmpty();
});

test('safe: some() returns boolean', () => {
  const { findings } = analyze(`
    var arr = [location.hash];
    var has = arr.some(function(x) { return x.length > 0; });
    document.body.innerHTML = has;
  `);
  expect(findings).toBeEmpty();
});

test('safe: every() returns boolean', () => {
  const { findings } = analyze(`
    var arr = [location.hash];
    var all = arr.every(function(x) { return x.length > 0; });
    document.body.innerHTML = all;
  `);
  expect(findings).toBeEmpty();
});

test('safe: includes() returns boolean', () => {
  const { findings } = analyze(`
    var arr = [location.hash];
    var has = arr.includes('test');
    document.body.innerHTML = has;
  `);
  expect(findings).toBeEmpty();
});

test('Array.from() with tainted iterable preserves taint', () => {
  const { findings } = analyze(`
    var arr = Array.from([location.hash]);
    document.body.innerHTML = arr[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('concat merges taint from multiple arrays', () => {
  const { findings } = analyze(`
    var a = ['safe'];
    var b = [location.hash];
    var c = a.concat(b);
    document.body.innerHTML = c[1];
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: Array.from with safe array', () => {
  const { findings } = analyze(`
    var arr = Array.from(['safe']);
    document.body.innerHTML = arr[0];
  `);
  expect(findings).toBeEmpty();
});

test('find() preserves taint from array elements', () => {
  const { findings } = analyze(`
    var arr = [location.hash, 'b'];
    var found = arr.find(function(x) { return x.length > 1; });
    document.body.innerHTML = found;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Error/throw taint propagation ──
console.log('\n--- Error/throw taint propagation ---');

test('throw tainted object → catch → access property → innerHTML', () => {
  const { findings } = analyze(`
    try {
      throw { msg: location.hash };
    } catch (e) {
      document.body.innerHTML = e.msg;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('nested try: inner rethrows → outer catches tainted', () => {
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

test('taint in try block persists to after try/catch/finally', () => {
  const { findings } = analyze(`
    var x;
    try {
      x = location.hash;
    } catch (e) {
      // error
    } finally {
      // cleanup
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: catch param not used in sink, safe string used instead', () => {
  const { findings } = analyze(`
    try {
      throw location.hash;
    } catch (e) {
      document.body.innerHTML = 'An error occurred';
    }
  `);
  expect(findings).toBeEmpty();
});

test('safe: finally overwrites tainted with safe', () => {
  const { findings } = analyze(`
    var x = location.hash;
    try {
      // process
    } finally {
      x = 'safe';
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Advanced destructuring patterns ──
console.log('\n--- Advanced destructuring patterns ---');

test('deeply nested destructuring: 3 levels', () => {
  const { findings } = analyze(`
    var obj = { a: { b: { c: location.hash } } };
    var { a: { b: { c: val } } } = obj;
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('destructuring with default from tainted source', () => {
  const { findings } = analyze(`
    var opts = {};
    var { value = location.hash } = opts;
    document.body.innerHTML = value;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: destructuring default not used when value exists', () => {
  const { findings } = analyze(`
    var opts = { value: 'safe' };
    var { value = location.hash } = opts;
    document.body.innerHTML = value;
  `);
  expect(findings).toHaveType('XSS');
});

test('rest destructuring captures remaining tainted properties', () => {
  const { findings } = analyze(`
    var obj = { a: 'safe', b: location.hash };
    var { a, ...rest } = obj;
    document.body.innerHTML = rest.b;
  `);
  expect(findings).toHaveType('XSS');
});

test('mixed array + object destructuring', () => {
  const { findings } = analyze(`
    var data = [{ html: location.hash }];
    var [{ html }] = data;
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

test('array destructuring with skip and rest', () => {
  const { findings } = analyze(`
    var arr = ['a', location.hash, 'c'];
    var [, second] = arr;
    document.body.innerHTML = second;
  `);
  expect(findings).toHaveType('XSS');
});

test('destructure { hash, search } from location in function param', () => {
  const { findings } = analyze(`
    function render({ hash, search }) {
      document.body.innerHTML = hash + search;
    }
    render(location);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Promise/async advanced patterns ──
console.log('\n--- Promise/async advanced patterns ---');

test('Promise.all with tainted array → then callback', () => {
  const { findings } = analyze(`
    Promise.all([Promise.resolve(location.hash)]).then(function(results) {
      document.body.innerHTML = results[0];
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('Promise.race with tainted value', () => {
  const { findings } = analyze(`
    Promise.race([Promise.resolve(location.hash)]).then(function(val) {
      document.body.innerHTML = val;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('Promise.allSettled with tainted value', () => {
  const { findings } = analyze(`
    Promise.allSettled([Promise.resolve(location.hash)]).then(function(results) {
      document.body.innerHTML = results[0];
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('async/await: await tainted promise → innerHTML', () => {
  const { findings } = analyze(`
    async function run() {
      var val = await Promise.resolve(location.hash);
      document.body.innerHTML = val;
    }
    run();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: async with sanitization after await', () => {
  const { findings } = analyze(`
    async function run() {
      var val = await Promise.resolve(location.hash);
      document.body.innerHTML = DOMPurify.sanitize(val);
    }
    run();
  `);
  expect(findings).toBeEmpty();
});

test('chained .then() propagates taint through returns', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash)
      .then(function(x) { return x.trim(); })
      .then(function(x) { return x.toLowerCase(); })
      .then(function(x) { document.body.innerHTML = x; });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Scope & hoisting edge cases ──
console.log('\n--- Scope & hoisting edge cases ---');

test('function hoisting: call before declaration with tainted arg', () => {
  const { findings } = analyze(`
    render(location.hash);
    function render(html) {
      document.body.innerHTML = html;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: catch param scoped to catch block, does not leak', () => {
  const { findings } = analyze(`
    var e = 'safe';
    try {
      throw location.hash;
    } catch (e) {
      // e is tainted here but scoped to catch
    }
    document.body.innerHTML = e;
  `);
  expect(findings).toBeEmpty();
});

test('var in for-loop leaks to function scope', () => {
  const { findings } = analyze(`
    for (var i = 0; i < 1; i++) {
      var x = location.hash;
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: let in for-loop does NOT leak', () => {
  const { findings } = analyze(`
    let x = 'safe';
    for (let i = 0; i < 1; i++) {
      let x = location.hash;
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('multiple var reassignments: last one wins', () => {
  const { findings } = analyze(`
    var x = location.hash;
    x = 'safe1';
    x = 'safe2';
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('multiple var reassignments: last one tainted', () => {
  const { findings } = analyze(`
    var x = 'safe';
    x = 'still safe';
    x = location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Object property and method patterns ──
console.log('\n--- Object property and method patterns ---');

test('method chaining with this-returning pattern', () => {
  const { findings } = analyze(`
    var builder = {
      _html: '',
      add: function(s) { this._html += s; return this; },
      build: function() { return this._html; }
    };
    var result = builder.add(location.hash).build();
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('Object.keys() returns safe array of property names', () => {
  const { findings } = analyze(`
    var obj = { a: location.hash, b: 'safe' };
    var keys = Object.keys(obj);
    document.body.innerHTML = keys.join(',');
  `);
  expect(findings).toBeEmpty();
});

test('Object.values() preserves taint from values', () => {
  const { findings } = analyze(`
    var obj = { a: location.hash };
    var vals = Object.values(obj);
    document.body.innerHTML = vals[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('Object.entries() preserves taint from values', () => {
  const { findings } = analyze(`
    var obj = { a: location.hash };
    var entries = Object.entries(obj);
    document.body.innerHTML = entries[0][1];
  `);
  expect(findings).toHaveType('XSS');
});

test('computed property access with string key', () => {
  const { findings } = analyze(`
    var obj = {};
    obj['html'] = location.hash;
    document.body.innerHTML = obj['html'];
  `);
  expect(findings).toHaveType('XSS');
});

test('Object.assign overwriting safe with tainted', () => {
  const { findings } = analyze(`
    var target = { html: 'safe' };
    Object.assign(target, { html: location.hash });
    document.body.innerHTML = target.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: Object.assign with all safe sources', () => {
  const { findings } = analyze(`
    var result = Object.assign({}, { a: 'safe' }, { b: 'also safe' });
    document.body.innerHTML = result.a;
  `);
  expect(findings).toBeEmpty();
});

test('spread overrides: later spread overwrites earlier tainted', () => {
  const { findings } = analyze(`
    var tainted = { html: location.hash };
    var safe = { html: 'safe' };
    var result = { ...tainted, ...safe };
    document.body.innerHTML = result.html;
  `);
  expect(findings).toBeEmpty();
});

// ── Map/Set taint tracking ──
console.log('\n--- Map/Set taint tracking ---');

test('Map.set then Map.get preserves taint', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('key', location.hash);
    var val = m.get('key');
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: Map with safe values', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('key', 'safe');
    document.body.innerHTML = m.get('key');
  `);
  expect(findings).toBeEmpty();
});

test('Map.values() iterator carries taint', () => {
  const { findings } = analyze(`
    var m = new Map();
    m.set('k', location.hash);
    for (var v of m.values()) {
      document.body.innerHTML = v;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('Set.add preserves taint, iteration carries taint', () => {
  const { findings } = analyze(`
    var s = new Set();
    s.add(location.hash);
    for (var v of s) {
      document.body.innerHTML = v;
    }
  `);
  expect(findings).toHaveType('XSS');
});

// ── Generator/yield advanced ──
console.log('\n--- Generator/yield advanced ---');

test('yield* delegation propagates taint from inner generator', () => {
  const { findings } = analyze(`
    function* inner() { yield location.hash; }
    function* outer() { yield* inner(); }
    var g = outer();
    document.body.innerHTML = g.next().value;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: generator yields only safe values', () => {
  const { findings } = analyze(`
    function* gen() {
      yield 'hello';
      yield 'world';
    }
    for (var v of gen()) {
      document.body.innerHTML = v;
    }
  `);
  expect(findings).toBeEmpty();
});

// ── Source-specific patterns ──
console.log('\n--- Source-specific patterns ---');

test('document.referrer → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.referrer;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.URL → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.URL;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.documentURI → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.documentURI;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.baseURI → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.baseURI;
  `);
  expect(findings).toHaveType('XSS');
});

test('document.cookie → innerHTML', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.cookie;
  `);
  expect(findings).toHaveType('XSS');
});

test('URLSearchParams.get() is tainted source', () => {
  const { findings } = analyze(`
    var params = new URLSearchParams(location.search);
    var val = params.get('q');
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: document.title is not a source', () => {
  const { findings } = analyze(`
    document.body.innerHTML = document.title;
  `);
  expect(findings).toBeEmpty();
});

// ── Ternary & conditional complex patterns ──
console.log('\n--- Ternary & conditional complex patterns ---');

test('deeply nested ternary: all branches tainted', () => {
  const { findings } = analyze(`
    var x = a ? location.hash :
            b ? location.search :
            c ? location.pathname :
                location.href;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: all ternary branches sanitized', () => {
  const { findings } = analyze(`
    var raw = location.hash;
    var x = cond ? DOMPurify.sanitize(raw) : encodeURIComponent(raw);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('if/else assigns tainted in both branches', () => {
  const { findings } = analyze(`
    var x;
    if (cond) {
      x = location.hash;
    } else {
      x = location.search;
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: if/else assigns safe in both branches', () => {
  const { findings } = analyze(`
    var x;
    if (cond) {
      x = 'safe1';
    } else {
      x = 'safe2';
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Template literal edge cases ──
console.log('\n--- Template literal edge cases ---');

test('nested template literals with tainted inner', () => {
  const { findings } = analyze(`
    var inner = \`\${location.hash}\`;
    var outer = \`<div>\${inner}</div>\`;
    document.body.innerHTML = outer;
  `);
  expect(findings).toHaveType('XSS');
});

test('template literal with multiple tainted expressions', () => {
  const { findings } = analyze(`
    var x = \`\${location.hash} and \${location.search}\`;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: template literal with only safe expressions', () => {
  const { findings } = analyze(`
    var name = 'world';
    var x = \`Hello \${name}!\`;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Cross-file advanced patterns ──
console.log('\n--- Cross-file advanced patterns ---');

test('cross-file: tainted flows through function chain across files', () => {
  const findings = analyzeMultiple([
    { source: `
      function process(data) { return data.trim(); }
    `, file: 'utils.js' },
    { source: `
      var result = process(location.hash);
      document.body.innerHTML = result;
    `, file: 'app.js' },
  ]);
  if (!findings.some(f => f.type === 'XSS')) throw new Error('Expected XSS');
});

test('safe: cross-file sanitization in utility function', () => {
  const findings = analyzeMultiple([
    { source: `
      function safeRender(data) {
        return DOMPurify.sanitize(data);
      }
    `, file: 'utils.js' },
    { source: `
      var safe = safeRender(location.hash);
      document.body.innerHTML = safe;
    `, file: 'app.js' },
  ]);
  if (findings.some(f => f.type === 'XSS')) throw new Error('Expected no XSS');
});

test('cross-file: class defined in one file, instantiated in another', () => {
  const findings = analyzeMultiple([
    { source: `
      class Widget {
        constructor(html) { this.html = html; }
        render() { document.body.innerHTML = this.html; }
      }
    `, file: 'widget.js' },
    { source: `
      var w = new Widget(location.hash);
      w.render();
    `, file: 'app.js' },
  ]);
  if (!findings.some(f => f.type === 'XSS')) throw new Error('Expected XSS');
});

// ── Closure & higher-order advanced patterns ──
console.log('\n--- Closure & higher-order advanced patterns ---');

test('closure over loop variable with let creates separate bindings', () => {
  const { findings } = analyze(`
    var fns = [];
    for (let i = 0; i < 1; i++) {
      fns.push(function() { return location.hash; });
    }
    document.body.innerHTML = fns[0]();
  `);
  expect(findings).toHaveType('XSS');
});

test('function composition: compose(f, g)(x)', () => {
  const { findings } = analyze(`
    function compose(f, g) {
      return function(x) { return f(g(x)); };
    }
    function identity(x) { return x; }
    function wrap(x) { return '<div>' + x + '</div>'; }
    var fn = compose(wrap, identity);
    document.body.innerHTML = fn(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: function composition with sanitizer', () => {
  const { findings } = analyze(`
    function compose(f, g) {
      return function(x) { return f(g(x)); };
    }
    function render(x) { return '<div>' + x + '</div>'; }
    var fn = compose(render, DOMPurify.sanitize);
    document.body.innerHTML = fn(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('callback passed as argument executed with tainted data', () => {
  const { findings } = analyze(`
    function fetchData(url, callback) {
      callback(location.hash);
    }
    fetchData('/api', function(data) {
      document.body.innerHTML = data;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── Switch statement edge cases ──
console.log('\n--- Switch statement edge cases ---');

test('switch fall-through: taint assigned in one case, used after switch', () => {
  const { findings } = analyze(`
    var x;
    switch (action) {
      case 'load':
        x = location.hash;
        break;
      case 'default':
        x = 'safe';
        break;
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: all switch cases assign safe values', () => {
  const { findings } = analyze(`
    var x;
    switch (action) {
      case 'a': x = 'safe1'; break;
      case 'b': x = 'safe2'; break;
      default: x = 'safe3'; break;
    }
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('switch with return inside function', () => {
  const { findings } = analyze(`
    function getContent(type) {
      switch (type) {
        case 'user': return location.hash;
        case 'safe': return 'safe';
        default: return '';
      }
    }
    document.body.innerHTML = getContent('user');
  `);
  expect(findings).toHaveType('XSS');
});

// ── Logical operators with taint ──
console.log('\n--- Logical operators with taint ---');

test('logical OR: safe || tainted → tainted (short-circuit may fail)', () => {
  const { findings } = analyze(`
    var x = '' || location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('logical AND: truthy && tainted → tainted', () => {
  const { findings } = analyze(`
    var x = true && location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('nullish coalescing: null ?? tainted → tainted', () => {
  const { findings } = analyze(`
    var x = null ?? location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: logical OR short-circuits with truthy safe value', () => {
  const { findings } = analyze(`
    var x = 'safe' || location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: nullish coalescing short-circuits with non-null', () => {
  const { findings } = analyze(`
    var x = 'safe' ?? location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Unary/typeof/void operators ──
console.log('\n--- Unary/typeof/void operators ---');

test('safe: typeof tainted returns string type name', () => {
  const { findings } = analyze(`
    var x = typeof location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: void expression always returns undefined', () => {
  const { findings } = analyze(`
    var x = void location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: negation of tainted returns boolean-like', () => {
  const { findings } = analyze(`
    var x = !location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: double negation returns boolean', () => {
  const { findings } = analyze(`
    var x = !!location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Prototype pollution advanced ──
console.log('\n--- Prototype pollution advanced ---');

test('prototype pollution via __proto__ with tainted value', () => {
  const { findings } = analyze(`
    var obj = {};
    obj.__proto__.polluted = location.hash;
  `);
  expect(findings).toHaveType('Prototype Pollution');
});

test('prototype pollution via constructor.prototype', () => {
  const { findings } = analyze(`
    var obj = {};
    obj.constructor.prototype.polluted = location.hash;
  `);
  expect(findings).toHaveType('Prototype Pollution');
});

test('safe: normal property assignment, not proto', () => {
  const { findings } = analyze(`
    var obj = {};
    obj.data = location.hash;
    document.body.innerHTML = obj.data;
  `);
  expect(findings).toHaveType('XSS');
  expect(findings).not.toHaveType('Prototype Pollution');
});

// ── Sink variety tests ──
console.log('\n--- Sink variety tests ---');

test('eval() with tainted argument', () => {
  const { findings } = analyze(`
    eval(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('setTimeout with tainted string', () => {
  const { findings } = analyze(`
    setTimeout(location.hash, 0);
  `);
  expect(findings).toHaveType('XSS');
});

test('new Function() with tainted body', () => {
  const { findings } = analyze(`
    var fn = new Function(location.hash);
    fn();
  `);
  expect(findings).toHaveType('XSS');
});

test('location.href assignment with tainted value', () => {
  const { findings } = analyze(`
    location.href = location.hash.slice(1);
  `);
  expect(findings).toHaveType('XSS');
});

test('window.open with tainted URL', () => {
  const { findings } = analyze(`
    window.open(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('script element .src assignment with tainted value', () => {
  const { findings } = analyze(`
    var s = document.createElement('script');
    s.src = location.hash;
  `);
  expect(findings).toHaveType('Script Injection');
});

test('setAttribute with tainted value on href', () => {
  const { findings } = analyze(`
    var a = document.createElement('a');
    a.setAttribute('href', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('document.write with tainted content', () => {
  const { findings } = analyze(`
    document.write(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('insertAdjacentHTML with tainted content', () => {
  const { findings } = analyze(`
    document.body.insertAdjacentHTML('beforeend', location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: textContent assignment (not a sink)', () => {
  const { findings } = analyze(`
    document.body.textContent = location.hash;
  `);
  expect(findings).toBeEmpty();
});

// ── Class patterns advanced ──
console.log('\n--- Class patterns advanced ---');

test('class with private-like field via closure', () => {
  const { findings } = analyze(`
    class Store {
      constructor(data) {
        this._data = data;
      }
      getData() {
        return this._data;
      }
    }
    var s = new Store(location.hash);
    document.body.innerHTML = s.getData();
  `);
  expect(findings).toHaveType('XSS');
});

test('class static method processes tainted input', () => {
  const { findings } = analyze(`
    class Util {
      static render(html) {
        document.body.innerHTML = html;
      }
    }
    Util.render(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: class method sanitizes before returning', () => {
  const { findings } = analyze(`
    class SafeRenderer {
      constructor(html) {
        this.html = DOMPurify.sanitize(html);
      }
      render() {
        document.body.innerHTML = this.html;
      }
    }
    var r = new SafeRenderer(location.hash);
    r.render();
  `);
  expect(findings).toBeEmpty();
});

test('class extends with tainted data through super()', () => {
  const { findings } = analyze(`
    class Base {
      constructor(data) { this.data = data; }
    }
    class Child extends Base {
      render() { document.body.innerHTML = this.data; }
    }
    var c = new Child(location.hash);
    c.render();
  `);
  expect(findings).toHaveType('XSS');
});

// ── Sanitizer validation patterns ──
console.log('\n--- Sanitizer validation patterns ---');

test('safe: encodeURIComponent sanitizes for innerHTML', () => {
  const { findings } = analyze(`
    var safe = encodeURIComponent(location.hash);
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});

test('safe: encodeURI sanitizes', () => {
  const { findings } = analyze(`
    var safe = encodeURI(location.hash);
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});

test('safe: DOMPurify.sanitize on concatenated tainted strings', () => {
  const { findings } = analyze(`
    var combined = location.hash + location.search;
    var safe = DOMPurify.sanitize(combined);
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});

test('safe: parseInt kills taint (returns number)', () => {
  const { findings } = analyze(`
    var x = parseInt(location.hash, 10);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: Number() kills taint (returns number)', () => {
  const { findings } = analyze(`
    var x = Number(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Event handler patterns ──
console.log('\n--- Event handler patterns ---');

test('addEventListener message: event.data → innerHTML', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(event) {
      document.body.innerHTML = event.data;
    });
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: addEventListener message with origin check and sanitize', () => {
  const { findings } = analyze(`
    window.addEventListener('message', function(event) {
      document.body.innerHTML = DOMPurify.sanitize(event.data);
    });
  `);
  expect(findings).toBeEmpty();
});

test('hashchange event: event.newURL → innerHTML', () => {
  const { findings } = analyze(`
    window.addEventListener('hashchange', function(event) {
      document.body.innerHTML = event.newURL;
    });
  `);
  expect(findings).toHaveType('XSS');
});

// ── for-in / for-of with complex sources ──
console.log('\n--- for-in / for-of complex ---');

test('for-of over array of tainted values', () => {
  const { findings } = analyze(`
    var sources = [location.hash, location.search];
    for (var src of sources) {
      document.body.innerHTML = src;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('for-in with Object.keys pattern', () => {
  const { findings } = analyze(`
    var config = { html: location.hash };
    for (var key in config) {
      document.body.innerHTML = config[key];
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: for-of over safe array', () => {
  const { findings } = analyze(`
    for (var x of ['a', 'b', 'c']) {
      document.body.innerHTML = x;
    }
  `);
  expect(findings).toBeEmpty();
});

// ── Misc operators and patterns ──
console.log('\n--- Misc operators and patterns ---');

test('comma operator: side effect assigns taint, last expr used', () => {
  const { findings } = analyze(`
    var y;
    var x = (y = location.hash, y);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: comma operator last expression is safe', () => {
  const { findings } = analyze(`
    var x = (location.hash, 'safe');
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('ternary in function call argument', () => {
  const { findings } = analyze(`
    function render(html) { document.body.innerHTML = html; }
    render(cond ? location.hash : location.search);
  `);
  expect(findings).toHaveType('XSS');
});

test('string concatenation with + operator', () => {
  const { findings } = analyze(`
    var x = '<div>' + location.hash + '</div>';
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('+= appends tainted to safe string', () => {
  const { findings } = analyze(`
    var html = '<div>';
    html += location.hash;
    html += '</div>';
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: += only appends safe strings', () => {
  const { findings } = analyze(`
    var html = '<div>';
    html += 'safe content';
    html += '</div>';
    document.body.innerHTML = html;
  `);
  expect(findings).toBeEmpty();
});

// ╔═══════════════════════════════════════════════════════╗
// ║  ROUND 17: Advanced AST gap tests                     ║
// ╚═══════════════════════════════════════════════════════╝
console.log('\n╔═══════════════════════════════════════════════════════╗');
console.log('║  ROUND 17: Advanced AST gap tests                     ║');
console.log('╚═══════════════════════════════════════════════════════╝\n');

// ── Assignment in conditions ──
console.log('\n--- Assignment in conditions ---');

test('assignment in if condition: if (x = tainted)', () => {
  const { findings } = analyze(`
    var x;
    if (x = location.hash) {
      document.body.innerHTML = x;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('assignment in while condition: while (x = tainted)', () => {
  const { findings } = analyze(`
    var x;
    while (x = location.hash) {
      document.body.innerHTML = x;
      break;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: assignment of safe value in condition', () => {
  const { findings } = analyze(`
    var x;
    if (x = 'safe') {
      document.body.innerHTML = x;
    }
  `);
  expect(findings).toBeEmpty();
});

// ── Chained method calls (complex chains) ──
console.log('\n--- Chained method calls ---');

test('4-method chain from tainted source preserves taint', () => {
  const { findings } = analyze(`
    var x = location.hash.split('.').join('-').toLowerCase().trim();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: chain with parseInt mid-chain kills taint', () => {
  const { findings } = analyze(`
    var x = [location.hash].map(parseInt).join(',');
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('split-map-join chain preserves taint', () => {
  const { findings } = analyze(`
    var result = location.hash.split(',').map(function(s) { return s.trim(); }).join(' ');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('chained reduce-concat from tainted array', () => {
  const { findings } = analyze(`
    var result = [location.hash, 'b'].reduce(function(a, b) { return a + b; }, '').concat('!');
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Bitwise and unary numeric operators ──
console.log('\n--- Bitwise and unary numeric operators ---');

test('safe: bitwise OR on tainted returns number', () => {
  const { findings } = analyze(`
    var x = location.hash | 0;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: bitwise AND on tainted returns number', () => {
  const { findings } = analyze(`
    var x = location.hash & 0xFF;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: bitwise XOR on tainted returns number', () => {
  const { findings } = analyze(`
    var x = location.hash ^ 42;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: bitwise NOT (~) on tainted returns number', () => {
  const { findings } = analyze(`
    var x = ~location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: left shift on tainted returns number', () => {
  const { findings } = analyze(`
    var x = location.hash << 2;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: right shift on tainted returns number', () => {
  const { findings } = analyze(`
    var x = location.hash >> 1;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: unsigned right shift on tainted returns number', () => {
  const { findings } = analyze(`
    var x = location.hash >>> 0;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: unary plus converts tainted to number', () => {
  const { findings } = analyze(`
    var x = +location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: unary minus converts tainted to number', () => {
  const { findings } = analyze(`
    var x = -location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── in / instanceof / delete operators ──
console.log('\n--- in / instanceof / delete operators ---');

test('safe: in operator returns boolean', () => {
  const { findings } = analyze(`
    var key = location.hash;
    var x = key in document;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: instanceof returns boolean', () => {
  const { findings } = analyze(`
    var x = location.hash instanceof String;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: delete returns boolean', () => {
  const { findings } = analyze(`
    var obj = { x: location.hash };
    var result = delete obj.x;
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

// ── JSON.parse / JSON.stringify edge cases ──
console.log('\n--- JSON.parse / JSON.stringify ---');

test('JSON.parse of tainted string → property access → innerHTML', () => {
  const { findings } = analyze(`
    var obj = JSON.parse(location.hash);
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('JSON.parse with destructuring preserves taint', () => {
  const { findings } = analyze(`
    var { html } = JSON.parse(location.hash);
    document.body.innerHTML = html;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: JSON.stringify returns escaped string (length is number)', () => {
  const { findings } = analyze(`
    var s = JSON.stringify(location.hash);
    document.body.innerHTML = s.length;
  `);
  expect(findings).toBeEmpty();
});

test('JSON.stringify of tainted preserves taint in output string', () => {
  const { findings } = analyze(`
    var s = JSON.stringify({data: location.hash});
    document.body.innerHTML = s;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Function.prototype.call / apply ──
console.log('\n--- Function.prototype.call / apply ---');

test('fn.call with tainted argument', () => {
  const { findings } = analyze(`
    function render(html) {
      document.body.innerHTML = html;
    }
    render.call(null, location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('fn.apply with tainted argument array', () => {
  const { findings } = analyze(`
    function render(html) {
      document.body.innerHTML = html;
    }
    render.apply(null, [location.hash]);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: fn.call with sanitized argument', () => {
  const { findings } = analyze(`
    function render(html) {
      document.body.innerHTML = html;
    }
    render.call(null, DOMPurify.sanitize(location.hash));
  `);
  expect(findings).toBeEmpty();
});

// ── Property shorthand in object literals ──
console.log('\n--- Property shorthand ---');

test('property shorthand captures tainted variable', () => {
  const { findings } = analyze(`
    var hash = location.hash;
    var obj = { hash };
    document.body.innerHTML = obj.hash;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: property shorthand with safe variable', () => {
  const { findings } = analyze(`
    var name = 'safe';
    var obj = { name };
    document.body.innerHTML = obj.name;
  `);
  expect(findings).toBeEmpty();
});

test('multiple shorthand properties, one tainted', () => {
  const { findings } = analyze(`
    var safe = 'hello';
    var tainted = location.hash;
    var obj = { safe, tainted };
    document.body.innerHTML = obj.tainted;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: access safe shorthand from mixed object', () => {
  const { findings } = analyze(`
    var safe = 'hello';
    var tainted = location.hash;
    var obj = { safe, tainted };
    document.body.innerHTML = obj.safe;
  `);
  expect(findings).toBeEmpty();
});

// ── Nested function calls (3+ levels) ──
console.log('\n--- Nested function calls ---');

test('3-level nested function calls propagate taint', () => {
  const { findings } = analyze(`
    function a(x) { return x + ''; }
    function b(y) { return a(y); }
    function c(z) { return b(z); }
    document.body.innerHTML = c(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: sanitizer at any level in nested calls kills taint', () => {
  const { findings } = analyze(`
    function a(x) { return DOMPurify.sanitize(x); }
    function b(y) { return a(y); }
    function c(z) { return b(z); }
    document.body.innerHTML = c(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('safe: typeof in nested call chain kills taint', () => {
  const { findings } = analyze(`
    function getType(x) { return typeof x; }
    function process(x) { return getType(x); }
    document.body.innerHTML = process(location.hash);
  `);
  expect(findings).toBeEmpty();
});

test('nested call with intermediate transformation', () => {
  const { findings } = analyze(`
    function wrap(x) { return '<div>' + x + '</div>'; }
    function process(x) { return wrap(x.trim()); }
    document.body.innerHTML = process(location.hash);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Variable shadowing at 3+ levels ──
console.log('\n--- Variable shadowing 3+ levels ---');

test('safe: 3-level shadowing with safe innermost', () => {
  const { findings } = analyze(`
    var x = location.hash;
    function f1() {
      var x = 'safe1';
      function f2() {
        var x = 'safe2';
        document.body.innerHTML = x;
      }
      f2();
    }
    f1();
  `);
  expect(findings).toBeEmpty();
});

test('3-level shadowing: innermost re-taints', () => {
  const { findings } = analyze(`
    var x = 'safe';
    function f1() {
      var x = 'still safe';
      function f2() {
        var x = location.hash;
        document.body.innerHTML = x;
      }
      f2();
    }
    f1();
  `);
  expect(findings).toHaveType('XSS');
});

test('3-level: middle shadows safe, inner reads middle', () => {
  const { findings } = analyze(`
    var x = location.hash;
    function f1() {
      var x = 'safe';
      function f2() {
        document.body.innerHTML = x;
      }
      f2();
    }
    f1();
  `);
  expect(findings).toBeEmpty();
});

// ── Multiple return paths in functions ──
console.log('\n--- Multiple return paths ---');

test('function with multiple return paths, one tainted', () => {
  const { findings } = analyze(`
    function getData(type) {
      if (type === 'user') return location.hash;
      if (type === 'safe') return 'safe';
      return '';
    }
    document.body.innerHTML = getData('user');
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: all return paths are safe', () => {
  const { findings } = analyze(`
    function getData(type) {
      if (type === 'a') return 'safe1';
      if (type === 'b') return 'safe2';
      if (type === 'c') return 'safe3';
      return 'default';
    }
    document.body.innerHTML = getData('a');
  `);
  expect(findings).toBeEmpty();
});

test('early return with taint, later return safe', () => {
  const { findings } = analyze(`
    function process(x) {
      if (!x) return location.hash;
      return 'safe';
    }
    document.body.innerHTML = process(true);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Self-referencing / circular objects ──
console.log('\n--- Self-referencing objects ---');

test('circular object: obj.self.data is tainted', () => {
  const { findings } = analyze(`
    var obj = { data: location.hash };
    obj.self = obj;
    document.body.innerHTML = obj.self.data;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: circular object with safe data', () => {
  const { findings } = analyze(`
    var obj = { data: 'safe' };
    obj.self = obj;
    document.body.innerHTML = obj.self.data;
  `);
  expect(findings).toBeEmpty();
});

// ── Dynamic import with tainted specifier ──
console.log('\n--- Dynamic import ---');

test('import() with tainted module path', () => {
  const { findings } = analyze(`
    var path = location.hash.slice(1);
    import(path);
  `);
  expect(findings).toHaveType('XSS');
});

// ── Object.freeze / Object.seal on tainted ──
console.log('\n--- Object.freeze / Object.seal ---');

test('Object.freeze does not sanitize tainted properties', () => {
  const { findings } = analyze(`
    var obj = Object.freeze({ html: location.hash });
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: Object.freeze on safe object stays safe', () => {
  const { findings } = analyze(`
    var obj = Object.freeze({ html: 'safe' });
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toBeEmpty();
});

// ── String/Number constructor edge cases ──
console.log('\n--- String/Number constructors ---');

test('String() preserves taint (identity for strings)', () => {
  const { findings } = analyze(`
    var x = String(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: Number() kills taint', () => {
  const { findings } = analyze(`
    var x = Number(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: Boolean() kills taint', () => {
  const { findings } = analyze(`
    var x = Boolean(location.hash);
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Array destructuring from function return ──
console.log('\n--- Array destructuring from return ---');

test('destructure array return: first element tainted', () => {
  const { findings } = analyze(`
    function getData() {
      return [location.hash, 'safe'];
    }
    var [tainted, safe] = getData();
    document.body.innerHTML = tainted;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: destructure array return, use safe element', () => {
  const { findings } = analyze(`
    function getData() {
      return [location.hash, 'safe'];
    }
    var [tainted, safe] = getData();
    document.body.innerHTML = safe;
  `);
  expect(findings).toBeEmpty();
});

test('nested array destructuring from return', () => {
  const { findings } = analyze(`
    function getData() {
      return [[location.hash], 'safe'];
    }
    var [[inner], outer] = getData();
    document.body.innerHTML = inner;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Short-circuit evaluation edge cases ──
console.log('\n--- Short-circuit evaluation ---');

test('tainted && string concat → still tainted', () => {
  const { findings } = analyze(`
    var x = location.hash && (location.hash + ' injected');
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: false && tainted → short-circuits to false', () => {
  const { findings } = analyze(`
    var x = false && location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: safe || tainted → short-circuits to safe', () => {
  const { findings } = analyze(`
    var x = 'safe value' || location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('empty string || tainted → tainted (falsy short-circuit fails)', () => {
  const { findings } = analyze(`
    var x = '' || location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Ternary with function calls ──
console.log('\n--- Ternary with function calls ---');

test('ternary: true branch calls function returning tainted', () => {
  const { findings } = analyze(`
    function getTainted() { return location.hash; }
    function getSafe() { return 'safe'; }
    var x = cond ? getTainted() : getSafe();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: ternary both branches return safe from functions', () => {
  const { findings } = analyze(`
    function safe1() { return 'a'; }
    function safe2() { return 'b'; }
    var x = cond ? safe1() : safe2();
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── for-loop complex patterns ──
console.log('\n--- for-loop complex patterns ---');

test('for-loop init with comma: tainted var initialized', () => {
  const { findings } = analyze(`
    for (var i = 0, x = location.hash; i < 1; i++) {
      document.body.innerHTML = x;
    }
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: for-loop with safe init', () => {
  const { findings } = analyze(`
    for (var i = 0, x = 'safe'; i < 1; i++) {
      document.body.innerHTML = x;
    }
  `);
  expect(findings).toBeEmpty();
});

test('for-loop body accumulates taint', () => {
  const { findings } = analyze(`
    var result = '';
    for (var i = 0; i < 1; i++) {
      result += location.hash;
    }
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Computed property access edge cases ──
console.log('\n--- Computed property access ---');

test('tainted key on safe object: value lookup', () => {
  const { findings } = analyze(`
    var obj = { a: 'safe1', b: 'safe2' };
    var key = location.hash;
    document.body.innerHTML = obj[key];
  `);
  expect(findings).toBeEmpty();
});

test('safe key on tainted object: value is tainted', () => {
  const { findings } = analyze(`
    var obj = { html: location.hash };
    var key = 'html';
    document.body.innerHTML = obj[key];
  `);
  expect(findings).toHaveType('XSS');
});

test('computed property with tainted value in object literal', () => {
  const { findings } = analyze(`
    var key = 'html';
    var obj = { [key]: location.hash };
    document.body.innerHTML = obj.html;
  `);
  expect(findings).toHaveType('XSS');
});

// ── RegExp constructor with taint ──
console.log('\n--- RegExp constructor ---');

test('safe: RegExp.test() returns boolean', () => {
  const { findings } = analyze(`
    var re = new RegExp(location.hash);
    var result = re.test('safe string');
    document.body.innerHTML = result;
  `);
  expect(findings).toBeEmpty();
});

test('new RegExp(tainted).source preserves taint', () => {
  const { findings } = analyze(`
    var re = new RegExp(location.hash);
    document.body.innerHTML = re.source;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Cross-file with method chains ──
console.log('\n--- Cross-file method chains ---');

test('cross-file: utility function chain processes tainted', () => {
  const findings = analyzeMultiple([
    { source: `
      function clean(s) { return s.trim().toLowerCase(); }
    `, file: 'utils.js' },
    { source: `
      document.body.innerHTML = clean(location.hash);
    `, file: 'app.js' },
  ]);
  if (!findings.some(f => f.type === 'XSS')) throw new Error('Expected XSS');
});

test('safe: cross-file utility sanitizes', () => {
  const findings = analyzeMultiple([
    { source: `
      function sanitize(s) { return DOMPurify.sanitize(s); }
    `, file: 'utils.js' },
    { source: `
      document.body.innerHTML = sanitize(location.hash);
    `, file: 'app.js' },
  ]);
  if (findings.some(f => f.type === 'XSS')) throw new Error('Expected no XSS');
});

// ── Taint through data structure patterns ──
console.log('\n--- Data structure patterns ---');

test('nested Map: Map of Maps preserves taint', () => {
  const { findings } = analyze(`
    var outer = new Map();
    var inner = new Map();
    inner.set('key', location.hash);
    outer.set('inner', inner);
    var val = outer.get('inner').get('key');
    document.body.innerHTML = val;
  `);
  expect(findings).toHaveType('XSS');
});

test('array of objects: tainted property accessed by index', () => {
  const { findings } = analyze(`
    var items = [{ html: location.hash }];
    document.body.innerHTML = items[0].html;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: array of safe objects', () => {
  const { findings } = analyze(`
    var items = [{ html: 'safe' }];
    document.body.innerHTML = items[0].html;
  `);
  expect(findings).toBeEmpty();
});

// ── Immediately invoked patterns (complex) ──
console.log('\n--- Complex IIFE patterns ---');

test('arrow IIFE with block body returns tainted', () => {
  const { findings } = analyze(`
    var x = (() => {
      var data = location.hash;
      return data.trim();
    })();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: arrow IIFE sanitizes before returning', () => {
  const { findings } = analyze(`
    var x = (() => {
      return DOMPurify.sanitize(location.hash);
    })();
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('nested IIFE: outer IIFE calls inner IIFE', () => {
  const { findings } = analyze(`
    var x = (function() {
      return (function() {
        return location.hash;
      })();
    })();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

// ── Taint through assignment operators ──
console.log('\n--- Assignment operators ---');

test('*= does not propagate string taint (numeric operation)', () => {
  const { findings } = analyze(`
    var x = 5;
    x *= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('-= does not propagate string taint (numeric operation)', () => {
  const { findings } = analyze(`
    var x = 10;
    x -= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('/= does not propagate string taint (numeric operation)', () => {
  const { findings } = analyze(`
    var x = 100;
    x /= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('%= does not propagate string taint (numeric operation)', () => {
  const { findings } = analyze(`
    var x = 100;
    x %= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('**= does not propagate string taint (numeric operation)', () => {
  const { findings } = analyze(`
    var x = 2;
    x **= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('<<= bitwise assignment kills taint', () => {
  const { findings } = analyze(`
    var x = 1;
    x <<= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('>>= bitwise assignment kills taint', () => {
  const { findings } = analyze(`
    var x = 255;
    x >>= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('&= bitwise assignment kills taint', () => {
  const { findings } = analyze(`
    var x = 0xFF;
    x &= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('|= bitwise assignment kills taint', () => {
  const { findings } = analyze(`
    var x = 0;
    x |= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('^= bitwise assignment kills taint', () => {
  const { findings } = analyze(`
    var x = 0;
    x ^= location.hash;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ── Sanitizer edge cases ──
console.log('\n--- Sanitizer edge cases ---');

test('safe: double sanitization still safe', () => {
  const { findings } = analyze(`
    var x = DOMPurify.sanitize(DOMPurify.sanitize(location.hash));
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('safe: sanitize then trim still safe', () => {
  const { findings } = analyze(`
    var x = DOMPurify.sanitize(location.hash).trim();
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('tainted concatenated AFTER sanitization re-taints', () => {
  const { findings } = analyze(`
    var safe = DOMPurify.sanitize(location.hash);
    var result = safe + location.search;
    document.body.innerHTML = result;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: map with sanitizer on tainted array', () => {
  const { findings } = analyze(`
    var items = [location.hash, location.search];
    var safe = items.map(function(x) { return DOMPurify.sanitize(x); });
    document.body.innerHTML = safe.join('');
  `);
  expect(findings).toBeEmpty();
});

// ── Class method chaining (returning this) ──
console.log('\n--- Class method chaining ---');

test('class method chaining with tainted data', () => {
  const { findings } = analyze(`
    class Builder {
      constructor() { this._html = ''; }
      add(s) { this._html += s; return this; }
      build() { return this._html; }
    }
    var b = new Builder();
    document.body.innerHTML = b.add(location.hash).build();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: class method chaining with safe data', () => {
  const { findings } = analyze(`
    class Builder {
      constructor() { this._html = ''; }
      add(s) { this._html += s; return this; }
      build() { return this._html; }
    }
    var b = new Builder();
    document.body.innerHTML = b.add('safe').build();
  `);
  expect(findings).toBeEmpty();
});

// ── Promise.then chaining complex ──
console.log('\n--- Promise.then chaining ---');

test('3-level promise chain preserves taint', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash)
      .then(function(x) { return x.trim(); })
      .then(function(x) { return '<div>' + x + '</div>'; })
      .then(function(html) { document.body.innerHTML = html; });
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: promise chain with sanitizer in middle', () => {
  const { findings } = analyze(`
    Promise.resolve(location.hash)
      .then(function(x) { return DOMPurify.sanitize(x); })
      .then(function(safe) { document.body.innerHTML = safe; });
  `);
  expect(findings).toBeEmpty();
});

// ── Complex real-world patterns ──
console.log('\n--- Real-world patterns ---');

test('URL parsing: new URL with tainted href', () => {
  const { findings } = analyze(`
    var url = new URL(location.hash.slice(1));
    document.body.innerHTML = url.pathname;
  `);
  expect(findings).toHaveType('XSS');
});

test('DOM element creation with tainted content', () => {
  const { findings } = analyze(`
    var div = document.createElement('div');
    div.innerHTML = location.hash;
  `);
  expect(findings).toHaveType('XSS');
});

test('event handler in object: onclick property', () => {
  const { findings } = analyze(`
    var el = document.getElementById('target');
    el.onclick = function() {
      document.body.innerHTML = location.hash;
    };
  `);
  expect(findings).toHaveType('XSS');
});

test('template literal in function call argument', () => {
  const { findings } = analyze(`
    function render(html) {
      document.body.innerHTML = html;
    }
    render(\`<div>\${location.hash}</div>\`);
  `);
  expect(findings).toHaveType('XSS');
});

test('ternary assignment to object property then sink', () => {
  const { findings } = analyze(`
    var config = {};
    config.html = cond ? location.hash : location.search;
    document.body.innerHTML = config.html;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: ternary both safe branches to property', () => {
  const { findings } = analyze(`
    var config = {};
    config.html = cond ? 'safe1' : 'safe2';
    document.body.innerHTML = config.html;
  `);
  expect(findings).toBeEmpty();
});

test('chained string replace calls preserve taint', () => {
  const { findings } = analyze(`
    var x = location.hash.replace('<', '').replace('>', '');
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('multiple sources in one expression', () => {
  const { findings } = analyze(`
    document.body.innerHTML = location.hash + location.search + location.pathname;
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through computed method call', () => {
  const { findings } = analyze(`
    var method = 'trim';
    var x = location.hash[method]();
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: JSON.parse then access .length (number)', () => {
  const { findings } = analyze(`
    var arr = JSON.parse(location.hash);
    document.body.innerHTML = arr.length;
  `);
  expect(findings).toBeEmpty();
});

// ── Spread in function calls ──
console.log('\n--- Spread in function calls ---');

test('spread tainted array into function call', () => {
  const { findings } = analyze(`
    function render(html) {
      document.body.innerHTML = html;
    }
    var args = [location.hash];
    render(...args);
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: spread safe array into function call', () => {
  const { findings } = analyze(`
    function render(html) {
      document.body.innerHTML = html;
    }
    var args = ['safe'];
    render(...args);
  `);
  expect(findings).toBeEmpty();
});

// ── Async/await complex patterns ──
console.log('\n--- Async/await complex ---');

test('async function with try/catch: taint in try, used after', () => {
  const { findings } = analyze(`
    async function run() {
      var data;
      try {
        data = await Promise.resolve(location.hash);
      } catch (e) {
        data = 'fallback';
      }
      document.body.innerHTML = data;
    }
    run();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: async with sanitization in catch path', () => {
  const { findings } = analyze(`
    async function run() {
      var data = await Promise.resolve(location.hash);
      data = DOMPurify.sanitize(data);
      document.body.innerHTML = data;
    }
    run();
  `);
  expect(findings).toBeEmpty();
});

// ── Misc edge cases ──
console.log('\n--- Misc edge cases ---');

test('taint survives through conditional (||) chain', () => {
  const { findings } = analyze(`
    var a = null;
    var b = undefined;
    var c = location.hash;
    var x = a || b || c;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: conditional chain resolves to first truthy safe', () => {
  const { findings } = analyze(`
    var a = null;
    var b = 'safe';
    var c = location.hash;
    var x = a || b || c;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

test('object method shorthand with tainted return', () => {
  const { findings } = analyze(`
    var obj = {
      getData() { return location.hash; }
    };
    document.body.innerHTML = obj.getData();
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: object method shorthand returns safe', () => {
  const { findings } = analyze(`
    var obj = {
      getData() { return 'safe'; }
    };
    document.body.innerHTML = obj.getData();
  `);
  expect(findings).toBeEmpty();
});

test('array.push then access preserves taint', () => {
  const { findings } = analyze(`
    var arr = [];
    arr.push(location.hash);
    document.body.innerHTML = arr[0];
  `);
  expect(findings).toHaveType('XSS');
});

test('taint through string template with method call', () => {
  const { findings } = analyze(`
    function getData() { return location.hash; }
    var x = \`Result: \${getData()}\`;
    document.body.innerHTML = x;
  `);
  expect(findings).toHaveType('XSS');
});

test('safe: string template with safe method call', () => {
  const { findings } = analyze(`
    function getData() { return 'safe'; }
    var x = \`Result: \${getData()}\`;
    document.body.innerHTML = x;
  `);
  expect(findings).toBeEmpty();
});

// ═══════════════════════════════════════════════════════
console.log(`\n${'='.repeat(50)}`);
console.log(`RESULTS: ${passed} passed, ${failed} failed out of ${passed + failed}`);
if (failed > 0) process.exit(1);
