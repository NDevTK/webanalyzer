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
