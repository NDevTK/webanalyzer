/* sink-discovery.js — Runtime DOM sink discovery via Trusted Types API.
   Probes the browser runtime to discover which element properties are
   injection sinks, using trustedTypes.getPropertyType() as the oracle.

   This replaces hardcoded sink lists — the browser IS the spec. */

// Discover all writable properties on an element by walking its prototype chain
function discoverWritableProperties(el) {
  const props = new Set();
  let proto = el;
  while (proto && proto !== Object.prototype) {
    for (const [name, desc] of Object.entries(Object.getOwnPropertyDescriptors(proto))) {
      if (desc.set && typeof name === 'string' && !name.startsWith('_')) {
        props.add(name);
      }
    }
    proto = Object.getPrototypeOf(proto);
  }
  return props;
}

// Discover all HTML element tags by checking window for HTML*Element constructors
function discoverTags() {
  const tags = new Map(); // tag → interfaceName
  // Standard tags
  const STANDARD = [
    'a', 'abbr', 'address', 'area', 'article', 'aside', 'audio', 'b', 'base',
    'bdi', 'bdo', 'blockquote', 'body', 'br', 'button', 'canvas', 'caption',
    'cite', 'code', 'col', 'colgroup', 'data', 'datalist', 'dd', 'del',
    'details', 'dfn', 'dialog', 'div', 'dl', 'dt', 'em', 'embed', 'fieldset',
    'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'head', 'header', 'hgroup', 'hr', 'html', 'i', 'iframe', 'img', 'input',
    'ins', 'kbd', 'label', 'legend', 'li', 'link', 'main', 'map', 'mark',
    'menu', 'meta', 'meter', 'nav', 'noscript', 'object', 'ol', 'optgroup',
    'option', 'output', 'p', 'picture', 'pre', 'progress', 'q', 'rp', 'rt',
    'ruby', 's', 'samp', 'script', 'search', 'section', 'select', 'slot',
    'small', 'source', 'span', 'strong', 'style', 'sub', 'summary', 'sup',
    'table', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead',
    'time', 'title', 'tr', 'track', 'u', 'ul', 'var', 'video', 'wbr',
    'frame', 'frameset', 'marquee', 'font',
  ];
  for (const tag of STANDARD) {
    try {
      const el = document.createElement(tag);
      tags.set(tag, el.constructor.name);
    } catch {}
  }
  return tags;
}

// Build the complete sink map by probing trustedTypes.getPropertyType
// Returns Map<"tag:prop", sinkType> where sinkType is "TrustedHTML"|"TrustedScript"|"TrustedScriptURL"
export function discoverSinks() {
  const sinks = new Map();

  if (typeof trustedTypes === 'undefined' || !trustedTypes.getPropertyType) {
    return sinks; // Not in a browser with Trusted Types support
  }

  const tags = discoverTags();

  for (const [tag] of tags) {
    let el;
    try { el = document.createElement(tag); } catch { continue; }

    const props = discoverWritableProperties(el);
    for (const prop of props) {
      try {
        const sinkType = trustedTypes.getPropertyType(tag, prop);
        if (sinkType) {
          sinks.set(`${tag}:${prop}`, sinkType);
        }
      } catch {}
    }
  }

  return sinks;
}

// Serialize the sink map to JSON for caching
export function serializeSinks(sinks) {
  const obj = {};
  for (const [key, type] of sinks) {
    obj[key] = type;
  }
  return JSON.stringify(obj);
}

// Deserialize cached sink data
export function deserializeSinks(json) {
  const sinks = new Map();
  const obj = JSON.parse(json);
  for (const [key, type] of Object.entries(obj)) {
    sinks.set(key, type);
  }
  return sinks;
}
