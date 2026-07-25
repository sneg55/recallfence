// RecallFence replay dashboard: DOM helpers.
//
// Pure, and deliberately knows nothing about the bundle's shape. Loaded before
// panels.js and app.js as a plain script rather than an ES module, so the page
// also opens straight off the filesystem without a server.

'use strict';

const PHASES = ['baseline', 'post_rls', 'post_quarantine'];

// Text only, never innerHTML with bundle data.
//
// Not a style choice. The bundle carries corpus content and tenant-authored
// strings, and this is a project about data crossing a boundary it should not.
// Rendering that content as markup would be a real hole in exactly the place a
// reviewer will look first.
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

function chip(label, value, cls) {
  const c = el('span', 'chip' + (cls ? ' ' + cls : ''));
  if (label) c.appendChild(el('b', null, label));
  c.appendChild(document.createTextNode((label ? ' ' : '') + value));
  return c;
}

function short(s, n) {
  return typeof s === 'string' ? s.slice(0, n || 8) : '';
}

// A table from a header list and an array of cell-arrays, wrapped in a scroller
// so a wide matrix never makes the page itself scroll sideways.
function table(headers, rows) {
  const wrap = el('div', 'scroll');
  const t = el('table');
  const thead = el('thead');
  const hr = el('tr');
  for (const h of headers) hr.appendChild(el('th', null, h));
  thead.appendChild(hr);
  t.appendChild(thead);
  const tb = el('tbody');
  for (const cells of rows) {
    const tr = el('tr');
    for (const c of cells) {
      tr.appendChild(c instanceof Node ? wrapCell(c) : el('td', 'mono', c));
    }
    tb.appendChild(tr);
  }
  t.appendChild(tb);
  wrap.appendChild(t);
  return wrap;
}

function wrapCell(node) {
  if (node.tagName === 'TD') return node;
  const td = el('td');
  td.appendChild(node);
  return td;
}

// Definition list used for every key/value block on the page.
function kv(pairs) {
  const dl = el('dl', 'kv');
  for (const [k, v] of pairs) {
    dl.appendChild(el('dt', null, k));
    dl.appendChild(el('dd', null, v));
  }
  return dl;
}

function callout(title, paragraphs) {
  const n = el('div', 'callout');
  if (title) n.appendChild(el('strong', null, title));
  for (const p of paragraphs) n.appendChild(el('p', null, p));
  return n;
}
