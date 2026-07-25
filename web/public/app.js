// RecallFence replay dashboard: bootstrap.
//
// Renders entirely from ./replay.json, the bundle `cli/rf snapshot` writes. No
// database, no API, no build step. That is the point: the demo URL has to keep
// working after the cluster is paused, reclaimed or torn down, so the database is
// an enhancement and never a dependency.

'use strict';

function wireTabs() {
  const tabs = document.getElementById('tabs');
  tabs.addEventListener('click', ev => {
    const btn = ev.target.closest('button[data-panel]');
    if (!btn) return;
    for (const b of tabs.querySelectorAll('button')) {
      b.classList.toggle('active', b === btn);
    }
    for (const p of document.querySelectorAll('.panel')) {
      p.hidden = p.id !== 'panel-' + btn.dataset.panel;
    }
  });
}

// A failed fetch says so in the verdict slot rather than leaving a page that
// looks like it rendered successfully and happens to be empty. Fail visibly.
function failed(message) {
  const badge = document.getElementById('verdict-badge');
  badge.textContent = 'unavailable';
  badge.className = 'badge badge-idle';
  document.getElementById('verdict-meta').textContent = message;
}

async function main() {
  wireTabs();

  let bundle;
  try {
    const res = await fetch('./replay.json', { cache: 'no-cache' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    bundle = await res.json();
  } catch (err) {
    failed('could not load replay.json: ' + err.message);
    return;
  }

  if (!bundle || !bundle.receipt || !bundle.receipt_meta) {
    failed('replay.json carries no receipt');
    return;
  }

  renderVerdict(bundle);
  renderMatrix(bundle);
  renderEvidence(bundle);
  renderPolicy(bundle);
  renderQuarantine(bundle);
  renderReceipt(bundle);
}

main();
