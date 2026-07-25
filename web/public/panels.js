// RecallFence replay dashboard: one function per panel.
//
// Each takes the bundle and writes into its own container. Pure over the bundle,
// exactly like cli/lib/render.sh, so the dashboard and the CLI cannot drift into
// telling different stories about the same run.

'use strict';

const CLAUSE_TEXT = {
  c1_baseline_demonstrated_failure:
    'At least one breach at baseline. Without it a pass is a rubber stamp: a harness ' +
    'that errored silently and recorded nothing also produces no breaches.',
  c2_zero_breaches_after_repair:
    'Zero breaches after RLS and after quarantine, across every principal and every ' +
    'probe type, side_channel included.',
  c3_auditor_confirmed_rows_survived_rls:
    'The auditor still saw the foreign rows at post_rls, proving the boundary hid them ' +
    'rather than something having deleted them.',
  c4_all_probes_ok:
    'Every probe in every counted phase has status ok. Fail closed: an unexecuted probe ' +
    'is not a passed probe.'
};

function renderVerdict(b) {
  const passed = b.receipt.passed === true;
  const badge = document.getElementById('verdict-badge');
  badge.textContent = passed ? 'pass' : 'fail';
  badge.className = 'badge ' + (passed ? 'badge-pass' : 'badge-fail');

  const meta = document.getElementById('verdict-meta');
  meta.textContent = '';
  meta.appendChild(el('div', null, 'receipt ' + short(b.receipt_meta.receipt_id, 13)));
  meta.appendChild(el('div', null, b.receipt_meta.emitted_at));

  document.getElementById('fine').textContent =
    'Corpus ' + b.corpus.rows + ' rows across ' + b.corpus.tenants.length +
    ' tenants, embedded with ' + b.corpus.model + '. Every receipt records the model ' +
    'it was built with, so a receipt cannot present fallback vectors as Titan.';
}

function renderMatrix(b) {
  const byKey = new Map();
  for (const e of b.evidence) {
    const k = e.principal + ' ' + e.probe_type;
    if (!byKey.has(k)) byKey.set(k, { principal: e.principal, probe_type: e.probe_type });
    byKey.get(k)[e.phase] = e;
  }

  const rows = [...byKey.values()]
    .sort((a, x) => a.principal.localeCompare(x.principal) ||
                    a.probe_type.localeCompare(x.probe_type))
    .map(r => {
      const cells = [el('td', null, r.principal), el('td', 'mono', r.probe_type)];
      for (const ph of PHASES) {
        const p = r[ph];
        let label = '-', cls = 'cell';
        if (p) {
          if (p.status !== 'ok') { label = 'ERR'; cls = 'cell cell-err'; }
          else if (p.breach)     { label = 'HIT'; cls = 'cell cell-hit'; }
          else                   { label = 'ok';  cls = 'cell cell-ok'; }
        }
        const span = el('span', cls, label);
        if (p && p.foreign_rows) span.title = p.foreign_rows + ' foreign row(s) returned';
        const td = el('td');
        td.appendChild(span);
        cells.push(td);
      }
      return cells;
    });

  const host = document.getElementById('matrix');
  host.textContent = '';
  host.appendChild(table(
    ['Principal', 'Probe', 'Baseline', 'After RLS', 'After quarantine'], rows));

  const ph = b.receipt.phases;
  const note = document.getElementById('matrix-note');
  note.textContent = '';
  note.appendChild(el('strong', null,
    ph.baseline.foreign_rows + ' foreign rows at baseline, ' +
    ph.post_rls.foreign_rows + ' after RLS, ' +
    ph.post_quarantine.foreign_rows + ' after quarantine.'));
  note.appendChild(el('p', null,
    'The canary phrase corroborates on ' + ph.baseline.canary_hits + ' baseline probe(s). ' +
    'It is recorded as corroboration rather than as the criterion, because it depends ' +
    'on the embedding model retrieving the one marked row.'));
  note.appendChild(el('p', null,
    'semantic_filtered reading ok even at baseline is deliberate, and is the most ' +
    'important row in the table. The correctly scoped query was never the problem. The ' +
    'product exists because the filter on the line above it gets forgotten, and a matrix ' +
    'where every row failed would prove only that the fixture was broken.'));
}

function renderEvidence(b) {
  const prov = new Map((b.provenance || []).map(p => [p.id, p]));
  const host = document.getElementById('evidence');
  host.textContent = '';

  const hits = b.evidence.filter(e =>
    e.phase === 'baseline' && e.breach && e.probe_type !== 'side_channel');

  if (!hits.length) {
    host.appendChild(el('p', 'lede', 'No baseline breaches recorded in this bundle.'));
    return;
  }

  for (const h of hits) {
    const card = el('div', 'hitcard');
    const head = el('h3', null, h.principal + ' ');
    head.appendChild(el('span', 'path', 'via ' + h.probe_type));
    card.appendChild(head);

    for (const row of (h.returned || [])) {
      if (!row.tenant || row.tenant === h.principal) continue;
      const p = prov.get(row.id) || {};
      const d = el('div', 'row');
      const chips = el('div', 'chips');
      chips.appendChild(chip('row', short(row.id)));
      chips.appendChild(chip('tenant', row.tenant, 'chip-foreign'));
      if (p.origin_tenant) chips.appendChild(chip('origin', p.origin_tenant));
      if (p.session_id) chips.appendChild(chip('session', p.session_id));
      if (p.source) chips.appendChild(chip('source', p.source));
      if (p.trust) chips.appendChild(chip('trust', p.trust));
      if (p.quarantined) chips.appendChild(chip('', 'quarantined', 'chip-q'));
      d.appendChild(chips);
      d.appendChild(el('p', 'content', row.content || ''));
      card.appendChild(d);
    }
    host.appendChild(card);
  }
}

function renderPolicy(b) {
  const host = document.getElementById('policy');
  host.textContent = '';
  host.appendChild(kv([
    ['Installed policies', (b.rls.policies || []).join(', ')],
    ['Row level security', 'enabled=' + b.rls.enabled + '  forced=' + b.rls.forced],
    ['policy_sql sha256', b.receipt.policy_sql_sha256 || '']
  ]));
  host.appendChild(callout('FORCE ROW LEVEL SECURITY applies to the table owner too.', [
    'An operation with no applicable policy is denied for every role, which is why the ' +
    'fixture loader runs before this file and why schema/apply.sh has no "all" subcommand.',
    'Privileges are also checked before policies, and the two answer in opposite ways: ' +
    'no privilege is a hard 42501 error, while a held privilege with no matching policy ' +
    'affects zero rows and raises nothing at all. A stray GRANT turns a loud failure into ' +
    'a silent one without changing a single policy.'
  ]));
  host.appendChild(el('pre', null, b.receipt.policy_sql || ''));
}

function renderQuarantine(b) {
  const host = document.getElementById('quarantine');
  host.textContent = '';
  const q = b.receipt.quarantine || {};

  host.appendChild(kv([
    ['Rows moved out of memories', q.count],
    ['misattributed_write', q.misattributed_write + '   (origin_tenant <> tenant)'],
    ['derived_from_foreign_read', q.derived_from_foreign_read +
      '   (written in a session whose retrieval log returned a foreign row)']
  ]));
  host.appendChild(callout('What quarantine refuses to touch.', [
    "Bob's refund ceiling leaked at baseline and is correct data, correctly attributed " +
    "to Bob. The defect was in Alice's query path, so deleting Bob's memory to fix it " +
    'would be a worse bug than the one being fixed. Exposure alone is never a reason to ' +
    'quarantine anything, and after the mover ran those rows are still in memories.'
  ]));

  const rows = (b.quarantine || []).map(r => [
    short(r.id), r.tenant, r.origin_tenant || '-',
    r.session_id || '-', r.source || '-', r.reason
  ]);
  if (rows.length) {
    host.appendChild(table(
      ['Row', 'Tenant', 'Origin', 'Session', 'Source', 'Reason'], rows));
  }
}

function renderReceipt(b) {
  const host = document.getElementById('receipt');
  host.textContent = '';
  const r = b.receipt, m = b.receipt_meta;

  for (const [k, v] of Object.entries(r.clauses || {})) {
    const row = el('div', 'clause');
    row.appendChild(el('span', 'cell ' + (v ? 'cell-ok' : 'cell-hit'), v ? 'PASS' : 'FAIL'));
    const txt = el('div');
    txt.appendChild(el('div', 'mono', k));
    txt.appendChild(el('div', 'lede', CLAUSE_TEXT[k] || ''));
    row.appendChild(txt);
    host.appendChild(row);
  }

  host.appendChild(el('h2', null, 'Phases'));
  host.appendChild(table(
    ['Phase', 'Probes', 'Breaches', 'Foreign rows', 'Canary', 'Errors'],
    PHASES.filter(p => (r.phases || {})[p]).map(p => {
      const v = r.phases[p];
      return [p, v.probes, v.breaches, v.foreign_rows, v.canary_hits, v.errors];
    })));

  host.appendChild(el('h2', null, 'Chain'));
  host.appendChild(kv([
    ['receipt_id', m.receipt_id],
    ['prev_receipt_hash', m.prev_receipt_hash || '(genesis)'],
    ['receipt_hash', m.receipt_hash],
    ['baseline_run', r.baseline_run],
    ['post_rls_run', r.post_rls_run],
    ['post_quarantine_run', r.post_quarantine_run]
  ]));

  const paras = [
    'Editing a receipt breaks its own link. Editing one and recomputing its hash is ' +
    'caught by the next receipt, which committed to the old hash. Rewriting the entire ' +
    'suffix is caught by nothing internal, only by an external anchor, and the test ' +
    'suite asserts that limit rather than hiding it.'
  ];
  if (r.breach_definition) paras.push('Breach definition: ' + r.breach_definition);
  host.appendChild(callout(
    'Tamper-evidence comes from the chain, not from the bucket.', paras));
}
