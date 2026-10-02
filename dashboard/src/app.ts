// The dashboard (PLAN §5.8, M8): status and audit summaries from the API, and everything about the
// log itself checked in the browser by verifier.ts. All text reaches the page through textContent
// (never innerHTML): entries are attacker-influenced (object keys), and the page holds a token.
//
// What is remembered: the vkey and witness keys in localStorage (public, and pinning them is the
// point); the read token in sessionStorage (this tab only); the last verified checkpoint per origin
// in localStorage, so the next visit can prove the log only grew (a small monitor).

import { decodeEntry, loggedName, newKeyBlinder, utf8Decode } from '@r2notary/core';
import {
  UnavailableError,
  VerifyError,
  httpSource,
  openLog,
  openNoteBytes,
  proveConsistency,
  proveEntry,
  recentEntries,
  type LogSource,
  type TrustPolicy,
  type VerifiedCheckpoint,
} from './verifier.ts';

const RECENT = 20;
const REFRESH_MS = 15_000;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  text?: string,
  className?: string,
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (className !== undefined) e.className = className;
  return e;
}

function byId<T extends HTMLElement>(id: string, type: new () => T): T {
  const e = document.getElementById(id);
  if (!(e instanceof type)) throw new Error(`#${id} is missing or not a ${type.name}`);
  return e;
}

const panel = (id: string): HTMLElement => byId(id, HTMLElement);
const tableEl = (id: string): HTMLTableElement => byId(id, HTMLTableElement);

// Storage can be unavailable (private windows, blocked site data); the page works without it.
function load(store: 'local' | 'session', key: string): string | null {
  try {
    return (store === 'local' ? localStorage : sessionStorage).getItem(key);
  } catch {
    return null;
  }
}

function save(store: 'local' | 'session', key: string, value: string | null): void {
  try {
    const s = store === 'local' ? localStorage : sessionStorage;
    if (value === null) s.removeItem(key);
    else s.setItem(key, value);
  } catch {
    // not remembered; fine
  }
}

interface Settings {
  readonly server: string;
  readonly log: string;
  readonly token: string | null;
  /** KEY_BLINDING_KEY of a log that blinds key names (M8), to look keys up by their HMAC. */
  readonly blinding: string | null;
  readonly policy: TrustPolicy;
  readonly auto: boolean;
}

function readSettings(form: HTMLFormElement): Settings {
  const f = new FormData(form);
  const s = (k: string): string =>
    (typeof f.get(k) === 'string' ? (f.get(k) as string) : '').trim();
  const witnesses = s('witnesses')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '');
  const quorum = s('quorum');
  return {
    server: s('server').replace(/\/+$/, ''),
    log: s('log'),
    token: s('token') === '' ? null : s('token'),
    blinding: s('blinding') === '' ? null : s('blinding'),
    policy: {
      vkey: s('vkey'),
      witnesses,
      ...(quorum === '' ? {} : { quorum: Number(quorum) }),
    },
    auto: f.get('auto') === 'on',
  };
}

/** Writes a verdict box: ok (verified), warn (unavailable), bad (the log lied). */
function verdict(
  target: HTMLElement,
  kind: 'ok' | 'warn' | 'bad',
  title: string,
  ...lines: (string | HTMLElement)[]
): void {
  target.className = `panel ${kind}-box`;
  target.replaceChildren(el('p', title, 'verdict'));
  for (const l of lines) target.append(typeof l === 'string' ? el('p', l) : l);
}

function failure(target: HTMLElement, e: unknown): void {
  if (e instanceof VerifyError) {
    verdict(
      target,
      'bad',
      'Verification FAILED: the log served data that does not verify.',
      e.message,
    );
  } else if (e instanceof UnavailableError || e instanceof RangeError) {
    verdict(target, 'warn', 'Could not verify.', e.message);
  } else {
    verdict(target, 'warn', 'Error.', e instanceof Error ? e.message : String(e));
  }
}

interface Api {
  get(route: string): Promise<unknown>;
}

function api(settings: Settings): Api {
  return {
    async get(route) {
      const res = await fetch(`${settings.server}/api/v1/${route}`, {
        headers: settings.token === null ? {} : { authorization: `Bearer ${settings.token}` },
        cache: 'no-store',
      });
      if (!res.ok) throw new UnavailableError(`/api/v1/${route}: HTTP ${String(res.status)}`);
      return (await res.json()) as unknown;
    },
  };
}

// ---- entries ----------------------------------------------------------------------------------

interface EntryView {
  readonly type: string;
  readonly key: string;
  readonly detail: string;
  readonly time: string;
}

function describeEntry(bytes: Uint8Array): EntryView {
  let d;
  try {
    d = decodeEntry(bytes);
  } catch {
    return { type: '(not a v1 entry)', key: '', detail: utf8Decode(bytes).slice(0, 200), time: '' };
  }
  if (!d.known) return { type: `${d.type} (unknown)`, key: '', detail: '', time: '' };
  const e = d.entry;
  const o = e as unknown as Record<string, unknown>;
  const key =
    typeof o.key === 'string' ? o.key : typeof o.keyHmac === 'string' ? `hmac:${o.keyHmac}` : '';
  switch (e.type) {
    case 'object.event':
      return {
        type: e.type,
        key,
        detail: [e.action, e.etag, e.size === undefined ? '' : `${String(e.size)} B`]
          .filter((x) => x !== undefined && x !== '')
          .join(' · '),
        time: e.eventTime,
      };
    case 'object.snapshot':
      return { type: e.type, key, detail: `${e.etag} · ${String(e.size)} B`, time: e.uploaded };
    case 'audit.finding':
      return { type: e.type, key, detail: `${e.kind} (${e.scanId})`, time: e.observedAt };
    case 'audit.observation':
      return { type: e.type, key, detail: `sha256 ${e.sha256.slice(0, 16)}…`, time: e.observedAt };
    case 'audit.scan':
      return {
        type: e.type,
        key: '',
        detail:
          e.phase === 'start'
            ? `${e.scanId} start`
            : `${e.scanId} end: ${String(e.findings ?? 0)} findings`,
        time: '',
      };
  }
}

function entryTable(table: HTMLTableElement, rows: { index: number; entry: Uint8Array }[]): void {
  const head = el('tr');
  for (const h of ['#', 'type', 'key', 'detail', 'time']) head.append(el('th', h));
  table.replaceChildren(head);
  for (const r of rows) {
    const v = describeEntry(r.entry);
    const tr = el('tr');
    tr.append(
      el('td', String(r.index), 'mono'),
      el('td', v.type),
      el('td', v.key, 'mono'),
      el('td', v.detail),
      el('td', v.time, 'mono'),
    );
    table.append(tr);
  }
}

// ---- the main verification --------------------------------------------------------------------

interface Session {
  readonly settings: Settings;
  readonly source: LogSource;
  readonly api: Api;
  cp: VerifiedCheckpoint | null;
  samples: { at: number; size: number }[];
  /** The API says the log blinds key names (M8); lookups then go by keyHmac. */
  readonly blinded: boolean;
}

let session: Session | null = null;
let timer: ReturnType<typeof setInterval> | null = null;

const lastKey = (origin: string): string => `r2notary:last-checkpoint:${origin}`;

async function verifyCheckpoint(s: Session): Promise<void> {
  const box = panel('checkpoint');
  const cp = await openLog(s.source, s.settings.policy);
  const { origin, size, rootHash } = cp.checkpoint;
  const lines: (string | HTMLElement)[] = [
    `origin ${origin}`,
    `size ${String(size)}`,
    `root ${btoa(String.fromCharCode(...rootHash))}`,
  ];
  for (const c of cp.cosignatures) {
    lines.push(`cosigned by witness ${c.name} at ${new Date(c.timestamp * 1000).toISOString()}`);
  }

  const checked = ['signature', 'origin'];
  if (cp.cosignatures.length > 0) {
    checked.push(`${String(cp.cosignatures.length)} witness cosignature(s)`);
  }
  // The log must extend whatever this browser verified before (a monitor's core check).
  const saved = load('local', lastKey(origin));
  if (saved !== null) {
    const older = await openNoteBytes(new TextEncoder().encode(saved), {
      vkey: s.settings.policy.vkey,
      origin,
    }).catch(() => null);
    if (older === null) {
      lines.push(
        'The checkpoint saved by an earlier visit does not verify with this key; ignored.',
      );
    } else {
      try {
        await proveConsistency(s.source, older, cp);
      } catch (e) {
        if (e instanceof VerifyError) {
          const evidence = el('pre');
          evidence.textContent = `previously verified:\n${saved}\nserved now:\n${cp.note}`;
          verdict(
            box,
            'bad',
            'FORK OR ROLLBACK: this checkpoint does not extend the one this browser verified before.',
            e.message,
            'Both signed checkpoints are below; together they are evidence. Not saving the new one.',
            evidence,
          );
          s.cp = null;
          return;
        }
        throw e;
      }
      lines.push(
        `Consistent with the checkpoint of size ${String(older.checkpoint.size)} verified before.`,
      );
      checked.push('that the log only grew since then');
    }
  }
  save('local', lastKey(origin), cp.note);
  s.cp = cp;
  if (saved === null) lines.push('First visit for this log: saved, so the next one checks growth.');
  verdict(box, 'ok', `Verified: ${checked.join(', ')}.`, ...lines);
}

/** A status value for display; anything that is not a plain value is shown as JSON. */
function show(v: unknown): string {
  if (v === null || v === undefined) return '–';
  return typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
    ? String(v)
    : JSON.stringify(v);
}

async function showStatus(s: Session): Promise<void> {
  const dl = byId('status', HTMLDListElement);
  const st = (await s.api.get('status')) as Record<string, unknown>;
  const now = Date.now();
  if (typeof st.size === 'number') {
    s.samples = [...s.samples.filter((x) => x.at > now - 600_000), { at: now, size: st.size }];
  }
  const first = s.samples[0];
  const last = s.samples.at(-1);
  const rate =
    first !== undefined && last !== undefined && last.at - first.at >= 10_000
      ? `${(((last.size - first.size) / (last.at - first.at)) * 60_000).toFixed(1)} entries/min (seen by this page)`
      : 'measuring…';
  const ingest = (st.ingest ?? {}) as Record<string, unknown>;
  const audit = (st.audit ?? null) as Record<string, unknown> | null;
  const rows: [string, unknown][] = [
    ['published size', st.size],
    ['durable (not yet published)', st.pending],
    ['growth', rate],
    ['last checkpoint', st.lastCheckpointAt],
    ['accepted events', ingest.accepted],
    ['duplicates', ingest.duplicates],
    ['invalid / dead-lettered', `${show(ingest.invalid)} / ${show(ingest.deadLettered)}`],
    ['last error', st.lastError ?? 'none'],
    ['last audit', audit === null ? 'none' : `${show(audit.scanId)} (${show(audit.state)})`],
  ];
  dl.replaceChildren();
  for (const [k, v] of rows) dl.append(el('dt', k), el('dd', show(v)));
}

async function showFindings(s: Session): Promise<void> {
  const box = panel('findings');
  const table = tableEl('findings-table');
  const cp = s.cp;
  if (cp === null) return;
  const page = (await s.api.get('findings?limit=1000')) as {
    scan: { scanId: string; state: string; findings: number; endIndex: number | null } | null;
    findings: { index: number; published: boolean }[];
    next: number | null;
  };
  if (page.scan === null) {
    verdict(box, 'ok', 'No audit has run yet.');
    table.replaceChildren();
    return;
  }
  const scan = page.scan;
  const proven: { index: number; entry: Uint8Array }[] = [];
  for (const f of page.findings.filter((x) => x.index < cp.checkpoint.size)) {
    const p = await proveEntry(s.source, cp, f.index);
    const d = decodeEntry(p.entry);
    if (!d.known || d.entry.type !== 'audit.finding' || d.entry.scanId !== scan.scanId) {
      throw new VerifyError(
        `the API listed entry ${String(f.index)}, which is not a finding of ${scan.scanId}`,
      );
    }
    proven.push(p);
  }
  const lines = [
    `${scan.scanId}: ${scan.state}. ${String(proven.length)} findings proven against the checkpoint.`,
  ];
  // The scan's signed end entry commits to how many findings there are, so the API cannot hide one.
  if (scan.endIndex !== null && scan.endIndex < cp.checkpoint.size && page.next === null) {
    const end = decodeEntry((await proveEntry(s.source, cp, scan.endIndex)).entry);
    const signed =
      end.known && end.entry.type === 'audit.scan' && end.entry.scanId === scan.scanId
        ? end.entry.findings
        : undefined;
    if (signed !== proven.length) {
      throw new VerifyError(
        `the scan's signed end entry counts ${String(signed)} findings; the API listed ${String(proven.length)}`,
      );
    }
    lines.push('The count matches the scan’s signed end entry.');
  }
  verdict(box, 'ok', 'Audit findings', ...lines);
  entryTable(table, proven);
}

async function refresh(s: Session): Promise<void> {
  // Status is informational; a failure there must not hide the verification result.
  await showStatus(s).catch((e: unknown) => {
    panel('status').replaceChildren(
      el('dt', 'status'),
      el('dd', e instanceof Error ? e.message : String(e)),
    );
  });
  try {
    await verifyCheckpoint(s);
    const cp = s.cp;
    if (cp === null) return;
    entryTable(tableEl('recent'), await recentEntries(s.source, cp, RECENT));
  } catch (e) {
    failure(panel('checkpoint'), e);
    return;
  }
  await showFindings(s).catch((e: unknown) => {
    failure(panel('findings'), e);
  });
}

async function start(form: HTMLFormElement): Promise<void> {
  const settings = readSettings(form);
  save('local', 'r2notary:vkey', settings.policy.vkey);
  save('local', 'r2notary:witnesses', (settings.policy.witnesses ?? []).join('\n'));
  save('session', 'r2notary:token', settings.token);
  save('session', 'r2notary:blinding', settings.blinding);
  const a = api(settings);
  let log = settings.log;
  let blinded = false;
  try {
    const st = (await a.get('status')) as { log?: unknown; keyBlinding?: unknown };
    if (log === '' && typeof st.log === 'string') log = st.log;
    blinded = st.keyBlinding === true;
  } catch (e) {
    if (log === '') {
      failure(panel('checkpoint'), e);
      return;
    }
  }
  const s: Session = {
    settings,
    source: httpSource(`${settings.server}/log/${encodeURIComponent(log)}`, settings.token),
    api: a,
    cp: null,
    samples: [],
    blinded,
  };
  session = s;
  if (timer !== null) clearInterval(timer);
  timer = settings.auto
    ? setInterval(() => {
        if (session === s) void refresh(s);
      }, REFRESH_MS)
    : null;
  await refresh(s);
}

async function lookup(query: string): Promise<void> {
  const box = panel('lookup-result');
  const s = session;
  const cp = s?.cp ?? null;
  if (s === null || cp === null) {
    verdict(box, 'warn', 'Verify the checkpoint first.');
    return;
  }
  try {
    let rows: { index: number; entry: Uint8Array }[];
    if (/^\d+$/.test(query)) {
      rows = [await proveEntry(s.source, cp, Number(query))];
    } else {
      // The lookup API is an unverified index: each index it returns is proven, and must name the
      // key. It could still leave entries out; the Go CLI's full scan cannot be fooled that way.
      // On a blinded log the HMAC is computed here, so neither the key nor the secret leaves.
      let name = query;
      let param = 'key';
      if (s.blinded) {
        if (s.settings.blinding === null) {
          verdict(
            box,
            'warn',
            'This log blinds key names: enter its key blinding key to look a key up.',
          );
          return;
        }
        name = await (await newKeyBlinder(s.settings.blinding)).blind(query);
        param = 'keyHmac';
      }
      const page = (await s.api.get(`lookup?${param}=${encodeURIComponent(name)}`)) as {
        entries: { index: number }[];
      };
      rows = [];
      for (const { index } of page.entries) {
        if (index >= cp.checkpoint.size) continue; // newer than this checkpoint
        const p = await proveEntry(s.source, cp, index);
        const d = decodeEntry(p.entry);
        const n = d.known ? loggedName(d.entry) : null;
        if (n?.name !== name || n.blinded !== s.blinded) {
          throw new VerifyError(
            `the lookup API returned entry ${String(index)}, which does not name the key`,
          );
        }
        rows.push(p);
      }
    }
    const table = el('table');
    entryTable(table, rows);
    verdict(
      box,
      'ok',
      `${String(rows.length)} entries proven in the tree of size ${String(cp.checkpoint.size)}.`,
      table,
    );
  } catch (e) {
    failure(box, e);
  }
}

function init(): void {
  const form = byId('settings', HTMLFormElement);
  const field = (name: string): HTMLInputElement | HTMLTextAreaElement =>
    form.elements.namedItem(name) as HTMLInputElement | HTMLTextAreaElement;
  if (location.protocol === 'http:' || location.protocol === 'https:') {
    field('server').value = location.origin;
  }
  // A link may carry the vkey in its fragment (never sent to the server): #vkey=...
  const hash = new URLSearchParams(location.hash.slice(1));
  field('vkey').value = hash.get('vkey') ?? load('local', 'r2notary:vkey') ?? '';
  field('witnesses').value = load('local', 'r2notary:witnesses') ?? '';
  field('token').value = load('session', 'r2notary:token') ?? '';
  field('blinding').value = load('session', 'r2notary:blinding') ?? '';
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    void start(form);
  });
  panel('forget').addEventListener('click', () => {
    const origin = session?.cp?.checkpoint.origin;
    if (origin !== undefined) save('local', lastKey(origin), null);
    verdict(
      panel('checkpoint'),
      'warn',
      'Forgot the saved checkpoint; the next verification starts afresh.',
    );
  });
  byId('lookup', HTMLFormElement).addEventListener('submit', (ev) => {
    ev.preventDefault();
    const q = new FormData(ev.target as HTMLFormElement).get('query');
    void lookup(typeof q === 'string' ? q.trim() : '');
  });
  if (field('vkey').value !== '' && hash.has('vkey')) void start(form);
}

init();
