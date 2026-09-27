/**
 * A mock Splunk search REST API (`POST /services/search/v2/jobs`, its status
 * endpoint, `/results`, `DELETE`) answering from an in-memory synthetic
 * auth+firewall index, in the same shape the site's `pushdown-splunk` usage
 * sample answers from (`src/lib/usage/sources.ts`). Ours is bigger (~50,000
 * events) and actually reads the SPL the grid's real `splunkAdapter` sends —
 * the filter expression, `earliest_time`/`latest_time`, `| sort` — so every
 * grid gesture visibly changes the result, per the work order.
 *
 * Only the filter EXPRESSION is parsed generically (§ parseExpr): the grid
 * can emit any combination the adapter's operators allow, so it earns a real
 * recursive-descent parser. The `| stats` and `| timechart` tails are ones
 * THIS FILE generates for its own second searches (app.js never builds SPL
 * itself), so they are recognised by a fixed shape rather than re-parsed —
 * this is a demo mock, not a Splunk reimplementation, and that boundary is
 * deliberate. Licence: the synthetic data is ours, CC0.
 */

const USERS = ['alice', 'bob', 'carol', 'dave', 'eve', 'frank', 'grace', 'heidi', 'admin', 'svc-backup', 'ivan', 'judy'];
const COUNTRIES = ['US', 'GB', 'DE', 'FR', 'NL', 'SG', 'BR', 'IN', 'CN', 'RU'];
const PORTS = [22, 443, 3389, 8080, 53, 3306, 8443, 5432];
const ATTACKER_IPS = ['203.0.113.7', '198.51.100.23', '192.0.2.44'];
// A fixed pool, not a fresh random quad per event: real traffic comes from a
// bounded set of hosts, so `distinct_sources` should read far below `events`.
// The first 20 are weighted 8x — a few noisy hosts, not a flat distribution.
const IP_POOL = Array.from({ length: 400 }, () => randomIp(4));

/** @param {number} n how many quad octets to generate @returns {string} a dotted-quad */
function randomIp(n) { return Array.from({ length: n }, () => Math.floor(Math.random() * 255)).join('.'); }
function pick(list) { return list[Math.floor(Math.random() * list.length)]; }
/** @returns {string} a source IP from the skewed pool (a few hosts chatter far more than most) */
function pickSourceIp() { return IP_POOL[Math.floor(Math.random() * (Math.random() < 0.5 ? 20 : IP_POOL.length))]; }

/**
 * Build the ~50,000-event synthetic index, spanning the last 48 hours, drawn
 * from a 400-host pool (skewed, so distinct sources reads far below the
 * event count), with three IPs seeded with failed-login bursts so the
 * alarms strip has real repeat offenders.
 * @returns {object[]} the index, newest-unsorted (the mock sorts on demand)
 */
export function buildIndex() {
  const now = Date.now();
  const events = [];
  for (let i = 0; i < 50000; i += 1) {
    const t = now - Math.floor(Math.random() * 48 * 3600000);
    const sourcetype = Math.random() < 0.55 ? 'auth' : 'firewall';
    const action = Math.random() < 0.08 ? 'failed_login' : (Math.random() < 0.3 ? 'blocked' : 'allowed');
    events.push({
      event_id: `e${i}`, _time: t, src_ip: pickSourceIp(), user: pick(USERS),
      action, dest_port: pick(PORTS), sourcetype, country: pick(COUNTRIES),
    });
  }
  for (const ip of ATTACKER_IPS) {
    const burstAt = now - Math.floor(Math.random() * 6 * 3600000);
    const n = 20 + Math.floor(Math.random() * 40);
    for (let i = 0; i < n; i += 1) {
      events.push({
        event_id: `atk${ip}-${i}`, _time: burstAt + i * 4000, src_ip: ip, user: pick(USERS),
        action: 'failed_login', dest_port: 22, sourcetype: 'auth', country: pick(COUNTRIES),
      });
    }
  }
  return events;
}

/** @param {string} s the char @returns {string} its regex-escaped form */
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Turn one quoted SPL literal's inner text (already stripped of its quotes)
 * into a case-insensitive `RegExp`, honouring the escaping `splunkAdapter`'s
 * `escaped()`/`quoted()` produce: `\\`, `\"`, `\*` are literal characters and
 * a bare `*` is a wildcard.
 * @param {string} inner the text between the quotes
 * @returns {RegExp} the equivalent matcher
 */
function literalToRegExp(inner) {
  let pattern = '^';
  for (let i = 0; i < inner.length; i += 1) {
    const c = inner[i];
    if (c === '\\' && i + 1 < inner.length) { pattern += reEsc(inner[i + 1]); i += 1; }
    else if (c === '*') pattern += '.*';
    else pattern += reEsc(c);
  }
  return new RegExp(`${pattern}$`, 'i');
}

/** Tokenize an SPL filter expression into the shapes `filtersToSpl` emits. */
function tokenize(expr) {
  const tokens = [];
  let i = 0;
  while (i < expr.length) {
    const c = expr[i];
    if (/\s/.test(c)) { i += 1; continue; }
    if (c === '(' || c === ')') { tokens.push({ t: c }); i += 1; continue; }
    if (c === '"') {
      let j = i + 1; let inner = '';
      while (j < expr.length && expr[j] !== '"') {
        if (expr[j] === '\\' && j + 1 < expr.length) { inner += expr[j] + expr[j + 1]; j += 2; }
        else { inner += expr[j]; j += 1; }
      }
      tokens.push({ t: 'str', re: literalToRegExp(inner) });
      i = j + 1; continue;
    }
    if (c === '*') { tokens.push({ t: 'star' }); i += 1; continue; }
    const opMatch = /^(<=|>=|=|<|>)/.exec(expr.slice(i));
    if (opMatch) { tokens.push({ t: 'op', v: opMatch[1] }); i += opMatch[1].length; continue; }
    const wordMatch = /^[A-Za-z_][A-Za-z0-9_.:-]*/.exec(expr.slice(i));
    if (wordMatch) {
      const w = wordMatch[0];
      tokens.push(/^(AND|OR|NOT)$/.test(w) ? { t: w } : { t: 'ident', v: w });
      i += w.length; continue;
    }
    const numMatch = /^-?\d+(\.\d+)?/.exec(expr.slice(i));
    if (numMatch) { tokens.push({ t: 'num', v: Number(numMatch[0]) }); i += numMatch[0].length; continue; }
    throw new Error(`mock splunk: cannot tokenize SPL near "${expr.slice(i, i + 20)}"`);
  }
  return tokens;
}

/** Recursive-descent parser over the token stream; returns an AST node. */
function parseExpr(expr) {
  const tokens = tokenize(expr);
  let p = 0;
  const peek = () => tokens[p];
  const parseLeaf = () => {
    if (peek() && peek().t === '(') { p += 1; const node = parseOr(); p += 1; return node; }
    if (peek() && peek().t === 'NOT') { p += 1; return { t: 'not', child: parseLeaf() }; }
    const ident = tokens[p]; p += 1;
    const op = tokens[p]; p += 1;
    const value = tokens[p]; p += 1;
    if (value.t === 'star') return { t: 'exists', field: ident.v };
    return { t: 'cmp', field: ident.v, op: op.v, value: value.t === 'num' ? value.v : value.re };
  };
  const parseAnd = () => {
    let node = parseLeaf();
    while (peek() && peek().t === 'AND') { p += 1; node = { t: 'and', a: node, b: parseLeaf() }; }
    return node;
  };
  const parseOr = () => {
    let node = parseAnd();
    while (peek() && peek().t === 'OR') { p += 1; node = { t: 'or', a: node, b: parseAnd() }; }
    return node;
  };
  return parseOr();
}

/** @param {object} event one mock row @param {object} node the AST @returns {boolean} match */
function evaluate(event, node) {
  switch (node.t) {
    case 'and': return evaluate(event, node.a) && evaluate(event, node.b);
    case 'or': return evaluate(event, node.a) || evaluate(event, node.b);
    case 'not': return !evaluate(event, node.child);
    case 'exists': return event[node.field] !== undefined && event[node.field] !== null && event[node.field] !== '';
    case 'cmp': {
      const actual = event[node.field];
      if (node.value instanceof RegExp) return node.op === '=' && node.value.test(String(actual));
      const n = Number(actual);
      if (node.op === '=') return n === node.value;
      if (node.op === '<') return n < node.value;
      if (node.op === '<=') return n <= node.value;
      if (node.op === '>') return n > node.value;
      if (node.op === '>=') return n >= node.value;
      return false;
    }
    default: return true;
  }
}

/**
 * Read the filter expression, `earliest_time`/`latest_time` and `| sort`
 * out of one dispatched search, and return the matching, sorted rows — or,
 * for the app's own `| stats`/`| timechart` second searches, the aggregate
 * they ask for.
 * @param {string} search the SPL, as `splunkAdapter.searchFor` built it
 * @param {{earliest?: string, latest?: string}} bounds the job's time window
 * @param {object[]} index the full mock index
 * @returns {object[]} the rows this job holds
 */
export function runSearch(search, bounds, index) {
  let body = search.replace(/^search\s+/, '');
  const bySourceMatch = / \| stats count by src_ip/.exec(body);
  const eventsStatsMatch = !bySourceMatch && / \| stats count as events/.exec(body);
  const timechartMatch = / \| timechart span=15m count/.exec(body);
  const sortMatch = / \| sort 0 (.+)$/.exec(body);
  if (bySourceMatch) body = body.slice(0, bySourceMatch.index);
  else if (eventsStatsMatch) body = body.slice(0, eventsStatsMatch.index);
  else if (timechartMatch) body = body.slice(0, timechartMatch.index);
  else if (sortMatch) body = body.slice(0, sortMatch.index);

  const rest = body.replace(/^index=security\s*/, '').trim();
  const ast = rest ? parseExpr(rest) : null;
  const earliest = bounds.earliest !== undefined ? Number(bounds.earliest) * 1000 : -Infinity;
  const latest = bounds.latest !== undefined ? Number(bounds.latest) * 1000 : Infinity;
  const matched = index.filter((e) => e._time >= earliest && e._time < latest && (!ast || evaluate(e, ast)));

  if (bySourceMatch) {
    const counts = new Map();
    for (const e of matched) counts.set(e.src_ip, (counts.get(e.src_ip) || 0) + 1);
    return [...counts.entries()].map(([src_ip, count]) => ({ src_ip, count }))
      .sort((a, b) => b.count - a.count);
  }
  if (eventsStatsMatch) {
    const blocked = matched.filter((e) => e.action === 'blocked').length;
    return [{
      events: matched.length,
      distinct_sources: new Set(matched.map((e) => e.src_ip)).size,
      blocked_share: matched.length ? blocked / matched.length : 0,
    }];
  }
  if (timechartMatch) {
    const spanMs = 15 * 60000;
    const buckets = new Map();
    for (const e of matched) {
      const key = Math.floor(e._time / spanMs) * spanMs;
      buckets.set(key, (buckets.get(key) || 0) + 1);
    }
    return [...buckets.entries()].sort((a, b) => a[0] - b[0])
      .map(([t, count]) => ({ _time: t, count }));
  }
  if (sortMatch) {
    const entries = sortMatch[1].split(',').map((s) => s.trim());
    matched.sort((a, b) => {
      for (const entry of entries) {
        const dir = entry[0] === '-' ? -1 : 1;
        const field = entry.replace(/^[+-]/, '');
        if (a[field] < b[field]) return -1 * dir;
        if (a[field] > b[field]) return 1 * dir;
      }
      return 0;
    });
  }
  return matched;
}

/**
 * A `fetch` implementation answering the Splunk search REST sequence over
 * `index`, honouring offset/count paging on `/results`.
 * @param {object[]} index the mock index (mutated by live tail to append events)
 * @returns {Function} a `fetch`-shaped function
 */
export function makeMockFetch(index) {
  const jobs = new Map();
  let seq = 0;
  return async (input, init = {}) => {
    const url = new URL(String(input));
    const method = String((init && init.method) || 'GET').toUpperCase();
    if (method === 'POST' && url.pathname.endsWith('/jobs')) {
      const params = new URLSearchParams(String(init.body || ''));
      const sid = `mock-${seq += 1}`;
      const rows = runSearch(params.get('search') || '', {
        earliest: params.get('earliest_time') || undefined,
        latest: params.get('latest_time') || undefined,
      }, index);
      jobs.set(sid, rows);
      return new Response(JSON.stringify({ sid }));
    }
    const sidMatch = /\/jobs\/([^/]+)/.exec(url.pathname);
    const sid = sidMatch ? decodeURIComponent(sidMatch[1]) : null;
    if (method === 'DELETE') { if (sid) jobs.delete(sid); return new Response(null, { status: 200 }); }
    if (url.pathname.endsWith('/results')) {
      const rows = jobs.get(sid) || [];
      const offset = Number(url.searchParams.get('offset') || 0);
      const count = Number(url.searchParams.get('count') || 0) || rows.length;
      return new Response(JSON.stringify({ results: rows.slice(offset, offset + count) }));
    }
    const rows = jobs.get(sid) || [];
    return new Response(JSON.stringify({ isDone: true, dispatchState: 'DONE', resultCount: rows.length }));
  };
}

/**
 * Run one search REST cycle (dispatch, then read every result) — for the
 * `| stats`/`| timechart` second searches the KPI tiles, the timeline and
 * the alarms strip need, since `splunkAdapter` does not push grouping
 * (BACKLOG-0001030 non-goal) and only reads/writes rows through its own
 * `execute`. Works against the mock `fetch` or a real one identically.
 * @param {Function} fetchImpl the `fetch` to use (mock, or the page's own)
 * @param {string} jobsUrl the `.../services/search/v2/jobs` endpoint
 * @param {Record<string,string>} headers extra headers (a bearer token, live)
 * @param {string} search the full SPL, including its `| stats`/`| timechart` tail
 * @param {{earliest?: number, latest?: number}} bounds the job's time window (epoch seconds)
 * @returns {Promise<object[]>} the rows Splunk (or the mock) returned
 */
export async function dispatchSearch(fetchImpl, jobsUrl, headers, search, bounds) {
  const body = new URLSearchParams({ search, output_mode: 'json', exec_mode: 'blocking' });
  if (bounds.earliest !== undefined) body.set('earliest_time', String(bounds.earliest));
  if (bounds.latest !== undefined) body.set('latest_time', String(bounds.latest));
  const created = await fetchImpl(jobsUrl, {
    method: 'POST', headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(),
  });
  const { sid } = await created.json();
  const results = await fetchImpl(`${jobsUrl}/${encodeURIComponent(sid)}/results?output_mode=json&count=0`, { headers });
  const { results: rows } = await results.json();
  return rows || [];
}
