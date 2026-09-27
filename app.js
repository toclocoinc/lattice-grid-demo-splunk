/**
 * Wiring only: the mock Splunk index and its search REST API live in
 * `mock-splunk.js`. One base search (`index=security`) drives the events
 * grid through the real `splunkAdapter`; `splunkAdapter` does not push
 * `| stats`/`| timechart` (BACKLOG-0001030 non-goal, read in the adapter's
 * own header), so the KPI tiles, the timeline and the alarms strip run their
 * own second searches against the same index, built from the same filter
 * plan the grid just sent.
 */
import { buildIndex, makeMockFetch, dispatchSearch } from './mock-splunk.js';
const WINDOWS = [
  { id: 'grid', title: 'Events', xPos: 1, yPos: 1, xSize: 14, ySize: 17, chrome: false, movable: true, resizable: true },
  { id: 'timeline', title: 'Timeline', xPos: 15, yPos: 1, xSize: 10, ySize: 12, chrome: false, movable: true, resizable: true },
  { id: 'kpis', title: 'KPIs', xPos: 15, yPos: 13, xSize: 10, ySize: 4, chrome: false, movable: true, resizable: true },
  { id: 'alarms', title: 'Alarms', xPos: 1, yPos: 18, xSize: 7, ySize: 4, chrome: false, movable: true, resizable: true },
  { id: 'plan', title: 'Plan', xPos: 8, yPos: 18, xSize: 7, ySize: 4, chrome: false, movable: true, resizable: true },
  { id: 'byo', title: 'BYO', xPos: 15, yPos: 17, xSize: 10, ySize: 5, chrome: false, movable: true, resizable: true },
];
const body = (id) => document.getElementById(`${id}-body`);
const panel = (id, heading) => {
  const el = body(id);
  el.className = 'panel';
  el.innerHTML = `<div class="panel__head">${heading}</div><div class="panel__body"></div>`;
  return el.lastChild;
};
LatticeGridLayout.createLayout(document.getElementById('container'), {
  columns: 26, rows: 24, gap: 6, padding: 6, overflowX: 'static', overflowY: 'static', windows: WINDOWS,
});
const THEME = new URLSearchParams(location.search).get('theme') === 'light' ? 'light' : 'dark';
const ALARM_THRESHOLD = 10;
const index = buildIndex();
let host = { url: null, headers: {}, fetch: makeMockFetch(index) };
let liveTimer = null;
const state = {};
const jobsUrlOf = (url) => `${(url || 'https://mock.splunk.local:8089').replace(/\/+$/, '')}/services/search/v2/jobs`;
/** (Re)build the grid, timeline chart and KPI tiles against the current `host`. */
function buildAll() {
  state.grid?.destroy(); state.chart?.destroy(); state.kpi?.destroy();
  const adapter = LatticeGrid.splunkAdapter({
    url: host.url || 'https://mock.splunk.local:8089', search: 'index=security',
    earliest: new Date(Date.now() - 24 * 3600000), fetch: host.fetch, headers: host.headers,
  });
  const source = LatticeGrid.createPushdownSource({ adapter, compute: LatticeGrid, pageSize: 50 });
  const grid = LatticeGrid.createGrid(
    panel('grid', host.url ? `Events · connected to ${host.url}` : 'Events · demo index (mock)'), {
      theme: THEME, rowKey: 'event_id', filterRow: true, source,
      columns: [
        { field: 'event_id', title: 'ID', layout: { hidden: true } },
        { field: '_time', title: 'Time', type: 'timestamp', format: { pattern: 'yyyy-MM-dd HH:mm:ss', timeZone: 'UTC' } },
        { field: 'src_ip', title: 'Source IP', filter: { type: 'text' } },
        { field: 'user', title: 'User', filter: { type: 'text' } },
        { field: 'action', title: 'Action', filter: { type: 'set' } },
        { field: 'dest_port', title: 'Port', type: 'number', filter: { type: 'number' } },
        { field: 'sourcetype', title: 'Type', filter: { type: 'set' } },
        { field: 'country', title: 'Country', filter: { type: 'text' } },
      ],
    });
  grid.sort.set([{ col: '_time', dir: 'desc' }]);
  const timelineGrid = LatticeGrid.createGrid(document.createElement('div'), {
    rowKey: '_time',
    columns: [{ field: '_time', type: 'timestamp', format: { pattern: 'HH:mm', timeZone: 'UTC' } }, { field: 'count', type: 'number' }],
    source: [{ _time: 0, count: 0 }],
  });
  const chart = LatticeGrid.createChart({
    grid: timelineGrid, container: panel('timeline', 'Events per 15 minutes · computed by Splunk (timechart)'),
    type: 'bar', x: '_time', y: 'count',
  });
  const kpi = LatticeGridKPI.createKPI(panel('kpis', 'Computed by Splunk (stats)'), {
    rows: [], columns: 3,
    tiles: [
      { id: 'events', label: 'Events', aggregation: 'sum', field: 'events' },
      { id: 'sources', label: 'Distinct sources', aggregation: 'sum', field: 'distinct_sources' },
      { id: 'blocked', label: 'Blocked share', aggregation: 'sum', field: 'blocked_share', format: { type: 'percent', decimals: 1 } },
    ],
  });
  const alarmsEl = panel('alarms', `${ALARM_THRESHOLD}+ failed logins`);
  const planEl = panel('plan', 'source.lastPlan()');
  /** Re-run the `| stats`/`| timechart` second searches and repaint every panel that follows the grid's query. */
  async function refresh() {
    const plan = source.lastPlan();
    const built = adapter.searchFor(plan ? plan.pushed : {});
    const filterOnly = built.search.replace(/ \| sort 0 .+$/, '');
    const bounds = { earliest: built.earliest, latest: built.latest };
    const jobsUrl = jobsUrlOf(host.url);
    const [statsRows, timelineRows, alarmRows] = await Promise.all([
      dispatchSearch(host.fetch, jobsUrl, host.headers,
        `${filterOnly} | stats count as events, dc(src_ip) as distinct_sources, count(eval(action="blocked")) as blocked_count`, bounds),
      dispatchSearch(host.fetch, jobsUrl, host.headers, `${filterOnly} | timechart span=15m count`, bounds),
      dispatchSearch(host.fetch, jobsUrl, host.headers, 'search index=security action="failed_login" | stats count by src_ip', bounds),
    ]);
    kpi.setRows([statsRows[0] || { events: 0, distinct_sources: 0, blocked_share: 0 }]).refresh();
    timelineGrid.rows.load(timelineRows);
    alarmsEl.innerHTML = alarmRows.filter((r) => r.count >= ALARM_THRESHOLD)
      .map((r) => `<div class="alarm">${r.src_ip} — ${r.count} failed logins</div>`).join('') || '<div class="ok">No alarms</div>';
    planEl.innerHTML = `<div><b>search</b><br>${built.search}</div>`
      + `<div>window: earliest ${new Date(bounds.earliest * 1000).toISOString()}</div>`
      + `<div>unpushed (stays client-side): ${plan && plan.unpushed.length ? plan.unpushed.join(', ') : 'none'}</div>`;
  }
  grid.on('model:changed', refresh); // a re-run query, not row-level edits, is what should re-run the second searches
  refresh();
  Object.assign(state, { grid, chart, kpi, source, adapter, refresh });
  window.__demo = state; // for the headless verification script only
}
buildAll();

// Live tail: append events, then roll the grid's window forward via
// `filters.set` — `liftTimeBounds` turns a top-level `_time >= x` into a
// moving `earliest_time`, so this is a real re-query, not just a repaint.
document.getElementById('live-toggle').addEventListener('change', (evt) => {
  if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
  if (!evt.target.checked) return;
  liveTimer = setInterval(() => {
    const now = Date.now();
    for (let i = 0; i < 5; i += 1) {
      index.push({
        event_id: `live-${now}-${i}`, _time: now, src_ip: `10.0.${i}.${(now + i) % 255}`, user: 'svc-backup',
        action: Math.random() < 0.2 ? 'blocked' : 'allowed', dest_port: 443, sourcetype: 'firewall', country: 'US',
      });
    }
    const current = state.grid.filters.get();
    state.grid.filters.set({
      op: 'and',
      conditions: [...(current ? [current] : []), { col: '_time', op: 'gte', value: new Date(now - 15 * 60000) }],
    });
  }, 2000);
});

// BYO Splunk: on a working connection, re-point the SAME page at the
// visitor's instance. The token lives only in this closure (`host.headers`)
// — never localStorage, never the URL — and a bad host leaves the mock running.
panel('byo', 'Bring your own Splunk').innerHTML = '<div class="byo">'
  + '<input id="byo-url" placeholder="https://splunk.example.com:8089">'
  + '<input id="byo-token" placeholder="Bearer token" type="password">'
  + '<button id="byo-connect">Connect</button><div id="byo-error"></div>'
  + '<div class="note">The token stays in page memory only, for this session. It is never written to storage or the URL.</div></div>';
document.getElementById('byo-connect').addEventListener('click', async () => {
  const url = document.getElementById('byo-url').value.trim();
  const headers = { Authorization: `Bearer ${document.getElementById('byo-token').value.trim()}` };
  const errEl = document.getElementById('byo-error');
  errEl.textContent = 'Connecting…';
  try {
    await dispatchSearch(fetch, jobsUrlOf(url), headers, 'search index=security | stats count', {});
    host = { url, headers, fetch };
    errEl.textContent = '';
    buildAll();
  } catch (err) {
    errEl.textContent = `Could not connect: ${err.message}. Still showing the demo index (mock).`;
  }
});
