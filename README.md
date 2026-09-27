# A SOC triage wall over Splunk

A security-operations triage wall driven by Splunk searches through the
grid's `splunkAdapter`: an events grid whose filter row is pushed down as
SPL, a per-minute timeline, KPI tiles, an alarms strip of source IPs with
repeated failed logins, a panel showing the exact SPL the grid generated,
and a "bring your own Splunk" panel that re-points the same page at a real
instance.

**[See it running](https://toclocoinc.github.io/lattice-grid-demo-splunk/)**

**The default mode is a mock.** With no Splunk instance configured, the
page answers Splunk's search REST API from an in-memory mock
(`mock-splunk.js`) over a synthetic index generated on load. See
[Pointing it at a real Splunk](#pointing-it-at-a-real-splunk) to use your
own.

| | |
| --- | --- |
| Grid on npm | [@toclocoinc/lattice-grid](https://www.npmjs.com/package/@toclocoinc/lattice-grid) |
| Grid repository | [toclocoinc/latticegrid](https://github.com/toclocoinc/latticegrid) |
| Product site | [latticegrid.dev](https://www.latticegrid.dev) |

## What it shows

- **Events grid** — the filter row's per-column conditions (text, number and
  set filters) are pushed down as an SPL `search` expression through
  `splunkAdapter` + `createPushdownSource`. Sorting and paging are pushed
  too.
- **Timeline** — events per minute, from a `| timechart span=1m count`
  search.
- **KPI tiles** — events, distinct sources, blocked share, from a `| stats`
  search.
- **Alarms strip** — source IPs with 10+ failed logins in the current
  window, from a `| stats count by src_ip` search.
- **"What we sent"** — `source.lastPlan()` plus
  `adapter.searchFor(plan.pushed)`: the exact SPL the grid generated, the
  time window, and what stayed client-side (`plan.unpushed`).
- **Bring your own Splunk** — a host URL and bearer token; on a working
  connection the same page re-points at your instance. The token lives only
  in page memory for that session: never `localStorage`, never the URL.
- **Live tail** — a checkbox that appends synthetic events every 2 s and
  rolls the grid's own filter forward with a `_time >= now-15m` condition;
  the adapter turns that into a moving `earliest_time` job parameter, so it
  is a real re-query, not a repaint.

`splunkAdapter` does not push `| stats` or `| timechart` (grouping is a
declared non-goal of the adapter), so the timeline, the KPI tiles and the
alarms strip each run their own search built from the same filter the
grid's last query sent. All of them go through the identical
`POST jobs` → status → `/results` → `DELETE` cycle the adapter uses, against
the mock or a real instance alike.

## Pointing it at a real Splunk

In the "Bring your own Splunk" panel, paste your instance's **management
endpoint** (`https://your-splunk:8089`, not Splunk Web's port) and a bearer
token, then Connect. The token should carry a **read-only role scoped to
the index** this demo searches (`index=security` by default); nothing here
writes to Splunk. A bad host or token shows a clear error and leaves the
demo index running.

**Cross-origin note.** The page calls the management port straight from the
browser, so Splunk must allow this page's origin: either add the origin
(`https://toclocoinc.github.io`, or `http://localhost:<port>` when running
locally) to `crossOriginSharingPolicy` in `server.conf` on your instance,
or put the management port behind your own reverse proxy that adds the
CORS headers and serves this page from the same origin. Without one of
those, the browser blocks the request before it reaches Splunk, and the
panel reports it as a failed connection.

## The mock's shape

`mock-splunk.js` answers the same REST surface (`POST .../jobs`, its status
endpoint, `/results`, `DELETE`) from an in-memory synthetic auth+firewall
index of about 50,000 events generated on load: `_time`, `src_ip`, `user`,
`action` (`allowed`/`blocked`/`failed_login`), `dest_port`, `sourcetype`
(`auth`/`firewall`), `country`. Three source IPs are seeded with
failed-login bursts so the alarms strip has something to show. The mock
parses the actual SPL filter expression the adapter emits (comparisons,
`AND`/`OR`/`NOT`, quoted literals with wildcards, `in` as a parenthesised
`OR`); it is not a general SPL implementation.

## Data

The synthetic index is ours: **CC0**, no attribution required. Nothing is
fetched from the network in the default mode.

## Grid features used

`splunkAdapter` + `createPushdownSource` (filter, sort and paging pushed as
SPL; `liftTimeBounds` for the moving time window), the filter row
(`filterRow: true`), `source.lastPlan()`, `createChart` with the `bar`
type, and the layout and KPI modules. Modules loaded: `layout`, `charts`,
`kpi`.

## Run it locally

Any static file server will do, for example:

```
npx serve .
```

or Python's built-in server:

```
python3 -m http.server
```

Open the page it prints. `?theme=light` forces the light theme; dark is
the default. No licence key is needed on localhost; a key is only required
once the page is published on a real address, which is why one appears in
`index.html` for this demo's own published address.

## Licence

The code in this repository is available under the MIT licence. See
[LICENSE](LICENSE).

Lattice Grid itself is a separate commercial product with its own terms. It
is free to use on localhost, with no key and no watermark, so a copy of
this repository runs unrestricted on your own machine. This demo carries a
key for its own published address only, which is why you will find one in
the source. Keys for your own sites come from
[latticegrid.dev](https://www.latticegrid.dev).

This demo is built on Lattice Grid 1.73.0.
