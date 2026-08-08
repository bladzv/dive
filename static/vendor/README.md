# Vendored third-party JavaScript

Self-hosted so `/history` makes zero third-party network requests. Previously
loaded from `https://cdn.jsdelivr.net/npm/chart.js@4.4.0/...` with no
integrity hash and no offline fallback — if jsdelivr was unreachable, the
page rendered permanently blank chart cards.

| File | Library | Version | License |
|---|---|---|---|
| `chart.umd.min.js` | [Chart.js](https://www.chartjs.org) | 4.5.1 | MIT |

Sourced from a local `node_modules/chart.js` install (the app's own code
targets the 4.4.x API, which 4.5.1 is backward-compatible with).

To upgrade: replace this file with a newer `chart.umd.min.js` build and
update the version in this table. No code changes needed — `templates/
history.html` loads it via `<script src="/static/vendor/chart.umd.min.js">`.
