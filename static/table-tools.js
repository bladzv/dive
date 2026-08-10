/* static/table-tools.js — sortable table headers + per-column filter menus.
 *
 * Loaded with data-pjax from findings.html, secrets.html, logs.html,
 * personal.html, weekly.html, so it re-runs on every in-app navigation to
 * one of those pages (see base.html's runPageScripts). Each run operates on
 * a freshly-swapped .page-main, so there is no cross-navigation state to
 * clean up — the per-<th> `.th-flex` check below just guards against this
 * file's own initTableTools() being called more than once for the same DOM
 * (harmless, but avoids double-wrapping a header's content).
 *
 * Two modes, set via `data-mode` on the <table>:
 *   - "server" (findings, secrets, logs): clicking a header (or its column
 *     menu's Sort items) rewrites the `sort`/`direction` query params and
 *     navigates — the real ordering happens in dive/db.py's whitelisted
 *     ORDER BY (see _order_by()), because these tables are paginated and a
 *     client-side sort would only ever reorder the current page, not the
 *     whole dataset. These tables also get the column menu (this file's
 *     addColumnMenu()) — findings/secrets/logs get Sort ascending/descending
 *     always, plus a filter section on the columns that have one backed by
 *     a real query param (`data-filter` on the <th>: repo/severity/level).
 *   - "client" (personal, weekly): these two tables render every row with
 *     no pagination, so sorting is just a plain in-DOM row reorder. No
 *     column menu — the plain header click (cycle) is the only control,
 *     since there's no server-side filter to expose for either table.
 *
 * Column widths (both modes): a 6px drag handle on each <th>'s right edge,
 * persisted to localStorage under `dive.cols.<data-table-tools value>` so
 * they survive reload and navigation. Desktop-only — .table-stack (below
 * 700px) hides <thead> entirely, where a stored pixel width is meaningless.
 */
(function () {
  const RESIZE_MIN_WIDTH = 60;
  const DESKTOP_QUERY = window.matchMedia('(min-width: 701px)');

  function initTableTools() {
    document.querySelectorAll('[data-table-tools]').forEach(initTable);
  }

  function initTable(table) {
    const mode = table.dataset.mode || 'server';
    const headers = Array.from(table.querySelectorAll('thead th[data-col]'));
    headers.forEach((th) => {
      wrapHeaderForSort(th, table, mode);
      if (mode === 'server') addColumnMenu(th, table);
    });
    if (mode === 'server') applyAriaSortFromURL(table, headers);
    initColumnResize(table, headers);
  }

  function _thFlex(th) {
    let flex = th.querySelector('.th-flex');
    if (!flex) {
      flex = document.createElement('div');
      flex.className = 'th-flex';
      th.appendChild(flex);
    }
    return flex;
  }

  function wrapHeaderForSort(th, table, mode) {
    if (th.querySelector('.th-sort-btn')) return; // already wrapped
    const label = th.textContent.trim();
    th.textContent = '';
    th.setAttribute('aria-sort', 'none');
    const flex = _thFlex(th);

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'th-sort-btn';
    btn.setAttribute('aria-label', 'Sort by ' + label);

    const labelSpan = document.createElement('span');
    labelSpan.textContent = label;
    btn.appendChild(labelSpan);

    const caret = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    caret.setAttribute('class', 'th-sort-caret');
    caret.setAttribute('viewBox', '0 0 12 12');
    caret.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M3 4.5 6 7.5 9 4.5');
    path.setAttribute('stroke', 'currentColor');
    path.setAttribute('stroke-width', '1.5');
    path.setAttribute('fill', 'none');
    caret.appendChild(path);
    btn.appendChild(caret);

    flex.appendChild(btn);
    btn.addEventListener('click', () => {
      if (mode === 'client') clientSort(table, th);
      else serverSort(table, th);
    });
  }

  /* unsorted -> descending -> ascending -> unsorted */
  function _cycle(current) {
    if (current === 'none') return 'descending';
    if (current === 'descending') return 'ascending';
    return 'none';
  }

  function _navigate(mutate) {
    const params = new URLSearchParams(window.location.search);
    mutate(params);
    params.delete('page');
    const qs = params.toString();
    window.location = window.location.pathname + (qs ? '?' + qs : '');
  }

  function serverSort(table, th) {
    const next = _cycle(th.getAttribute('aria-sort'));
    _navigate((params) => {
      if (next === 'none') {
        params.delete('sort');
        params.delete('direction');
      } else {
        params.set('sort', th.dataset.col);
        params.set('direction', next === 'ascending' ? 'asc' : 'desc');
      }
    });
  }

  /* Same as serverSort but a fixed direction — used by the column menu's
   * explicit "Sort ascending"/"Sort descending" items instead of cycling. */
  function forceSort(th, direction) {
    _navigate((params) => {
      params.set('sort', th.dataset.col);
      params.set('direction', direction === 'ascending' ? 'asc' : 'desc');
    });
  }

  function applyParam(name, value) {
    _navigate((params) => {
      if (value) params.set(name, value);
      else params.delete(name);
    });
  }

  function applyAriaSortFromURL(table, headers) {
    const params = new URLSearchParams(window.location.search);
    const sort = params.get('sort') || table.dataset.defaultSort;
    const direction = (params.get('direction') || table.dataset.defaultDirection || 'desc')
      .toLowerCase();
    headers.forEach((th) => th.setAttribute('aria-sort', 'none'));
    if (!sort) return;
    const match = headers.find((th) => th.dataset.col === sort);
    if (match) match.setAttribute('aria-sort', direction === 'asc' ? 'ascending' : 'descending');
  }

  /* ── Per-column filter/sort menu (findings, secrets, logs only) ───────
   * Sheets-style: every sortable column gets the dropdown (Sort ascending /
   * Sort descending); a `data-filter` value on the <th> ("repo" | "severity"
   * | "level") additionally appends a filter section. Options for "repo"
   * are read straight off the page's own repo <select> (in the filter bar)
   * rather than re-threaded through Jinja — one source of truth for what
   * repos exist on this page. */
  function addColumnMenu(th, table) {
    if (th.querySelector('.th-menu')) return; // already built
    const flex = _thFlex(th);
    const filterKind = th.dataset.filter;

    const menu = document.createElement('div');
    menu.className = 'menu th-menu';
    menu.dataset.menu = 'portal';

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'th-menu-trigger menu-trigger';
    trigger.setAttribute('aria-haspopup', 'menu');
    trigger.setAttribute('aria-expanded', 'false');
    trigger.setAttribute('aria-label', 'Sort and filter ' + th.textContent.trim());
    trigger.innerHTML =
      '<svg viewBox="0 0 12 12" aria-hidden="true">' +
      '<path d="M2.5 3.5h7L6.7 7v2.2L5.3 8.4V7L2.5 3.5z" ' +
      'fill="currentColor"/></svg>';

    const panel = document.createElement('div');
    panel.className = 'menu-panel';
    panel.setAttribute('role', 'menu');

    let i = 0;
    function addItem(label, onClick, current) {
      const item = document.createElement('button');
      item.type = 'button';
      item.setAttribute('role', 'menuitem');
      item.style.setProperty('--i', i++);
      item.textContent = label;
      if (current) item.setAttribute('aria-current', 'true');
      item.addEventListener('click', onClick);
      panel.appendChild(item);
    }
    function addSep() {
      const sep = document.createElement('div');
      sep.className = 'menu-sep';
      sep.setAttribute('role', 'separator');
      panel.appendChild(sep);
    }

    addItem('Sort ascending', () => forceSort(th, 'ascending'));
    addItem('Sort descending', () => forceSort(th, 'descending'));

    if (filterKind) {
      addSep();
      const options = _filterOptions(filterKind);
      const current = new URLSearchParams(window.location.search).get(filterKind) || '';
      let anyActive = false;
      options.forEach((opt) => {
        const isCurrent = opt.value === current;
        if (isCurrent && opt.value) anyActive = true;
        addItem(opt.label, () => applyParam(filterKind, opt.value), isCurrent);
      });
      trigger.classList.toggle('has-filter', anyActive);
    }

    addSep();
    addItem('Reset column widths', () => {
      const allHeaders = Array.from(table.querySelectorAll('thead th[data-col]'));
      _clearWidths(table.dataset.tableTools, table, allHeaders);
    });

    menu.appendChild(trigger);
    menu.appendChild(panel);
    flex.appendChild(menu);
  }

  function _filterOptions(kind) {
    if (kind === 'repo') {
      const select = document.querySelector('select[aria-label="Filter by repository"]');
      if (!select) return [];
      return Array.from(select.options).map((o) => ({
        value: o.value,
        label: o.textContent.trim(),
      }));
    }
    if (kind === 'severity') {
      return [
        { value: '', label: 'All severities' },
        { value: 'critical', label: 'Critical' },
        { value: 'high', label: 'High' },
        { value: 'medium', label: 'Medium' },
        { value: 'low', label: 'Low' },
        { value: 'unknown', label: 'Unknown' },
      ];
    }
    if (kind === 'level') {
      return [
        { value: '', label: 'All' },
        { value: 'INFO', label: 'INFO' },
        { value: 'WARNING', label: 'WARNING' },
        { value: 'ERROR', label: 'ERROR' },
      ];
    }
    return [];
  }

  /* ── Client-side sort (personal.html, weekly.html) ─────────────────────
   * Neither table is paginated — every row is already in the DOM, so this
   * is a plain in-place reorder. Numeric-aware: prefers a td's
   * data-sort-value (set server-side where the visible text isn't sortable
   * as-is, e.g. a formatted CVSS string or a severity badge), falling back
   * to the cell's text content. */
  function clientSort(table, th) {
    const tbody = table.querySelector('tbody');
    if (!tbody) return;
    const headers = Array.from(table.querySelectorAll('thead th[data-col]'));
    // Toggle only (no "unsorted" state — a client-rendered table always
    // shows some order, so there's no equivalent of the server mode's
    // "remove the params" reset). Starts at descending on a fresh column,
    // same first-click direction as serverSort's unsorted->descending.
    const next = th.getAttribute('aria-sort') === 'descending' ? 'ascending' : 'descending';
    headers.forEach((h) => h.setAttribute('aria-sort', 'none'));
    th.setAttribute('aria-sort', next);

    const idx = Array.from(th.parentElement.children).indexOf(th);
    const dir = next === 'ascending' ? 1 : -1;
    const rows = Array.from(tbody.querySelectorAll('tr'));

    rows.sort((a, b) => {
      const av = _cellValue(a, idx);
      const bv = _cellValue(b, idx);
      if (av == null && bv == null) return 0;
      if (av == null) return 1; // nulls last regardless of direction
      if (bv == null) return -1;
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
    rows.forEach((r) => tbody.appendChild(r));
  }

  function _cellValue(row, idx) {
    const cell = row.children[idx];
    if (!cell) return null;
    if (cell.dataset.sortValue !== undefined) {
      if (cell.dataset.sortValue === '') return null;
      const n = Number(cell.dataset.sortValue);
      return Number.isNaN(n) ? cell.dataset.sortValue : n;
    }
    const text = cell.textContent.trim();
    if (text === '' || text === '—') return null;
    const n = Number(text.replace(/[, ]/g, ''));
    return Number.isNaN(n) ? text : n;
  }

  /* ── Column resize ─────────────────────────────────────────────────── */
  function _widthsKey(tableKey) {
    return 'dive.cols.' + tableKey;
  }

  function _loadWidths(tableKey) {
    try {
      return JSON.parse(window.localStorage.getItem(_widthsKey(tableKey)) || '{}');
    } catch (_e) {
      return {};
    }
  }

  function _saveWidths(tableKey, widths) {
    try {
      window.localStorage.setItem(_widthsKey(tableKey), JSON.stringify(widths));
    } catch (_e) {
      /* localStorage unavailable (private mode, quota) — resize still works
         for the current page load, it just won't persist. */
    }
  }

  function _setWidth(tableKey, col, px) {
    const widths = _loadWidths(tableKey);
    if (px == null) delete widths[col];
    else widths[col] = px;
    _saveWidths(tableKey, widths);
  }

  /* `<table>` here defaults to table-layout: auto (style.css sets
   * min-width: 780px and relies on content to size columns), so a lone
   * <th style="width:...px"> is only ever a hint the auto-layout algorithm
   * is free to override based on cell content across the whole column —
   * confirmed live: dragging a handle updated the inline style but the
   * rendered column didn't move. table-layout: fixed is the only way to
   * make an explicit width authoritative, but switching a table into fixed
   * layout unconditionally would also make EVERY other column rigid
   * (wrapping/overflowing instead of sizing to content) for tables nobody
   * ever tried to resize. So: stay in auto layout until the first resize,
   * then _freezeColumnWidths() snapshots every column's current rendered
   * width into a <colgroup> and flips on .tt-fixed — visually seamless
   * (nothing moves) because the frozen widths ARE the current widths, and
   * only the dragged column's <col> changes from then on. */
  function _ensureColgroup(table) {
    let colgroup = table.querySelector(':scope > colgroup.tt-colgroup');
    if (colgroup) return colgroup;
    const headerRow = table.querySelector('thead tr');
    const count = headerRow ? headerRow.children.length : 0;
    colgroup = document.createElement('colgroup');
    colgroup.className = 'tt-colgroup';
    for (let i = 0; i < count; i++) colgroup.appendChild(document.createElement('col'));
    table.insertBefore(colgroup, table.querySelector('thead'));
    return colgroup;
  }

  function _colForTh(table, th) {
    const idx = Array.from(th.parentElement.children).indexOf(th);
    const colgroup = _ensureColgroup(table);
    return colgroup.children[idx] || null;
  }

  function _freezeColumnWidths(table) {
    if (table.classList.contains('tt-fixed')) return; // already frozen
    const colgroup = _ensureColgroup(table);
    const ths = Array.from(table.querySelectorAll('thead tr th'));
    ths.forEach((th, i) => {
      const col = colgroup.children[i];
      if (!col) return;
      col.style.width = Math.round(th.getBoundingClientRect().width) + 'px';
    });
    table.classList.add('tt-fixed');
  }

  function _clearWidths(tableKey, table, headers) {
    _saveWidths(tableKey, {});
    table.classList.remove('tt-fixed');
    const colgroup = table.querySelector(':scope > colgroup.tt-colgroup');
    if (colgroup) {
      Array.from(colgroup.children).forEach((col) => {
        col.style.width = '';
      });
    }
    headers.forEach((th) => {
      th.style.width = '';
    });
  }

  function _applyStoredWidths(tableKey, table, headers) {
    if (!DESKTOP_QUERY.matches) return; // .table-stack hides <thead>; irrelevant below 700px
    const widths = _loadWidths(tableKey);
    if (!Object.keys(widths).length) return; // nothing customized — stay in auto layout
    _freezeColumnWidths(table);
    headers.forEach((th) => {
      const px = widths[th.dataset.col];
      if (!px) return;
      const col = _colForTh(table, th);
      if (col) col.style.width = px + 'px';
    });
  }

  function initColumnResize(table, headers) {
    const tableKey = table.dataset.tableTools;
    if (!tableKey) return;
    const resizable = headers.filter((th) => !('noResize' in th.dataset));

    _applyStoredWidths(tableKey, table, resizable);
    // Re-check on viewport crossing the breakpoint (not just at load).
    DESKTOP_QUERY.addEventListener('change', () => _applyStoredWidths(tableKey, table, resizable));

    resizable.forEach((th) => addResizeHandle(th, table, tableKey));
  }

  function addResizeHandle(th, table, tableKey) {
    if (th.querySelector('.col-resize')) return; // already wired
    const handle = document.createElement('div');
    handle.className = 'col-resize';
    th.appendChild(handle);

    handle.addEventListener('dblclick', (e) => {
      e.stopPropagation();
      const col = _colForTh(table, th);
      if (col) col.style.width = '';
      th.style.width = '';
      _setWidth(tableKey, th.dataset.col, null);
    });

    handle.addEventListener('pointerdown', (e) => {
      if (!DESKTOP_QUERY.matches) return;
      e.preventDefault();
      e.stopPropagation();
      _freezeColumnWidths(table);
      const col = _colForTh(table, th);
      if (!col) return;
      const startX = e.clientX;
      const startWidth = col.getBoundingClientRect().width;
      try {
        handle.setPointerCapture(e.pointerId);
      } catch (_e) {
        /* Some pointer sources (synthetic events, certain touch paths)
           can't be captured — dragging still works via the plain
           listeners below, capture is just an enhancement. */
      }
      handle.classList.add('dragging');

      function onMove(ev) {
        const next = Math.round(startWidth + (ev.clientX - startX));
        col.style.width = Math.max(RESIZE_MIN_WIDTH, next) + 'px';
      }
      function onUp() {
        handle.classList.remove('dragging');
        handle.removeEventListener('pointermove', onMove);
        _setWidth(tableKey, th.dataset.col, Math.round(col.getBoundingClientRect().width));
      }

      handle.addEventListener('pointermove', onMove);
      handle.addEventListener('pointerup', onUp, { once: true });
    });
  }

  initTableTools();
})();
