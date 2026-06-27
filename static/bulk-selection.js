/* Shared bulk row-selection helpers for the findings & secrets tables.
 *
 * Loaded once via <script src> and reused across PJAX navigations (the router
 * skips re-loading an already-present src), so these globals persist between
 * page swaps. Each page's inline script calls initBulkSelection() on load to
 * reset the selection for the freshly rendered table.
 *
 * The page-specific bulkAction(action) (different API endpoint per page) stays
 * in each template.
 */
var _selected = new Set();

function initBulkSelection() {
  _selected = new Set();
  _updateBulkBar();
}

function toggleRow(id, checked) {
  if (checked) _selected.add(id);
  else _selected.delete(id);
  _updateBulkBar();
}

function toggleAll(checked) {
  document.querySelectorAll('.row-check').forEach(cb => {
    cb.checked = checked;
    const id = parseInt(cb.value, 10);
    if (checked) _selected.add(id);
    else _selected.delete(id);
  });
  _updateBulkBar();
}

function _updateBulkBar() {
  const inline = document.getElementById('bulk-inline');
  const countEl = document.getElementById('bulk-count');
  const allCb = document.getElementById('select-all');
  if (!inline || !countEl) return;  // page without a bulk toolbar
  inline.style.display = _selected.size > 0 ? 'inline-flex' : 'none';
  countEl.textContent = _selected.size + ' selected';
  const allCbs = document.querySelectorAll('.row-check');
  if (allCb) {
    allCb.checked = _selected.size > 0 && _selected.size === allCbs.length;
    allCb.indeterminate = _selected.size > 0 && _selected.size < allCbs.length;
  }
}

function applyRepoFilter(repo) {
  const params = new URLSearchParams(window.location.search);
  if (repo) params.set('repo', repo);
  else params.delete('repo');
  params.delete('page');
  window.location = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
}

function setPageSize(size) {
  const params = new URLSearchParams(window.location.search);
  params.set('per_page', size);
  params.set('page', '1');
  window.location = window.location.pathname + '?' + params.toString();
}
