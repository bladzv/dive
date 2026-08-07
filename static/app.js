/* static/app.js — shared page utilities.
 *
 * Loaded once from base.html WITHOUT data-pjax, so it persists across
 * in-app navigation (the pjax router in base.html only re-executes scripts
 * that follow the #page-scripts-fence sentinel). Exposed under window.DIVE
 * so every page's inline script calls DIVE.<fn>(...) instead of redefining
 * its own copy — setPageSize, toggleBookmark, and HTML-escaping were each
 * previously implemented three times, with subtly different (and in two
 * cases unescaped, XSS-prone) behavior.
 */
(function () {
  const RUN_TOKEN_META = document.querySelector('meta[name="run-token"]');
  const RUN_TOKEN = RUN_TOKEN_META ? RUN_TOKEN_META.content : '';

  function apiFetch(url, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = Object.assign({}, options.headers);
    if (method !== 'GET' && method !== 'HEAD') {
      headers['X-Run-Token'] = RUN_TOKEN;
    }
    return fetch(url, Object.assign({ credentials: 'same-origin' }, options, { headers }));
  }

  function showToast(msg, type = 'info') {
    const t = document.getElementById('toast');
    if (!t) return;
    t.textContent = msg;
    t.className = 'show toast-' + type;
    clearTimeout(t._timer);
    t._timer = setTimeout(() => { t.className = ''; }, 3500);
  }

  function timeAgo(iso) {
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60)    return 'just now';
    if (diff < 3600)  return Math.floor(diff / 60)   + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }

  function timeUntil(iso) {
    const diff = (new Date(iso).getTime() - Date.now()) / 1000;
    if (diff <= 0)     return 'soon';
    if (diff < 3600)   return Math.ceil(diff / 60)   + 'm';
    if (diff < 86400)  return Math.floor(diff / 3600) + 'h';
    return Math.floor(diff / 86400) + 'd';
  }

  function escapeHtml(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
  }

  function setPageSize(size) {
    const params = new URLSearchParams(window.location.search);
    params.set('per_page', size);
    params.set('page', '1');
    window.location = window.location.pathname + '?' + params.toString();
  }

  function toggleBookmark(itemId) {
    return apiFetch('/api/news/' + itemId + '/bookmark', { method: 'POST' })
      .then(r => r.json());
  }

  /* Minimal confirm modal reusing the existing .modal-backdrop/.modal-panel
   * classes (see static/style.css) — a fuller version with a focus trap and
   * ARIA wiring lands in the modal-consolidation pass; this covers the
   * common "sure you want to do X?" case that findings/secrets/settings
   * each built inline with their own markup and no dialog semantics.
   */
  function confirmModal(message, onConfirm, opts) {
    opts = opts || {};
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    backdrop.innerHTML = `
      <div class="modal-panel" role="dialog" aria-modal="true" aria-label="${escapeHtml(opts.title || 'Confirm')}">
        <p style="font-weight:600;margin-bottom:0.5rem">${escapeHtml(message)}</p>
        <div style="display:flex;justify-content:flex-end;gap:0.5rem;margin-top:1rem">
          <button type="button" class="btn btn-outline btn-sm" data-role="cancel">Cancel</button>
          <button type="button" class="btn btn-sm ${opts.dangerous ? 'btn-danger' : 'btn-primary'}" data-role="confirm">${escapeHtml(opts.confirmLabel || 'Confirm')}</button>
        </div>
      </div>`;
    document.body.appendChild(backdrop);

    const triggerEl = document.activeElement;
    const close = () => {
      backdrop.remove();
      if (triggerEl && triggerEl.focus) triggerEl.focus();
    };
    backdrop.addEventListener('click', (e) => { if (e.target === backdrop) close(); });
    backdrop.querySelector('[data-role="cancel"]').addEventListener('click', close);
    backdrop.querySelector('[data-role="confirm"]').addEventListener('click', () => {
      close();
      onConfirm();
    });
    backdrop.querySelector('[data-role="confirm"]').focus();
  }

  window.DIVE = {
    apiFetch, showToast, timeAgo, timeUntil, escapeHtml,
    setPageSize, toggleBookmark, confirmModal,
  };
})();
