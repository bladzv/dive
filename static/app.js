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

  /* ── Shared modal component ────────────────────────────
   * Every modal in the app is a `.modal-backdrop > .modal-panel` pair (see
   * static/style.css), toggled via the `open` class. openModal()/closeModal()
   * are the single place that: move focus into the panel, trap Tab inside it
   * while open, and restore focus to whatever triggered it on close. State is
   * stashed directly on the backdrop element (`_triggerEl`, `_trapHandler`)
   * so this works for both static modals in base.html and ones created on
   * the fly (confirmModal below).
   */
  function _focusableIn(panel) {
    return Array.from(panel.querySelectorAll(
      'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )).filter((el) => el.offsetParent !== null);
  }

  function _trapTab(panel, e) {
    if (e.key !== 'Tab') return;
    const items = _focusableIn(panel);
    if (!items.length) { e.preventDefault(); return; }
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  function openModal(idOrEl) {
    const backdrop = typeof idOrEl === 'string' ? document.getElementById(idOrEl) : idOrEl;
    if (!backdrop) return;
    backdrop._triggerEl = document.activeElement;
    backdrop.classList.add('open');
    const panel = backdrop.querySelector('.modal-panel') || backdrop;
    const focusable = _focusableIn(panel);
    (focusable[0] || panel).focus();
    backdrop._trapHandler = (e) => _trapTab(panel, e);
    backdrop.addEventListener('keydown', backdrop._trapHandler);
  }

  function closeModal(idOrEl) {
    const backdrop = typeof idOrEl === 'string' ? document.getElementById(idOrEl) : idOrEl;
    if (!backdrop) return;
    backdrop.classList.remove('open');
    if (backdrop._trapHandler) {
      backdrop.removeEventListener('keydown', backdrop._trapHandler);
      backdrop._trapHandler = null;
    }
    const trigger = backdrop._triggerEl;
    backdrop._triggerEl = null;
    if (trigger && trigger.focus) trigger.focus();
  }

  /* Backdrop-click and Escape dismissal for every current and future
   * .modal-backdrop, wired once here instead of per-page. */
  document.addEventListener('click', function (e) {
    if (e.target.classList && e.target.classList.contains('modal-backdrop') && e.target.classList.contains('open')) {
      closeModal(e.target);
    }
  });

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    document.querySelectorAll('.modal-backdrop.open').forEach((m) => closeModal(m));
  });

  /* Minimal confirm modal reusing the shared component — covers the common
   * "sure you want to do X?" case that findings/secrets/settings each used
   * to build inline with their own markup and no dialog semantics.
   */
  function confirmModal(message, onConfirm, opts) {
    opts = opts || {};
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    const titleId = 'confirm-modal-title-' + Math.floor(Math.random() * 1e9);
    backdrop.innerHTML = `
      <div class="modal-panel" role="dialog" aria-modal="true" aria-labelledby="${titleId}" tabindex="-1">
        <p id="${titleId}" style="font-weight:600;margin-bottom:0.5rem">${escapeHtml(message)}</p>
        <div style="display:flex;justify-content:flex-end;gap:0.5rem;margin-top:1rem">
          <button type="button" class="btn btn-outline btn-sm" data-role="cancel">Cancel</button>
          <button type="button" class="btn btn-sm ${opts.dangerous ? 'btn-danger' : 'btn-primary'}" data-role="confirm">${escapeHtml(opts.confirmLabel || 'Confirm')}</button>
        </div>
      </div>`;
    document.body.appendChild(backdrop);

    const close = () => {
      closeModal(backdrop);
      backdrop.remove();
    };
    backdrop.querySelector('[data-role="cancel"]').addEventListener('click', close);
    backdrop.querySelector('[data-role="confirm"]').addEventListener('click', () => {
      close();
      onConfirm();
    });
    openModal(backdrop);
    backdrop.querySelector('[data-role="confirm"]').focus();
  }

  window.DIVE = {
    apiFetch, showToast, timeAgo, timeUntil, escapeHtml,
    setPageSize, toggleBookmark, confirmModal, openModal, closeModal,
  };
})();
