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
    // role="alert" (implicit assertive live region) for errors so screen
    // readers interrupt with them immediately; role="status" (polite) is
    // the default set once in base.html's markup for everything else.
    t.setAttribute('role', type === 'error' ? 'alert' : 'status');
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

  /* ── Inline field validation ───────────────────────────
   * Mirrors login.html's .login-error pattern (a role="alert" message tied
   * to the field via aria-describedby) instead of the toast-only, post-hoc
   * validation used everywhere else. Creates the <p class="field-error">
   * on demand right after the input, so call sites don't need to add
   * markup for every field up front.
   */
  function setFieldError(input, message) {
    input.setAttribute('aria-invalid', 'true');
    const id = input.id ? input.id + '-error' : null;
    let el = id ? document.getElementById(id) : input._fieldErrorEl;
    if (!el) {
      el = document.createElement('p');
      el.className = 'field-error';
      el.setAttribute('role', 'alert');
      if (id) el.id = id;
      else input._fieldErrorEl = el;
      input.insertAdjacentElement('afterend', el);
    }
    el.textContent = message;
    if (id) input.setAttribute('aria-describedby', id);
  }

  function clearFieldError(input) {
    input.removeAttribute('aria-invalid');
    input.removeAttribute('aria-describedby');
    const id = input.id ? input.id + '-error' : null;
    const el = id ? document.getElementById(id) : input._fieldErrorEl;
    if (el) el.remove();
    input._fieldErrorEl = null;
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

  /* ── Shared menu/dropdown component ────────────────────
   * Every consolidated control (export, state filter, row actions, column
   * headers) is one `.menu` element: a `.menu-trigger` button plus a
   * `.menu-panel[role=menu]` of `[role=menuitem]` children, toggled via the
   * `open` class (see static/style.css). Two listeners registered once here
   * — a click listener and a keydown listener — drive every menu, current
   * and future, and survive PJAX navigation because this file loads without
   * data-pjax (see base.html's runPageScripts).
   *
   * Menus inside a table need `data-menu="portal"`: `.table-wrap` is
   * `overflow-x:auto` and the findings/secrets card is `overflow:hidden`, so
   * a plain `position:absolute` panel gets clipped (the same trap CLAUDE.md
   * documents for [data-tip] tooltips). Portal mode moves the panel into
   * #menu-layer (a body-level div, see base.html) and positions it
   * `position:fixed` from the trigger's bounding rect instead.
   */
  const _menuState = new WeakMap();
  let _openMenuEl = null;

  function _ensureMenuState(menuEl) {
    let st = _menuState.get(menuEl);
    if (!st) {
      const panel = menuEl.querySelector('.menu-panel');
      st = {
        panel,
        homeParent: panel ? panel.parentNode : null,
        homeNext: panel ? panel.nextSibling : null,
        portal: menuEl.dataset.menu === 'portal',
        scrollHandler: null,
        resizeHandler: null,
      };
      _menuState.set(menuEl, st);
    }
    return st;
  }

  function _menuItems(panel) {
    if (!panel) return [];
    // getClientRects() (not offsetParent, which is always null for
    // position:fixed descendants — i.e. every portal-mode panel) is what
    // correctly reports "actually rendered" for both positioning schemes.
    return Array.from(panel.querySelectorAll('[role="menuitem"]')).filter(
      (el) => el.getClientRects().length > 0
    );
  }

  function _positionPortalPanel(menuEl, st) {
    const trigger = menuEl.querySelector('.menu-trigger');
    const panel = st.panel;
    if (!trigger || !panel) return;
    const rect = trigger.getBoundingClientRect();
    panel.classList.remove('anchor-right');
    panel.style.position = 'fixed';
    panel.style.left = rect.left + 'px';
    panel.style.right = 'auto';
    panel.style.top = (rect.bottom + 6) + 'px';
    const pw = panel.offsetWidth;
    const ph = panel.offsetHeight;
    if (rect.left + pw > window.innerWidth - 8) {
      panel.style.left = 'auto';
      panel.style.right = Math.max(8, window.innerWidth - rect.right) + 'px';
      panel.classList.add('anchor-right');
    }
    let top = rect.bottom + 6;
    if (top + ph > window.innerHeight - 8 && rect.top - ph - 6 > 0) {
      top = rect.top - ph - 6;
    }
    panel.style.top = top + 'px';
  }

  function openMenu(menuEl) {
    if (!menuEl || menuEl.classList.contains('open')) return;
    closeAllMenus();
    const st = _ensureMenuState(menuEl);
    if (!st.panel) return;
    const trigger = menuEl.querySelector('.menu-trigger');
    if (st.portal) {
      const layer = document.getElementById('menu-layer');
      if (layer) layer.appendChild(st.panel);
      st.panel.classList.add('is-open');
    }
    menuEl.classList.add('open');
    if (trigger) trigger.setAttribute('aria-expanded', 'true');
    if (st.portal) {
      _positionPortalPanel(menuEl, st);
      st.scrollHandler = () => _positionPortalPanel(menuEl, st);
      st.resizeHandler = st.scrollHandler;
      window.addEventListener('scroll', st.scrollHandler, true);
      window.addEventListener('resize', st.resizeHandler);
    } else {
      st.panel.classList.remove('anchor-right');
      const rect = st.panel.getBoundingClientRect();
      if (rect.right > window.innerWidth - 8) st.panel.classList.add('anchor-right');
    }
    _openMenuEl = menuEl;
    const items = _menuItems(st.panel);
    if (items[0]) items[0].focus();
  }

  function closeMenu(menuEl, opts) {
    opts = opts || {};
    if (!menuEl || !menuEl.classList.contains('open')) return;
    const st = _menuState.get(menuEl);
    const trigger = menuEl.querySelector('.menu-trigger');
    const focusWasInside = !!(st && st.panel &&
      (st.panel.contains(document.activeElement) || document.activeElement === trigger));
    menuEl.classList.remove('open');
    if (trigger) trigger.setAttribute('aria-expanded', 'false');
    if (st) {
      if (st.portal && st.panel) {
        st.panel.classList.remove('is-open', 'anchor-right');
        st.panel.style.position = '';
        st.panel.style.top = '';
        st.panel.style.left = '';
        st.panel.style.right = '';
        if (st.homeParent) st.homeParent.insertBefore(st.panel, st.homeNext);
      } else if (st.panel) {
        st.panel.classList.remove('anchor-right');
      }
      if (st.scrollHandler) { window.removeEventListener('scroll', st.scrollHandler, true); st.scrollHandler = null; }
      if (st.resizeHandler) { window.removeEventListener('resize', st.resizeHandler); st.resizeHandler = null; }
    }
    if (_openMenuEl === menuEl) _openMenuEl = null;
    if ((opts.restoreFocus || focusWasInside) && trigger) trigger.focus();
  }

  function closeAllMenus() {
    document.querySelectorAll('.menu.open').forEach((m) => closeMenu(m));
  }

  document.addEventListener('click', function (e) {
    const trigger = e.target.closest('.menu-trigger');
    if (trigger && trigger.closest('.menu')) {
      const menuEl = trigger.closest('.menu');
      if (menuEl.classList.contains('open')) closeMenu(menuEl);
      else openMenu(menuEl);
      return;
    }
    const panel = e.target.closest('.menu-panel');
    if (panel) {
      // A click anywhere inside the panel is never "outside" — but
      // activating an item closes its menu (unless it opts out via
      // data-keep-open, for multi-select filter menus).
      const item = e.target.closest('[role="menuitem"]');
      if (item && !item.hasAttribute('data-keep-open') && _openMenuEl) {
        closeMenu(_openMenuEl);
      }
      return;
    }
    if (_openMenuEl) closeAllMenus();
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      if (_openMenuEl) closeMenu(_openMenuEl, { restoreFocus: true });
      return;
    }
    if (!_openMenuEl) return;
    const st = _menuState.get(_openMenuEl);
    const panel = st && st.panel;
    if (!panel) return;
    const trigger = _openMenuEl.querySelector('.menu-trigger');
    const withinMenu = panel.contains(document.activeElement) || document.activeElement === trigger;
    if (!withinMenu) return;
    if (e.key === 'Tab') { closeMenu(_openMenuEl); return; }
    const items = _menuItems(panel);
    if (!items.length) return;
    const idx = items.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); items[(idx + 1 + items.length) % items.length].focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); items[(idx - 1 + items.length) % items.length].focus(); }
    else if (e.key === 'Home') { e.preventDefault(); items[0].focus(); }
    else if (e.key === 'End') { e.preventDefault(); items[items.length - 1].focus(); }
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
    setFieldError, clearFieldError,
    openMenu, closeMenu, closeAllMenus,
  };
})();
