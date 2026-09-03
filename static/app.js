/* static/app.js — shared page utilities.
 *
 * Loaded once from base.html WITHOUT data-pjax, so it persists across
 * in-app navigation (the pjax router in base.html only re-executes scripts
 * that follow the #page-scripts-fence sentinel). Exposed under window.DIVE
 * so every page's inline script calls DIVE.<fn>(...) instead of redefining
 * its own copy — toggleBookmark and HTML-escaping were each previously
 * implemented three times, with subtly different (and in some cases
 * unescaped, XSS-prone) behavior. (setPageSize used to be here too; the
 * per-page controls it drove are now ui.param_menu link menus, built
 * server-side with no client-side duplication to drift.)
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

  /* POST an action endpoint and resolve with its parsed JSON body, or reject
   * with an Error whose `.status` carries the HTTP status code. Every row
   * action (acknowledge/resolve/reopen/markFP/…) used to hand-roll this
   * apiFetch → check r.ok → r.json() → throw chain; centralizing it here is
   * what makes the 404 case (see submitButton below) checkable in one place
   * instead of five near-identical copies. */
  function postAction(url, body) {
    const opts = { method: 'POST' };
    if (body !== undefined) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    }
    return apiFetch(url, opts).then((r) => {
      return r
        .json()
        .catch(() => null)
        .then((data) => {
          if (!r.ok) {
            const err = new Error((data && data.detail) || 'Request failed');
            err.status = r.status;
            throw err;
          }
          return data;
        });
    });
  }

  /* Drive a button through label → loading → checkmark for an in-flight
   * action, replacing a blind `setTimeout(refresh, 700)` with an actual
   * confirmation. Reuses .btn.is-loading (already used elsewhere) for the
   * pending state rather than adding a separate bouncing-dots animation,
   * which is one more thing running on a Pi for the same information.
   *
   * On success the checkmark is held for `holdMs` (default 550 — long
   * enough for the stroke-draw transition below to finish and register)
   * before opts.onSuccess fires, so a caller that closes a menu or starts
   * an undo snackbar there does so only once the confirmation was actually
   * visible, not the instant the network request resolved.
   *
   * `promise` must already be the in-flight request (e.g. from
   * DIVE.postAction) — this function only owns the button's visual state,
   * not the request itself. */
  function submitButton(btn, promise, opts) {
    opts = opts || {};
    const holdMs = opts.holdMs != null ? opts.holdMs : 550;
    const originalHTML = btn.innerHTML;
    btn.disabled = true;
    btn.classList.add('is-loading');
    return promise
      .then((result) => {
        btn.classList.remove('is-loading');
        btn.classList.add('is-done');
        btn.innerHTML = '<svg class="btn-check-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-check"/></svg>';
        // Force a layout flush so the browser registers stroke-dashoffset's
        // starting value before .drawn changes it — otherwise the two
        // states land in the same frame and there is nothing to transition.
        void btn.offsetWidth;
        btn.classList.add('drawn');
        return new Promise((resolve) => setTimeout(() => resolve(result), holdMs));
      })
      .then((result) => {
        if (opts.onSuccess) opts.onSuccess(result);
        return result;
      })
      .catch((err) => {
        btn.classList.remove('is-loading', 'is-done', 'drawn');
        btn.disabled = false;
        btn.innerHTML = originalHTML;
        // Deliberately not re-thrown: onError (or the default toast) is the
        // one place this error gets handled, and no caller chains anything
        // after submitButton() — re-throwing here just turned every error
        // path into an unhandled promise rejection in the console.
        if (opts.onError) opts.onError(err);
        else showToast((err && err.message) || 'Request failed', 'error');
      });
  }

  const REDUCE_MOTION = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let _snackbarEl = null;

  /* A single undo snackbar at a time — a second action while one is showing
   * replaces it rather than stacking, since only the most recent action is
   * undoable in this UI (there is no undo history). */
  function _dismissSnackbar() {
    if (_snackbarEl) {
      _snackbarEl.remove();
      _snackbarEl = null;
    }
  }

  /* Show "<message> [Undo]" with a draining window (default 3s) during
   * which `onUndo` can still be called. `opts.onExpire` fires if the window
   * closes without Undo being clicked — callers use it to actually refresh
   * the table, so the row visibly stays put for the whole undo window
   * rather than vanishing (or the list re-sorting under it) the instant the
   * action fires.
   *
   * The drain bar is the only indication of remaining time, and the global
   * reduced-motion rule would otherwise freeze it — misleadingly, since it
   * freezes at whatever the animation's first frame is, not the visually
   * "full" state. Under reduced motion this shows a static bar plus a live
   * numeric countdown instead, mirroring the topbar run-bar's fallback. */
  function undoSnackbar(message, onUndo, opts) {
    opts = opts || {};
    const durationMs = opts.durationMs || 3000;
    _dismissSnackbar();

    const el = document.createElement('div');
    el.className = 'undo-snackbar';
    el.setAttribute('role', 'status');
    el.innerHTML =
      '<span class="undo-snackbar-msg"></span>' +
      '<button type="button" class="btn btn-outline btn-sm undo-snackbar-btn">Undo</button>' +
      '<span class="undo-snackbar-count" aria-hidden="true"></span>' +
      '<span class="undo-snackbar-progress"><span class="undo-snackbar-bar"></span></span>';
    el.querySelector('.undo-snackbar-msg').textContent = message;
    document.body.appendChild(el);
    _snackbarEl = el;
    requestAnimationFrame(() => el.classList.add('show'));

    const bar = el.querySelector('.undo-snackbar-bar');
    const countEl = el.querySelector('.undo-snackbar-count');
    let remaining = Math.ceil(durationMs / 1000);
    countEl.textContent = '(' + remaining + ')';
    if (REDUCE_MOTION) {
      el.classList.add('reduce-motion');
    } else {
      bar.style.transitionDuration = durationMs + 'ms';
      requestAnimationFrame(() => { bar.style.transform = 'scaleX(0)'; });
    }
    const countdown = setInterval(() => {
      remaining -= 1;
      if (remaining > 0) countEl.textContent = '(' + remaining + ')';
    }, 1000);

    let settled = false;
    function cleanup() {
      clearInterval(countdown);
      clearTimeout(expireTimer);
      el.classList.remove('show');
      setTimeout(() => el.remove(), 250);
      if (_snackbarEl === el) _snackbarEl = null;
    }

    el.querySelector('.undo-snackbar-btn').addEventListener('click', () => {
      if (settled) return;
      settled = true;
      cleanup();
      onUndo();
    });

    const expireTimer = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      if (opts.onExpire) opts.onExpire();
    }, durationMs);
  }

  /* Toast stack — #toast used to be a single element, so a second action
   * fired within 3.5s of the first overwrote its text and reset its timer,
   * silently swallowing the first message. Each call now gets its own node
   * in #toast-stack, entering and leaving independently.
   *
   * role is set per-item, not on the stack container: role="alert" needs to
   * be present on an element the instant it's inserted to get its own
   * assertive announcement, independent of whatever else is in the stack —
   * a single container-level role couldn't represent two concurrent toasts
   * of different urgency correctly. role="status" is the default (same as
   * the old element's base.html markup), role="alert" for errors, matching
   * the previous behavior exactly, just per-message instead of per-element. */
  function showToast(msg, type = 'info') {
    const stack = document.getElementById('toast-stack');
    if (!stack) return;
    const el = document.createElement('div');
    el.className = 'toast-item toast-' + type;
    el.setAttribute('role', type === 'error' ? 'alert' : 'status');
    el.textContent = msg;
    stack.appendChild(el);
    // rAF, not immediate: the .show transition needs the browser to have
    // painted the pre-transition (translateY/opacity:0) state first, or the
    // entrance never animates — it just appears.
    requestAnimationFrame(() => el.classList.add('show'));
    el._timer = setTimeout(() => _dismissToast(el), 3500);
  }

  function _dismissToast(el) {
    if (!el.isConnected) return;
    clearTimeout(el._timer);
    el.classList.remove('show');
    el.classList.add('leaving');
    el.addEventListener('transitionend', () => el.remove(), { once: true });
    // Fallback in case transitionend never fires (e.g. the element was
    // already display:none'd some other way) — never leave a dead node.
    setTimeout(() => { if (el.isConnected) el.remove(); }, 600);
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
    panel.style.maxHeight = '';
    panel.style.top = (rect.bottom + 6) + 'px';
    const pw = panel.offsetWidth;
    const ph = panel.offsetHeight;
    if (rect.left + pw > window.innerWidth - 8) {
      panel.style.left = 'auto';
      panel.style.right = Math.max(8, window.innerWidth - rect.right) + 'px';
      panel.classList.add('anchor-right');
    }
    const spaceBelow = window.innerHeight - rect.bottom - 6 - 8;
    const spaceAbove = rect.top - 6 - 8;
    let top = rect.bottom + 6;
    let maxSpace = spaceBelow;
    // Flip above only when the panel doesn't fit below AND there's more room
    // above — otherwise a long option list (e.g. many repos) is better
    // served staying below and scrolling in place (see the .menu-panel
    // max-height/overflow-y rule) than flipping to a side with even less
    // room. Either way, maxHeight is capped to whichever side we land on so
    // the panel scrolls instead of running off-screen.
    if (ph > spaceBelow && spaceAbove > spaceBelow) {
      top = Math.max(8, rect.top - Math.min(ph, spaceAbove) - 6);
      maxSpace = spaceAbove;
    }
    panel.style.top = top + 'px';
    panel.style.maxHeight = Math.max(120, maxSpace) + 'px';
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
        st.panel.style.maxHeight = '';
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

  /* Repaint a field-menu's trigger label and aria-current from its hidden
   * mirror input (see the field_menu macro in templates/_macros.html).
   *
   * MUST be called after any programmatic `input.value = …`: a hidden input
   * has no visible box, so writing it otherwise leaves the trigger showing
   * whatever the server rendered while the stored value has moved on — the
   * UI reads "Critical only" while the saved setting is "high". */
  function syncMenuField(id) {
    const input = document.getElementById(id);
    const menu = document.querySelector('.menu[data-field="' + id + '"]');
    if (!input || !menu) return;
    let label = null;
    menu.querySelectorAll('[role="menuitem"]').forEach((it) => {
      if (it.dataset.value === input.value) {
        it.setAttribute('aria-current', 'true');
        label = it.textContent.trim();
      } else {
        it.removeAttribute('aria-current');
      }
    });
    const out = menu.querySelector('.menu-trigger-label');
    if (out && label !== null) out.textContent = label;
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
        // A field_menu item drives a hidden <input> mirror rather than
        // navigating. Order matters: write the value, repaint the trigger,
        // THEN dispatch — so any handler reading .value sees the new one.
        // The synthetic 'change' is what fires the mirror's inline
        // onchange= attribute, which is how the original <select>'s
        // handler keeps working verbatim.
        const field = _openMenuEl.dataset.field;
        if (field && item.dataset.value !== undefined) {
          const input = document.getElementById(field);
          if (input && input.value !== item.dataset.value) {
            input.value = item.dataset.value;
            syncMenuField(field);
            input.dispatchEvent(new Event('change', { bubbles: true }));
          }
        }
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

  /* Stagger a small, once-per-page-load card grid into view as it scrolls
   * in (dashboard metric tiles, settings sections) — never table rows,
   * which would re-run on every pjax swap for no informational gain. Both
   * classes are added/removed entirely here; the caller's template needs no
   * markup of its own beyond the selector it passes in. */
  function staggerIn(selector, opts) {
    const items = Array.from(document.querySelectorAll(selector));
    if (!items.length) return;
    const delayMs = (opts && opts.delayMs) || 90;
    items.forEach((el) => el.classList.add('stagger-pending'));
    if (REDUCE_MOTION) {
      items.forEach((el) => el.classList.add('stagger-in'));
      return;
    }
    const observer = new IntersectionObserver((entries, obs) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        const i = items.indexOf(entry.target);
        setTimeout(() => entry.target.classList.add('stagger-in'), Math.max(0, i) * delayMs);
        obs.unobserve(entry.target);
      });
    }, { threshold: 0.2 });
    items.forEach((el) => observer.observe(el));
  }

  /* Animate a server-rendered integer up from zero when it scrolls into
   * view (dashboard hero score, exposure pills). The value is read from
   * the DOM, never fetched, so the number that ends up on screen is
   * always exactly what the server rendered — including its "or 0"
   * fallback and any non-numeric placeholder, which this simply skips.
   * Mirrors staggerIn's IntersectionObserver/REDUCE_MOTION shape. */
  function countUp(selector, opts) {
    const items = Array.from(document.querySelectorAll(selector));
    if (!items.length) return;
    const duration = (opts && opts.duration) || 1200;
    // Under reduced motion the correct value is already painted — this is
    // a no-op, not a fallback, so the DOM is never touched.
    if (REDUCE_MOTION) return;

    const targets = items
      .map((el) => ({ el, raw: el.textContent, target: parseInt(el.textContent.trim(), 10) }))
      .filter((t) => /^\d+$/.test(t.raw.trim()) && Number.isFinite(t.target));
    if (!targets.length) return;

    const observer = new IntersectionObserver((entries, obs) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        const t = targets.find((x) => x.el === entry.target);
        if (!t) return;
        obs.unobserve(entry.target);
        // A hidden document suspends requestAnimationFrame outright, so
        // never start a tween that cannot be finished — the
        // server-rendered value is already correct and simply stays put.
        if (document.hidden) return;

        let settled = false;
        const settle = () => {
          if (settled) return;
          settled = true;
          // Write back the stashed original string, not the computed
          // number, so formatting the server rendered (thousands
          // separators, the raw "0" fallback text) survives exactly.
          entry.target.textContent = t.raw;
        };

        const t0 = performance.now();
        const step = (now) => {
          if (settled) return;
          const p = Math.min((now - t0) / duration, 1);
          if (p < 1) {
            const eased = 1 - Math.pow(1 - p, 3);
            entry.target.textContent = Math.round(t.target * eased).toLocaleString();
            requestAnimationFrame(step);
          } else {
            settle();
          }
        };
        requestAnimationFrame(step);
        // Backstop, and not a theoretical one: if the tab is backgrounded
        // mid-tween, rAF stops firing and the loop dies on whatever frame
        // it reached, leaving a WRONG number on screen permanently (seen
        // in testing: a frozen 26 where the real figure was 30). A
        // setTimeout still fires while hidden, so the true value always
        // lands regardless of what happens to the frame loop.
        setTimeout(settle, duration + 150);
      });
    }, { threshold: 0.2 });
    targets.forEach((t) => observer.observe(t.el));
  }

  /* Grow a server-rendered visual from zero up to its real value once,
   * on load — the dashboard severity stack, priority bars and donut.
   * The caller passes the CONTAINER selector(s); the zero state and the
   * transition both live in style.css (see the "Fill-in reveal" block
   * there), so this only has to add .is-pending and take it away again.
   *
   * No requestAnimationFrame: rAF does not fire at all while a document
   * is hidden, which would leave a background-tab load pinned at zero.
   * Forcing one synchronous style flush instead makes the zero state the
   * transition's start value in the same tick — the same
   * `void offsetWidth` idiom submitButton() uses above.
   *
   * The REDUCE_MOTION check here only avoids pointless DOM work; the
   * actual correctness guarantee is that every .is-pending rule in
   * style.css is scoped to prefers-reduced-motion: no-preference, so the
   * zero state cannot exist for those users even if this runs. */
  function revealFill(selector) {
    const items = Array.from(document.querySelectorAll(selector));
    if (!items.length || REDUCE_MOTION) return;
    items.forEach((el) => el.classList.add('is-pending'));
    void document.body.offsetWidth;
    items.forEach((el) => el.classList.remove('is-pending'));
  }

  /* ── ⌘K command palette ────────────────────────────────
   * Markup lives in base.html outside .page-main, so a pjax swap never
   * touches it and this module (loaded once, without data-pjax) never
   * re-registers its listener.
   *
   * Combobox + listbox, NOT role=menu: focus stays on the input and
   * aria-activedescendant points at the highlighted option, which is what
   * screen readers expect for filter-as-you-type. That is also why Home/End
   * are deliberately NOT captured — they move the text caret, as they
   * should in any text field. Arrows/Enter/Escape are the only keys taken.
   *
   * Commands are data: {id, group, label, hint, when, run}. `hint` and
   * `when` may be functions of the current context, so a command can
   * describe itself differently (or hide) depending on the page and the
   * current row selection. Adding a command is one object, not new DOM.
   */
  const _PALETTE_FILTERS = [
    ['filter:findings-open', 'Open vulnerabilities', '/findings?state=unresolved'],
    ['filter:findings-new', 'Vulnerabilities: new this run', '/findings?state=new'],
    ['filter:findings-critical', 'Vulnerabilities: critical only', '/findings?state=unresolved&severity=critical'],
    ['filter:secrets-open', 'Open secrets', '/secrets?state=unresolved'],
    ['filter:secrets-new', 'Secrets: new this run', '/secrets?state=new'],
  ];

  /* Selection actions delegate to the page's own bulkAction(), so the
   * Submit States + Undo Snackbar behavior from that page is reused rather
   * than reimplemented here — the palette never talks to the API itself. */
  const _PALETTE_SELECTION = [
    ['sel:acknowledge', 'Acknowledge selected', 'findings', 'acknowledge'],
    ['sel:resolve', 'Resolve selected', 'findings', 'resolve'],
    ['sel:reopen', 'Reopen selected', 'findings', 'reopen'],
    ['sel:false-positive', 'Mark selected as false positive', 'secrets', 'false-positive'],
    ['sel:secret-resolve', 'Resolve selected secrets', 'secrets', 'resolve'],
  ];

  let _paletteItems = [];
  let _paletteIndex = 0;
  let _paletteTrigger = null;

  function _paletteGo(url) {
    // DIVE.navigate is the pjax router's own function (exposed in
    // base.html) — a filter jump has no anchor to click, and assigning
    // window.location here would turn every palette jump into a full reload.
    if (window.DIVE && DIVE.navigate) DIVE.navigate(url);
    else window.location = url;
  }

  function _paletteContext() {
    const path = window.location.pathname;
    const selected = window._selected;
    return {
      page: path === '/findings' ? 'findings' : path === '/secrets' ? 'secrets' : '',
      selection: selected && selected.size ? selected.size : 0,
    };
  }

  function _paletteCommands(ctx) {
    const cmds = [];

    // Built from the live sidebar rather than a hardcoded list, so a new
    // destination shows up here automatically. Clicking the real anchor
    // lets base.html's pjax click delegate handle it exactly as a click.
    document.querySelectorAll('.site-nav a[href]').forEach((a) => {
      const span = a.querySelector('span');
      cmds.push({
        id: 'nav:' + a.getAttribute('href'),
        group: 'Go to',
        label: (span ? span.textContent : a.textContent).trim(),
        hint: a.getAttribute('href'),
        run: () => a.click(),
      });
    });

    _PALETTE_FILTERS.forEach(([id, label, url]) => {
      cmds.push({ id, group: 'Filter', label, hint: url, run: () => _paletteGo(url) });
    });

    _PALETTE_SELECTION.forEach(([id, label, page, action]) => {
      cmds.push({
        id,
        group: 'Selection',
        label,
        hint: ctx.selection + ' selected',
        when: () => ctx.page === page && ctx.selection > 0,
        run: () => { if (window.bulkAction) window.bulkAction(action); },
      });
    });

    cmds.push({
      id: 'pipeline:run',
      group: 'Pipeline',
      label: 'Run pipeline now',
      hint: 'Collect, scan, notify',
      run: () => { if (window.triggerRun) window.triggerRun(); },
    });

    return cmds.filter((c) => !c.when || c.when());
  }

  function _paletteMatch(cmd, query) {
    if (!query) return true;
    const haystack = (cmd.label + ' ' + cmd.group + ' ' + (cmd.hint || '')).toLowerCase();
    // Every whitespace-separated token must appear — predictable, unlike a
    // fuzzy scorer that can surface surprising matches for a short query.
    return query.toLowerCase().split(/\s+/).filter(Boolean).every((t) => haystack.includes(t));
  }

  function _renderPalette() {
    const list = document.getElementById('command-list');
    const input = document.getElementById('command-input');
    const empty = document.querySelector('.command-empty');
    const status = document.getElementById('command-status');
    if (!list || !input) return;

    const ctx = _paletteContext();
    _paletteItems = _paletteCommands(ctx).filter((c) => _paletteMatch(c, input.value));
    if (_paletteIndex >= _paletteItems.length) _paletteIndex = 0;

    list.innerHTML = '';
    let lastGroup = null;
    _paletteItems.forEach((cmd, i) => {
      if (cmd.group !== lastGroup) {
        lastGroup = cmd.group;
        const header = document.createElement('li');
        header.className = 'command-group';
        header.setAttribute('role', 'presentation');
        header.textContent = cmd.group;
        list.appendChild(header);
      }
      const li = document.createElement('li');
      li.className = 'command-option';
      li.id = 'command-opt-' + i;
      li.setAttribute('role', 'option');
      li.setAttribute('aria-selected', i === _paletteIndex ? 'true' : 'false');
      li.style.setProperty('--i', i);
      const label = document.createElement('span');
      label.className = 'command-option-label';
      label.textContent = cmd.label;
      li.appendChild(label);
      if (cmd.hint) {
        const hint = document.createElement('span');
        hint.className = 'command-option-hint';
        hint.textContent = cmd.hint;
        li.appendChild(hint);
      }
      li.addEventListener('click', () => { _paletteIndex = i; _runPaletteItem(); });
      list.appendChild(li);
    });

    if (empty) empty.hidden = _paletteItems.length > 0;
    _syncPaletteActive();
    if (status) {
      status.textContent = _paletteItems.length
        ? _paletteItems.length + ' command' + (_paletteItems.length === 1 ? '' : 's')
        : 'No matching commands';
    }
  }

  function _syncPaletteActive() {
    const input = document.getElementById('command-input');
    const options = document.querySelectorAll('#command-list .command-option');
    options.forEach((el, i) => el.setAttribute('aria-selected', i === _paletteIndex ? 'true' : 'false'));
    const active = options[_paletteIndex];
    if (input) {
      if (active) input.setAttribute('aria-activedescendant', active.id);
      else input.removeAttribute('aria-activedescendant');
    }
    if (active && active.scrollIntoView) active.scrollIntoView({ block: 'nearest' });
  }

  function _movePaletteHighlight(delta) {
    if (!_paletteItems.length) return;
    _paletteIndex = (_paletteIndex + delta + _paletteItems.length) % _paletteItems.length;
    _syncPaletteActive();
  }

  function _runPaletteItem() {
    const cmd = _paletteItems[_paletteIndex];
    if (!cmd) return;
    // Close first: the command may swap .page-main out from under us, and
    // focus restore should target the pre-navigation element.
    closePalette();
    cmd.run();
  }

  function openPalette() {
    const palette = document.getElementById('command-palette');
    const input = document.getElementById('command-input');
    if (!palette || palette.classList.contains('open')) return;
    _paletteTrigger = document.activeElement;
    palette.classList.add('open');
    palette.setAttribute('aria-hidden', 'false');
    input.value = '';
    _paletteIndex = 0;
    _renderPalette();
    input.focus();
  }

  function closePalette() {
    const palette = document.getElementById('command-palette');
    if (!palette || !palette.classList.contains('open')) return;
    palette.classList.remove('open');
    palette.setAttribute('aria-hidden', 'true');
    const trigger = _paletteTrigger;
    _paletteTrigger = null;
    if (trigger && trigger.focus && trigger.isConnected) trigger.focus();
  }

  function _isTextEntry(el) {
    if (!el) return false;
    return el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable;
  }

  /* The palette's ONE document-level keydown listener, in the CAPTURE phase
   * so it runs before the modal and menu Escape handlers registered above.
   * stopPropagation on the keys it owns is the explicit precedence rule:
   * Escape while the palette is open closes the palette and nothing else. */
  document.addEventListener('keydown', function (e) {
    const palette = document.getElementById('command-palette');
    if (!palette) return;

    if (palette.classList.contains('open')) {
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closePalette(); return; }
      if (e.key === 'ArrowDown') { e.preventDefault(); e.stopPropagation(); _movePaletteHighlight(1); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); e.stopPropagation(); _movePaletteHighlight(-1); return; }
      if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); _runPaletteItem(); return; }
      if (e.key === 'Tab') { e.stopPropagation(); _trapTab(palette.querySelector('.command-panel'), e); return; }
      return; // every other key is typing — let it reach the input
    }

    if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
      // Don't steal ⌘K from a field the user is typing in (news search, the
      // annotation textarea), and don't open on top of a modal — two focus
      // traps fighting over the same document is not a state worth having.
      if (_isTextEntry(document.activeElement)) return;
      if (document.querySelector('.modal-backdrop.open')) return;
      e.preventDefault();
      e.stopPropagation();
      openPalette();
    }
  }, true);

  document.addEventListener('input', function (e) {
    if (e.target && e.target.id === 'command-input') {
      _paletteIndex = 0;
      _renderPalette();
    }
  });

  document.addEventListener('click', function (e) {
    if (e.target && e.target.dataset && e.target.dataset.role === 'scrim') closePalette();
  });

  window.DIVE = {
    apiFetch, postAction, showToast, timeAgo, timeUntil, escapeHtml,
    toggleBookmark, confirmModal, openModal, closeModal,
    setFieldError, clearFieldError,
    openMenu, closeMenu, closeAllMenus, syncMenuField,
    submitButton, undoSnackbar,
    openPalette, closePalette, staggerIn, countUp, revealFill,
  };
})();
