// Sticky filters. Filter controls are remembered per workspace in localStorage and
// re-applied on load, so a refresh (or coming back from a task page) doesn't silently
// drop the view you had set up.
//
// Restoring the *values* isn't enough on its own: browsers also restore form fields on a
// soft reload without firing input/change, which is how you end up staring at a filter
// box with text in it and an unfiltered table. So every restore is followed by an
// explicit apply(), including on pageshow for back/forward (bfcache) navigations.
(function () {
  const ns = (window.Thoth = window.Thoth || {});

  // Scoped by path: each workspace remembers its own filters, and a subdomain page's
  // path filter doesn't leak onto the next subdomain.
  function keyFor(name) {
    return `thoth:${location.pathname}:${name}`;
  }

  function valueOf(el) {
    return el.type === 'checkbox' ? el.checked : el.value;
  }

  function setValue(el, v) {
    if (el.type === 'checkbox') el.checked = !!v;
    else el.value = v;
  }

  function isSet(el) {
    return el.type === 'checkbox' ? el.checked : !!el.value;
  }

  /**
   * Persist a set of controls and keep the view in sync with them.
   * @param name      storage bucket (unique per control group on the page)
   * @param els       controls to remember; each needs an id. Falsy entries are ignored.
   * @param apply     re-renders the filtered view; called after every restore.
   * @param resetBtn  optional button: wired to clear the filters, and highlighted
   *                  whenever any filter is active so a remembered one is never silent.
   * @returns {{reset: function}} reset() clears both the controls and the stored state.
   */
  ns.persist = function (name, els, apply, resetBtn) {
    const key = keyFor(name);
    els = els.filter(el => el && el.id);
    if (!els.length) return { reset: apply || (() => {}) };

    const syncReset = () => {
      if (resetBtn) resetBtn.classList.toggle('filtering', els.some(isSet));
    };

    const save = () => {
      const data = {};
      els.forEach(el => { data[el.id] = valueOf(el); });
      try { localStorage.setItem(key, JSON.stringify(data)); } catch (e) { /* full/blocked */ }
      syncReset();
    };

    const restore = () => {
      let data;
      try { data = JSON.parse(localStorage.getItem(key)); } catch (e) { data = null; }
      if (!data) return false;
      let any = false;
      els.forEach(el => {
        if (!(el.id in data)) return;
        // A select whose options are built at runtime may not have this value (yet);
        // setting it would blank the select, so leave it alone.
        if (el.tagName === 'SELECT' && data[el.id] &&
            ![...el.options].some(o => o.value === data[el.id])) return;
        setValue(el, data[el.id]);
        any = true;
      });
      return any;
    };

    els.forEach(el => {
      el.addEventListener('input', save);
      el.addEventListener('change', save);
    });

    restore();
    apply();
    syncReset();
    // Back/forward and soft reloads restore fields behind our back — re-sync the view.
    window.addEventListener('pageshow', () => { restore(); apply(); syncReset(); });

    const store = {
      reset() {
        try { localStorage.removeItem(key); } catch (e) { /* ignore */ }
        els.forEach(el => setValue(el, el.type === 'checkbox' ? false : ''));
        apply();
        syncReset();
      },
    };
    if (resetBtn) resetBtn.addEventListener('click', store.reset);
    return store;
  };

  /** Remember which tab was open. An explicit #hash always wins over the memory. */
  ns.persistTab = function () {
    const key = keyFor('tab');
    const tabFor = (name) => document.querySelector(`.tab[data-tab="${name}"]`);
    document.querySelectorAll('.tab').forEach(btn => {
      btn.addEventListener('click', () => {
        try { localStorage.setItem(key, btn.dataset.tab); } catch (e) { /* ignore */ }
      });
    });
    if (location.hash) return;
    let saved;
    try { saved = localStorage.getItem(key); } catch (e) { saved = null; }
    const btn = saved && tabFor(saved);
    if (btn) btn.click();
  };
})();
