/* =========================================================================
   Password Security Suite — front-end
   Talks to the local Java server's JSON API (/api/...). No dependencies.
   ========================================================================= */
(function () {
  'use strict';

  // ------------------------------------------------------------------ helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const fmtInt = (n) => Number(n).toLocaleString('en-US');

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const c of children) if (c != null) node.append(c);
    return node;
  }

  /** POST form-encoded params (or GET when params is null) and return parsed JSON. */
  async function api(path, params) {
    const opts = params
      ? { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params) }
      : { method: 'GET' };
    let res;
    try {
      res = await fetch('api/' + path, opts);
    } catch (e) {
      throw new Error('Cannot reach the local server. Is it still running?');
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Request failed (' + res.status + ')');
    return data;
  }

  function toast(msg, kind) {
    const t = el('div', { class: 'toast ' + (kind || ''), role: 'status', text: msg });
    $('#toasts').append(t);
    setTimeout(() => t.remove(), 3800);
  }

  /** Runs an async action, showing any error as a toast. */
  async function guard(fn) {
    try { return await fn(); } catch (e) { toast(e.message, 'bad'); }
  }

  function debounce(fn, ms) {
    let t;
    return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  }

  const tone = (category) => ({ Strong: 'good', 'Very Strong': 'good', Medium: 'warn', Weak: 'bad' }[category] || '');
  const flag = (id) => ($('#' + id).checked ? '1' : '0');

  // Show / hide password toggles
  $$('[data-toggle]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const input = $('#' + btn.dataset.toggle);
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Hide' : 'Show';
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  });

  // ------------------------------------------------------------------ theme
  (function theme() {
    const root = document.documentElement;
    let saved = null;
    try { saved = localStorage.getItem('pss-theme'); } catch (e) { /* storage unavailable */ }
    if (saved) root.dataset.theme = saved;
    $$('[data-theme-toggle]').forEach((b) => b.addEventListener('click', () => {
      const dark = root.dataset.theme
        ? root.dataset.theme === 'dark'
        : matchMedia('(prefers-color-scheme: dark)').matches;
      root.dataset.theme = dark ? 'light' : 'dark';
      try { localStorage.setItem('pss-theme', root.dataset.theme); } catch (e) { /* ignore */ }
    }));
  })();

  // ------------------------------------------------------------------ router
  const pages = {};
  const onShow = {};

  function route() {
    const name = (location.hash || '#home').slice(1);
    const page = $('#page-' + name) ? name : 'home';
    $$('.page').forEach((p) => { p.hidden = p.id !== 'page-' + page; });
    $$('.nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === page));
    const title = $('#page-' + page).dataset.title;
    $('#topbarTitle').textContent = title;
    document.title = page === 'home' ? 'Password Security Suite' : title + ' · Password Security Suite';
    closeMenu();
    window.scrollTo(0, 0);
    if (onShow[page]) onShow[page]();
  }
  window.addEventListener('hashchange', route);

  function closeMenu() {
    $('#sidebar').classList.remove('open');
    $('#scrim').hidden = true;
    $('#menuBtn').setAttribute('aria-expanded', 'false');
  }
  $('#menuBtn').addEventListener('click', () => {
    $('#sidebar').classList.add('open');
    $('#scrim').hidden = false;
    $('#menuBtn').setAttribute('aria-expanded', 'true');
  });
  $('#scrim').addEventListener('click', closeMenu);

  // ------------------------------------------------------------------ home
  onShow.home = () => guard(async () => {
    const s = await api('stats');
    const strip = $('#homeStats');
    strip.replaceChildren(
      ...[
        [s.totalAnalyzed, 'Passwords analyzed'],
        [s.totalAnalyzed ? s.averageScore.toFixed(1) : '—', 'Average score'],
        [s.bruteForce + s.dictionary, 'Attack simulations'],
        [s.loginAttempts, 'Login attempts'],
      ].map(([v, l]) => el('div', { class: 's' }, el('div', { class: 'v', text: String(v) }), el('div', { class: 'l', text: l })))
    );
  });

  // ================================================================== 1. Analyzer
  (function analyzer() {
    const input = $('#anPassword');
    const checks = [
      ['length', 'Length'],
      ['hasUpper', 'Uppercase letters (A–Z)', '+26'],
      ['hasLower', 'Lowercase letters (a–z)', '+26'],
      ['hasDigit', 'Digits (0–9)', '+10'],
      ['hasSymbol', 'Symbols & spaces', '+33'],
    ];

    function render(r) {
      const gauge = $('#anGauge');
      gauge.style.setProperty('--val', r ? r.score : 0);
      gauge.className = 'gauge ' + (r ? tone(r.category) : '');
      $('#anScore').textContent = r ? r.score : 0;
      const badge = $('#anBadge');
      badge.textContent = r ? r.category : 'Awaiting input';
      badge.className = 'badge ' + (r ? tone(r.category) : '');
      $('#anEntropy').textContent = (r ? r.entropy : 0).toFixed(1) + ' bits';
      $('#anPool').textContent = (r ? r.poolSize : 0) + ' chars';
      $('#anCrack').textContent = r ? r.crackTime : 'Instant';

      $('#anChecklist').replaceChildren(...checks.map(([key, label, extra]) => {
        let ok, text = label, note = extra || '';
        if (key === 'length') {
          const n = r ? r.length : 0;
          ok = n >= 12;
          text = 'Length: ' + n + ' character' + (n === 1 ? '' : 's');
          note = n >= 12 ? 'Excellent' : n >= 8 ? 'Acceptable' : 'Too short';
        } else {
          ok = !!(r && r[key]);
          if (!ok) note = '';
        }
        return el('li', { class: ok ? 'ok' : '' }, el('span', { class: 'ic', text: ok ? '✓' : '–' }), text, el('span', { class: 'extra', text: note }));
      }));

      const box = $('#anWarnings');
      if (!r) {
        box.className = 'muted';
        box.textContent = 'Enter a password to inspect it for weak patterns.';
      } else if (r.warnings.length === 0) {
        box.className = '';
        box.replaceChildren(el('div', { class: 'ok-msg', text: '✓ No common weak patterns detected.' }));
      } else {
        box.className = '';
        box.replaceChildren(
          el('ul', { class: 'warn-list' }, ...r.warnings.map((w) => el('li', { text: w }))),
          el('p', { class: 'small muted', text: 'Tip: use 12+ characters and avoid familiar words, sequences and repeats.' })
        );
      }
    }

    let seq = 0;
    const live = debounce(async () => {
      const mine = ++seq;
      if (!input.value) { render(null); return; }
      const r = await guard(() => api('analyze', { password: input.value, record: '0' }));
      if (r && mine === seq) render(r);
    }, 120);

    input.addEventListener('input', live);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#anRecord').click(); });
    $('#anRecord').addEventListener('click', () => guard(async () => {
      if (!input.value) { toast('Type a password first.'); input.focus(); return; }
      const r = await api('analyze', { password: input.value, record: '1' });
      render(r);
      toast('Recorded: ' + r.category + ' (' + r.score + '/100). Only the score is saved.', 'good');
    }));
    $('#anClear').addEventListener('click', () => { input.value = ''; seq++; render(null); input.focus(); });
    pages.analyzer = { analyze(pw) { input.value = pw; live(); } };
    render(null);
  })();

  // ================================================================== 2. Generator
  (function generator() {
    const out = $('#genOutput');
    let current = '';

    $$('.tab').forEach((tab) => tab.addEventListener('click', () => {
      $$('.tab').forEach((t) => { t.classList.toggle('active', t === tab); t.setAttribute('aria-selected', t === tab); });
      $$('.tab-panel').forEach((p) => { p.hidden = p.id !== tab.dataset.tab; });
    }));

    const len = $('#genLength');
    len.addEventListener('input', () => { $('#genLengthVal').textContent = len.value; });

    function show(r, unit) {
      current = r.value;
      out.textContent = r.value;
      out.classList.add('filled');
      $('#genCopy').disabled = $('#genAnalyze').disabled = false;
      $('#genInfo').textContent = (unit === 'chars'
        ? 'Length ' + r.value.length + ' · pool ' + r.poolSize + ' chars'
        : 'Vocabulary ' + r.poolSize + ' words') + ' · entropy ≈ ' + r.entropy.toFixed(1) + ' bits · ' + r.strength;
    }

    $('#genPwBtn').addEventListener('click', () => guard(async () => {
      show(await api('generate/password', {
        length: len.value, upper: flag('genUpper'), lower: flag('genLower'),
        digits: flag('genDigits'), symbols: flag('genSymbols'), excludeAmbiguous: flag('genAmbig'),
      }), 'chars');
    }));
    $('#genPpBtn').addEventListener('click', () => guard(async () => {
      show(await api('generate/passphrase', {
        words: $('#ppWords').value, separator: $('#ppSep').value,
        capitalize: flag('ppCap'), appendNumber: flag('ppNum'),
      }), 'words');
    }));
    $('#genCopy').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(current);
        toast('Copied to clipboard.', 'good');
      } catch (e) {
        const range = document.createRange();
        range.selectNodeContents(out);
        getSelection().removeAllRanges();
        getSelection().addRange(range);
        toast('Press Ctrl+C to copy the selected text.');
      }
    });
    $('#genAnalyze').addEventListener('click', () => {
      location.hash = '#analyzer';
      pages.analyzer.analyze(current);
    });
  })();

  // ================================================================== 3. Brute force
  (function bruteForce() {
    const target = $('#bfTarget');
    const pool = () => ({ digits: flag('bfDigits'), lower: flag('bfLower'), upper: flag('bfUpper'), symbols: flag('bfSymbols') });
    let runId = 0;

    const updateSpace = debounce(() => guard(async () => {
      const r = await api('bruteforce/space', Object.assign({ target: target.value }, pool()));
      $('#bfPool').textContent = r.poolSize + ' chars';
      $('#bfCombos').textContent = r.combinations;
      $('#bfEst').textContent = r.estimate;
    }), 100);

    $('#bfPreset').addEventListener('change', (e) => {
      if (!e.target.value) return;
      const [t, sets] = e.target.value.split('|');
      target.value = t;
      $('#bfDigits').checked = sets.includes('d');
      $('#bfLower').checked = sets.includes('l');
      $('#bfUpper').checked = sets.includes('u');
      $('#bfSymbols').checked = false;
      updateSpace();
    });
    target.addEventListener('input', () => { $('#bfPreset').value = ''; updateSpace(); });
    $$('#page-bruteforce .checks input').forEach((c) => c.addEventListener('change', updateSpace));

    function setRunning(on) {
      $('#bfRun').disabled = on;
      $('#bfStop').disabled = !on;
      $('#bfReset').disabled = on;
    }

    function reset() {
      runId++;
      setRunning(false);
      const cand = $('#bfCandidate');
      cand.textContent = '—';
      cand.className = 'candidate';
      $('#bfBar').style.width = '0';
      $('#bfBar').parentElement.classList.remove('done');
      $('#bfAttempts').textContent = '0';
      $('#bfElapsed').textContent = '0 ms';
      $('#bfStatus').textContent = 'Ready';
    }

    $('#bfRun').addEventListener('click', () => guard(async () => {
      const t = target.value;
      if (t.length > 5 && !confirm('This target is ' + t.length + ' characters. The demo will stop after 50,000 attempts, long before it finishes. Run it anyway?')) return;
      reset();
      const id = runId;
      setRunning(true);
      $('#bfStatus').textContent = 'Running…';
      let r;
      try {
        r = await api('bruteforce/run', Object.assign({ target: t }, pool()));
      } catch (e) {
        setRunning(false);
        $('#bfStatus').textContent = 'Ready';
        throw e;
      }
      // Replay evenly spaced snapshots so the search is visible.
      const total = Number(r.totalCombinationsRaw);
      const n = r.samples.length;
      const frame = Math.max(8, Math.min(25, 1800 / Math.max(n, 1)));
      for (let i = 0; i < n; i++) {
        if (id !== runId) return;
        const attempts = Math.round((r.attempts * (i + 1)) / (n + 1));
        $('#bfCandidate').textContent = r.samples[i];
        $('#bfAttempts').textContent = fmtInt(attempts);
        $('#bfBar').style.width = Math.min(100, (attempts / Math.min(total, r.maxAttempts)) * 100) + '%';
        await sleep(frame);
      }
      if (id !== runId) return;
      setRunning(false);
      $('#bfAttempts').textContent = fmtInt(r.attempts);
      $('#bfElapsed').textContent = r.elapsedMs < 1 ? '< 1 ms' : r.elapsedMs.toFixed(1) + ' ms';
      const cand = $('#bfCandidate');
      if (r.found) {
        cand.textContent = 'Found: ' + t;
        cand.className = 'candidate found';
        $('#bfBar').style.width = '100%';
        $('#bfBar').parentElement.classList.add('done');
        $('#bfStatus').textContent = 'Cracked';
        toast('Found "' + t + '" after ' + fmtInt(r.attempts) + ' attempts.', 'good');
      } else {
        cand.textContent = 'Stopped at cap';
        cand.className = 'candidate miss';
        $('#bfStatus').textContent = 'Capped';
        toast('Stopped after ' + fmtInt(r.maxAttempts) + ' of ' + r.totalCombinations + ' combinations. Length makes brute force impractical.');
      }
    }));
    $('#bfStop').addEventListener('click', () => {
      runId++;
      setRunning(false);
      $('#bfStatus').textContent = 'Stopped';
    });
    $('#bfReset').addEventListener('click', reset);
    updateSpace();
  })();

  // ================================================================== 4. Dictionary
  (function dictionary() {
    let words = [];
    let runId = 0;
    const target = $('#dictTarget');

    function renderList() {
      $('#dictCount').textContent = words.length;
      $('#dictList').replaceChildren(...words.map((w, i) =>
        el('button', { class: 'word', type: 'button', role: 'listitem', 'data-i': i, text: w, onclick: () => { target.value = w; } })));
      $('#dictAttempt').textContent = '0 / ' + words.length;
    }

    async function load(path, params) {
      const r = await api(path, params);
      words = r.words;
      renderList();
    }

    function setRunning(on) {
      $('#dictRun').disabled = on;
      $('#dictStop').disabled = !on;
      $('#dictReset').disabled = on;
    }

    function reset() {
      runId++;
      setRunning(false);
      $$('#dictList .word').forEach((w) => w.classList.remove('current', 'tested', 'hit'));
      const c = $('#dictCandidate');
      c.textContent = '—';
      c.className = 'candidate';
      $('#dictBar').style.width = '0';
      $('#dictBar').parentElement.classList.remove('done');
      $('#dictAttempt').textContent = '0 / ' + words.length;
      $('#dictStatus').textContent = 'Ready';
    }

    $('#dictPreset').addEventListener('change', (e) => { target.value = e.target.value; });
    $('#dictAddForm').addEventListener('submit', (e) => {
      e.preventDefault();
      guard(async () => {
        const w = $('#dictNewWord').value.trim();
        await load('dictionary/add', { word: w });
        $('#dictNewWord').value = '';
        toast('Added "' + w + '" to the wordlist.', 'good');
        const list = $('#dictList');
        list.scrollTop = list.scrollHeight;
      });
    });
    $('#dictRestore').addEventListener('click', () => guard(async () => {
      await load('dictionary/reset', {});
      reset();
      toast('Wordlist restored from data/sample_words.txt.');
    }));

    $('#dictRun').addEventListener('click', () => guard(async () => {
      const t = target.value.trim();
      if (!t) { toast('Enter a target string.'); return; }
      reset();
      const id = runId;
      setRunning(true);
      $('#dictStatus').textContent = 'Running…';
      let r;
      try {
        r = await api('dictionary/run', { target: t });
      } catch (e) {
        setRunning(false);
        $('#dictStatus').textContent = 'Ready';
        throw e;
      }
      const delay = Number($('#dictSpeed').value);
      const stopAt = r.found ? r.index : r.total;
      const chips = $$('#dictList .word');
      const list = $('#dictList');
      if (delay > 0) {
        for (let i = 0; i < stopAt; i++) {
          if (id !== runId) return;
          if (chips[i - 1]) chips[i - 1].classList.replace('current', 'tested');
          if (chips[i]) {
            chips[i].classList.add('current');
            list.scrollTop = chips[i].offsetTop - list.offsetTop - 40;
          }
          $('#dictCandidate').textContent = words[i];
          $('#dictAttempt').textContent = (i + 1) + ' / ' + r.total;
          $('#dictBar').style.width = ((i + 1) / r.total) * 100 + '%';
          await sleep(delay);
        }
      } else {
        chips.slice(0, stopAt).forEach((c) => c.classList.add('tested'));
      }
      if (id !== runId) return;
      setRunning(false);
      chips.forEach((c) => c.classList.remove('current'));
      $('#dictAttempt').textContent = stopAt + ' / ' + r.total;
      const c = $('#dictCandidate');
      if (r.found) {
        if (chips[r.index - 1]) chips[r.index - 1].classList.add('hit');
        c.textContent = 'Match: ' + t;
        c.className = 'candidate found';
        $('#dictBar').style.width = '100%';
        $('#dictBar').parentElement.classList.add('done');
        $('#dictStatus').textContent = 'Found at #' + r.index;
        toast('"' + t + '" was found at attempt #' + r.index + ' of ' + r.total + '. Dictionary words offer no protection.', 'good');
      } else {
        c.textContent = 'Not in wordlist';
        c.className = 'candidate miss';
        $('#dictBar').style.width = '100%';
        $('#dictStatus').textContent = 'Not found';
        toast('Checked all ' + r.total + ' words. No match: unique passwords defeat dictionary lookups.');
      }
    }));
    $('#dictStop').addEventListener('click', () => {
      runId++;
      setRunning(false);
      $('#dictStatus').textContent = 'Stopped';
    });
    $('#dictReset').addEventListener('click', reset);
    guard(() => load('dictionary'));
  })();

  // ================================================================== 5. Hashing lab
  (function hashing() {
    $('#hashBtn').addEventListener('click', () => guard(async () => {
      const r = await api('hash', { input: $('#hashInput').value });
      $('#hashOut').textContent = r.hash;
    }));
    $('#hashInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#hashBtn').click(); });

    /** Hash with characters that differ from `base` highlighted. */
    function diffHash(hash, base) {
      const box = el('div', { class: 'hash-out' });
      for (let i = 0; i < hash.length; i++) {
        if (base && hash[i] !== base[i]) box.append(el('span', { class: 'diff', text: hash[i] }));
        else box.append(hash[i]);
      }
      return box;
    }

    const renderers = {
      determinism(r) {
        return [
          el('h2', { class: 'card-title', text: 'Determinism: input "' + r.input + '" hashed 4 times' }),
          ...r.runs.map((h, i) => el('div', { class: 'demo-row' }, el('div', { class: 'head' }, el('strong', { text: 'Run #' + (i + 1) })), el('div', { class: 'hash-out', text: h }))),
          el('p', { class: 'takeaway', text: 'All four digests are identical. A hash function has no randomness of its own, which is why it can verify passwords, and why identical passwords leak as identical hashes.' }),
        ];
      },
      avalanche(r) {
        const base = r.rows[0].hash;
        return [
          el('h2', { class: 'card-title', text: 'Avalanche effect: one character, a completely different hash' }),
          ...r.rows.map((row, i) => el('div', { class: 'demo-row' },
            el('div', { class: 'head' },
              el('span', {}, el('code', { text: row.input }), ' ', el('span', { class: 'muted', text: row.change })),
              i ? el('strong', { text: row.bitsChanged + ' of ' + r.totalBits + ' bits changed (' + Math.round((row.bitsChanged / r.totalBits) * 100) + '%)' }) : null),
            diffHash(row.hash, i ? base : null))),
          el('p', { class: 'takeaway', text: 'Highlighted characters differ from the original. About half the bits flip, so similar passwords give no hint about each other.' }),
        ];
      },
      salt(r) {
        const row = (who, salt, hash) => el('div', { class: 'demo-row' },
          el('div', { class: 'head' }, el('strong', { text: who }), salt ? el('span', { class: 'muted' }, 'salt ', el('code', { text: salt })) : el('span', { class: 'muted', text: 'no salt: found in rainbow tables' })),
          el('div', { class: 'hash-out', text: hash }));
        return [
          el('h2', { class: 'card-title', text: 'Salting: two users, same password "' + r.password + '"' }),
          row('Unsalted SHA-256', null, r.unsalted),
          row('Alice: SHA-256(salt + password)', r.alice.salt, r.alice.hash),
          row('Bob: SHA-256(salt + password)', r.bob.salt, r.bob.hash),
          el('p', { class: 'takeaway', text: 'Alice and Bob chose the exact same password, yet their stored hashes are completely different. Precomputed tables are useless, and each account has to be attacked separately. Run it again for fresh random salts.' }),
        ];
      },
    };

    $$('.demo-btn').forEach((btn) => btn.addEventListener('click', () => guard(async () => {
      const type = btn.dataset.demo;
      const r = await api('hash/demo', { type, input: $('#hashInput').value });
      $$('.demo-btn').forEach((b) => b.classList.toggle('active', b === btn));
      const out = $('#hashDemoOut');
      out.replaceChildren(...renderers[type](r));
      out.hidden = false;
      out.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    })));
  })();

  // ================================================================== 6. Hash matching
  (function hashMatch() {
    let runId = 0;
    let total = 0;
    const targetInput = $('#hmTarget');

    function setRunning(on) {
      $('#hmRun').disabled = on;
      $('#hmStop').disabled = !on;
      $('#hmReset').disabled = on;
    }

    function setStatus(text, kind) {
      const s = $('#hmStatus');
      s.textContent = text;
      s.className = 'status-banner ' + (kind || '');
    }

    function reset() {
      runId++;
      setRunning(false);
      $('#hmWord').textContent = '—';
      $('#hmWord').className = 'candidate';
      $('#hmHash').textContent = '—';
      $('#hmHash').className = 'hash-out';
      $('#hmTargetEcho').textContent = targetInput.value || '—';
      $('#hmBar').style.width = '0';
      $('#hmBar').parentElement.classList.remove('done');
      $('#hmCount').textContent = '0 / ' + total;
      setStatus('Ready');
    }

    guard(async () => {
      const r = await api('hashmatch');
      total = r.candidates.length;
      const sel = $('#hmPreset');
      sel.replaceChildren(
        ...r.targets.map((t) => el('option', { value: t.hash, text: t.label + ': ' + t.description })),
        el('option', { value: '', text: 'Custom hash…' })
      );
      targetInput.value = r.targets[0].hash;
      sel.addEventListener('change', () => {
        if (sel.value) targetInput.value = sel.value;
        else { targetInput.value = ''; targetInput.focus(); }
        reset();
      });
      reset();
    });
    targetInput.addEventListener('input', () => { $('#hmTargetEcho').textContent = targetInput.value || '—'; });

    $('#hmRun').addEventListener('click', () => guard(async () => {
      reset();
      const id = runId;
      setRunning(true);
      setStatus('Hashing candidates and comparing…');
      let r;
      try {
        r = await api('hashmatch/run', { hash: targetInput.value });
      } catch (e) {
        setRunning(false);
        setStatus('Ready');
        throw e;
      }
      for (let i = 0; i < r.steps.length; i++) {
        if (id !== runId) return;
        const s = r.steps[i];
        $('#hmWord').textContent = s.word;
        $('#hmHash').textContent = s.hash;
        $('#hmCount').textContent = (i + 1) + ' / ' + r.total;
        $('#hmBar').style.width = ((i + 1) / r.total) * 100 + '%';
        await sleep(80);
      }
      if (id !== runId) return;
      setRunning(false);
      if (r.found) {
        const hit = r.steps[r.steps.length - 1];
        $('#hmWord').textContent = hit.word;
        $('#hmWord').className = 'candidate found';
        $('#hmHash').className = 'hash-out match';
        $('#hmBar').style.width = '100%';
        $('#hmBar').parentElement.classList.add('done');
        setStatus('Match found: the leaked hash belongs to "' + hit.word + '" (attempt #' + r.steps.length + ' of ' + r.total + '). The hash was guessed, not reversed.', 'good');
      } else {
        $('#hmWord').textContent = 'No match';
        $('#hmWord').className = 'candidate miss';
        setStatus('All ' + r.total + ' candidates tested, no match. Unique, non-dictionary passwords survive this attack.', 'bad');
      }
    }));
    $('#hmStop').addEventListener('click', () => {
      runId++;
      setRunning(false);
      setStatus('Stopped');
    });
    $('#hmReset').addEventListener('click', reset);
  })();

  // ================================================================== 7. Login
  (function login() {
    const userSel = $('#loginUser');
    let maxAttempts = 3;
    let lockTimer = null;

    function renderState(remaining, lockMs) {
      const pips = $$('#loginPips span');
      pips.forEach((p, i) => p.classList.toggle('used', i >= remaining));
      $('#loginPips').classList.toggle('locked', lockMs > 0);
      clearInterval(lockTimer);
      const box = $('#lockBox');
      $('#loginBtn').disabled = lockMs > 0;
      if (lockMs > 0) {
        box.hidden = false;
        const until = Date.now() + lockMs;
        const totalMs = lockMs;
        const bar = $('#lockBar');
        bar.style.transition = 'none';
        bar.style.width = '100%';
        const tick = () => {
          const left = Math.max(0, until - Date.now());
          $('#lockSecs').textContent = Math.ceil(left / 1000);
          bar.style.transition = '';
          bar.style.width = (left / Math.max(totalMs, 15000)) * 100 + '%';
          if (left <= 0) {
            clearInterval(lockTimer);
            log({ outcome: 'INFO', user: userSel.value, time: new Date().toTimeString().slice(0, 8), message: 'Cooldown finished. Account unlocked.' });
            refresh();
          }
        };
        tick();
        lockTimer = setInterval(tick, 250);
      } else {
        box.hidden = true;
      }
    }

    async function refresh() {
      const s = await api('login/status?username=' + encodeURIComponent(userSel.value));
      if (s.known) renderState(s.remainingAttempts, s.lockRemainingMs);
    }

    function log(entry) {
      const list = $('#loginLog');
      const first = list.firstElementChild;
      if (first && first.classList.contains('muted')) first.remove();
      const label = { SUCCESS: 'SUCCESS', FAILED: 'FAILED', UNKNOWN_USER: 'FAILED', LOCKED_NOW: 'LOCKED', BLOCKED: 'BLOCKED', INFO: 'INFO', RESET: 'RESET' }[entry.outcome] || entry.outcome;
      list.append(el('li', { class: entry.outcome }, el('span', { class: 't', text: '[' + entry.time + ']' }), '[' + label + '] ' + entry.user + ' — ' + entry.message));
      list.scrollTop = list.scrollHeight;
    }

    guard(async () => {
      const r = await api('login/accounts');
      maxAttempts = r.maxAttempts;
      $('#loginIter').textContent = fmtInt(r.iterations);
      userSel.replaceChildren(...r.accounts.map((a) => el('option', { value: a.username, text: a.username })));
      $('#loginAccounts').replaceChildren(...r.accounts.map((a) => el('li', {},
        el('div', { class: 'acc-head' }, el('strong', { text: a.username }), el('code', { text: a.demoPassword })),
        el('div', { class: 'acc-line' }, el('span', { text: 'salt' }), el('code', { text: a.salt })),
        el('div', { class: 'acc-line' }, el('span', { text: 'hash' }), el('code', { text: a.hash.slice(0, 32) + '…' }))
      )));
      await refresh();
    });

    userSel.addEventListener('change', () => guard(refresh));

    $('#loginForm').addEventListener('submit', (e) => {
      e.preventDefault();
      guard(async () => {
        const pass = $('#loginPass');
        if (!pass.value) { toast('Enter a password.'); pass.focus(); return; }
        const r = await api('login', { username: userSel.value, password: pass.value });
        pass.value = '';
        r.user = userSel.value;
        if (r.outcome === 'FAILED') r.message += ' ' + r.remainingAttempts + ' attempt' + (r.remainingAttempts === 1 ? '' : 's') + ' left.';
        log(r);
        toast(r.message, r.outcome === 'SUCCESS' ? 'good' : 'bad');
        if (r.outcome === 'BLOCKED' || r.outcome === 'LOCKED_NOW') renderState(0, r.lockRemainingMs);
        else renderState(r.remainingAttempts, 0);
      });
    });

    $('#loginReset').addEventListener('click', () => guard(async () => {
      const s = await api('login/reset', { username: userSel.value });
      log({ outcome: 'RESET', user: userSel.value, time: new Date().toTimeString().slice(0, 8), message: 'Admin reset: unlocked and failure counter cleared.' });
      renderState(s.remainingAttempts, s.lockRemainingMs);
    }));
    $('#loginClearLog').addEventListener('click', () => {
      $('#loginLog').replaceChildren(el('li', { class: 'muted', text: 'No attempts yet.' }));
    });

    onShow.login = () => guard(refresh);
  })();

  // ================================================================== 8. Analytics
  (function analytics() {
    async function refresh() {
      const s = await api('stats');
      const tiles = [
        [s.totalAnalyzed, 'Passwords analyzed', ''],
        [s.totalAnalyzed ? s.averageScore.toFixed(1) : '—', 'Average score / 100', ''],
        [s.strong, 'Strong', 'good'],
        [s.medium, 'Medium', 'warn'],
        [s.weak, 'Weak', 'bad'],
      ];
      $('#statTiles').replaceChildren(...tiles.map(([v, l, k]) =>
        el('div', { class: 'tile ' + k }, el('div', { class: 'v', text: String(v) }), el('div', { class: 'l', text: l }))));

      const chart = $('#strengthChart');
      if (!s.totalAnalyzed) {
        chart.replaceChildren(el('p', { class: 'muted', text: 'No data yet. Use “Analyze & record” in the Strength Analyzer to populate this chart.' }));
      } else {
        const max = Math.max(s.weak, s.medium, s.strong, 1);
        chart.replaceChildren(...[['Weak', s.weak, 'bad'], ['Medium', s.medium, 'warn'], ['Strong', s.strong, 'good']].map(([label, n, k]) => {
          const fill = el('div', { class: 'bar-fill ' + k });
          requestAnimationFrame(() => { fill.style.width = (n / max) * 100 + '%'; });
          return el('div', { class: 'bar-row' },
            el('span', { text: label }),
            el('div', { class: 'bar-track' }, fill),
            el('span', { class: 'n', text: n + ' (' + Math.round((n / s.totalAnalyzed) * 100) + '%)' }));
        }));
      }

      $('#activityList').replaceChildren(...[
        ['Brute force simulations', s.bruteForce],
        ['Dictionary attack runs', s.dictionary],
        ['Hashing tests', s.hashing],
        ['Login attempts', s.loginAttempts],
        ['Account lockouts', s.lockouts],
      ].map(([l, v]) => el('li', {}, el('span', { text: l }), el('strong', { text: fmtInt(v) }))));

      const rows = s.history.slice().reverse().map((h) => el('tr', {},
        el('td', { text: new Date(h.timestamp).toLocaleTimeString() }),
        el('td', { text: h.score + ' / 100' }),
        el('td', {}, el('span', { class: 'badge ' + tone(h.category), text: h.category })),
        el('td', { text: h.entropy.toFixed(1) + ' bits' }),
        el('td', { text: h.crackTime })));
      $('#historyTable tbody').replaceChildren(...(rows.length ? rows : [el('tr', {}, el('td', { class: 'empty', colspan: '5', text: 'No analyses recorded yet.' }))]));
    }

    $('#resetStats').addEventListener('click', () => guard(async () => {
      if (!confirm('Reset all session statistics?')) return;
      await api('stats/reset', {});
      await refresh();
      toast('Session statistics cleared.');
    }));
    onShow.analytics = () => guard(refresh);
  })();

  // ================================================================== 9. Estimator
  (function estimator() {
    let rates = [];
    const p1 = $('#estP1'), p2 = $('#estP2');

    function summary(label, pw, e) {
      return el('div', { class: 'card est-card' },
        el('h3', { text: label }),
        el('div', { class: 'pw', text: pw || '(empty)' }),
        el('dl', { class: 'kv' },
          el('dt', { text: 'Length' }), el('dd', { text: e.length + ' chars' }),
          el('dt', { text: 'Pool size (R)' }), el('dd', { text: e.poolSize + ' chars' }),
          el('dt', { text: 'Entropy' }), el('dd', { text: e.entropy.toFixed(1) + ' bits' }),
          el('dt', { text: 'Combinations (R^L)' }), el('dd', { text: e.combinations })));
    }

    const update = debounce(() => guard(async () => {
      if (!rates.length) rates = (await api('estimate/rates')).rates;
      const r = await api('estimate', { p1: p1.value, p2: p2.value });
      $('#estInsight').textContent = '💡 ' + r.insight;
      $('#estSummary').replaceChildren(summary('Password 1', p1.value, r.p1), summary('Password 2', p2.value, r.p2));
      $('#estTable tbody').replaceChildren(...rates.map((rate, i) => el('tr', {},
        el('td', {}, el('strong', { text: rate.name }), el('span', { class: 'sub', text: fmtInt(rate.perSecond) + ' guesses/sec' })),
        el('td', {}, r.p1.averageTimes[i], el('span', { class: 'sub', text: 'worst: ' + r.p1.worstTimes[i] })),
        el('td', {}, r.p2.averageTimes[i], el('span', { class: 'sub', text: 'worst: ' + r.p2.worstTimes[i] })))));
    }), 120);

    p1.addEventListener('input', update);
    p2.addEventListener('input', update);
    $$('#page-estimator .chip').forEach((c) => c.addEventListener('click', () => {
      p1.value = c.dataset.p1;
      p2.value = c.dataset.p2;
      update();
    }));
    onShow.estimator = update;
  })();

  route();
})();
