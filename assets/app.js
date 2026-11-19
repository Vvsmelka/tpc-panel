/* Panel TPC: lee data.enc.json, lo descifra en el navegador y pinta Inicio (hoy + mapa), Lista y Agenda. */
(function () {
  'use strict';

  var ST = {
    bloqueado: { l: 'Bloqueado', o: 0 }, toca: { l: 'Te toca', o: 1 }, esperando: { l: 'Esperando respuesta', s: 'Esperando', o: 2 },
    marcha: { l: 'En marcha', o: 3 }, sinempezar: { l: 'Sin empezar', o: 4 }, hecho: { l: 'Hecho', o: 5 }, parado: { l: 'Parado o descartado', s: 'Parado', o: 6 }
  };
  var ORDER = ['bloqueado', 'toca', 'esperando', 'marcha', 'sinempezar', 'hecho', 'parado'];
  var AREAS = ['Clientes', 'Colaboradores', 'Oportunidades', 'Eventos', 'Creadores', 'Redes', 'Equipo', 'Tienda'];
  var AREA_LONG = { Equipo: 'Equipo y empresa' };
  var AREA_DESC = {
    Clientes: 'Tienda online, ayuntamientos y clubes.', Colaboradores: 'Distribuidores, marcas en tienda, transporte, conectores e instituciones.',
    Oportunidades: 'Marcas de EE. UU., clubes de Nueva York, fulfillment, inversores y otros frentes.', Eventos: 'Hechos y por venir, viajes y llamadas con fecha.',
    Creadores: 'Creadores y medios de pickleball para Estados Unidos.', Redes: 'Cuentas, anuncios y blog.', Equipo: 'Fundadores, posibles socios y asesores, y lo legal.', Tienda: 'La web, Google y el catálogo.'
  };
  var PRI = { A: 0, B: 1, C: 2 };
  var PESO = { A: 2.3, B: 1.6, C: 1.2 };
  var MES = ['ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic'];
  var MES_L = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre'];
  var KEY_STORE = 'tpc-panel-key-v1';
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var S = { data: null, rows: [], view: 'inicio', area: null, showParados: false, fArea: null, fSt: null, q: '', sel: null };

  function $(s, r) { return (r || document).querySelector(s); }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function areaName(a) { return AREA_LONG[a] || a; }
  function clean(t) { return String(t || '').replace(/\.\s*$/, ''); }
  function b64d(s) { var b = atob(s); var u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  function b64e(buf) { var s = ''; var u = new Uint8Array(buf); for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
  function pf(s) {
    var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s || ''); if (!m) return null;
    var d = new Date(+m[1], +m[2] - 1, +m[3]); var t = new Date(); t.setHours(0, 0, 0, 0);
    var diff = Math.round((d - t) / 864e5);
    return { d: d, t: d.getTime(), diff: diff, past: diff < 0, soon: diff >= 0 && diff <= 14, day: d.getDate(), mon: MES[d.getMonth()],
      short: d.getDate() + ' ' + MES[d.getMonth()] + (d.getFullYear() !== t.getFullYear() ? ' ' + d.getFullYear() : ''),
      rel: diff === 0 ? 'hoy' : diff === 1 ? 'mañana' : diff > 1 ? 'en ' + diff + ' días' : 'hace ' + (-diff) + ' días' };
  }
  function ft(r) { var p = pf(r.fecha); return p ? p.t : 9e15; }
  function cmp(a, b) {
    return (ST[a.estado].o - ST[b.estado].o) || (ft(a) - ft(b)) || ((PRI[a.prioridad] != null ? PRI[a.prioridad] : 3) - (PRI[b.prioridad] != null ? PRI[b.prioridad] : 3)) || ((a.orden || 0) - (b.orden || 0));
  }
  function active(rows) { return rows.filter(function (r) { return S.showParados || r.estado !== 'parado'; }); }
  function counts(rows) { var c = {}; ORDER.forEach(function (s) { c[s] = 0; }); rows.forEach(function (r) { if (c[r.estado] != null) c[r.estado]++; }); return c; }
  function dot(st) { var d = el('i', 'dot'); d.setAttribute('data-st', st); d.setAttribute('aria-hidden', 'true'); return d; }
  function whenEl(r) { var p = pf(r.fecha); if (!p) return null; var w = el('span', 'when' + (p.past ? ' past' : p.soon ? ' soon' : ''), p.short); w.title = p.rel; return w; }

  /* ---------- acceso y descifrado ---------- */
  var enc = null;
  async function loadEnc() {
    var res = await fetch('data.enc.json', { cache: 'no-store' });
    if (!res.ok) throw new Error('No se ha podido descargar los datos.');
    enc = await res.json();
  }
  async function keyFromPass(pass) {
    var base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64d(enc.salt), iterations: enc.iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  async function decryptWith(key) {
    var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(enc.iv) }, key, b64d(enc.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  async function tryStored() {
    try {
      var saved = JSON.parse(localStorage.getItem(KEY_STORE) || 'null');
      if (!saved || saved.salt !== enc.salt) return null;
      var key = await crypto.subtle.importKey('raw', b64d(saved.k), { name: 'AES-GCM' }, false, ['decrypt']);
      return await decryptWith(key);
    } catch (e) { return null; }
  }
  async function unlock(pass, remember) {
    var key = await keyFromPass(pass);
    var data = await decryptWith(key);
    if (remember) {
      try { var raw = await crypto.subtle.exportKey('raw', key); localStorage.setItem(KEY_STORE, JSON.stringify({ salt: enc.salt, k: b64e(raw) })); } catch (e) { }
    }
    return data;
  }

  $('#lock-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var btn = $('#lock-btn'); btn.disabled = true; btn.textContent = 'Abriendo…'; $('#lock-err').hidden = true;
    try {
      if (!enc) await loadEnc();
      var data = await unlock($('#pass').value, $('#remember').checked);
      start(data);
    } catch (err) {
      $('#lock-err').hidden = false; $('#lock-err').textContent = (err && err.message && /descargar/.test(err.message)) ? err.message : 'La contraseña no es correcta.';
      btn.disabled = false; btn.textContent = 'Entrar';
    }
  });
  $('#logout').addEventListener('click', function () { try { localStorage.removeItem(KEY_STORE); } catch (e) { } location.reload(); });

  (async function boot() {
    try { await loadEnc(); var d = await tryStored(); if (d) { start(d); return; } } catch (e) { }
    $('#lock').hidden = false; $('#pass').focus();
  })();

  function start(data) {
    S.data = data; S.rows = (data.registros || []).filter(function (r) { return ST[r.estado]; });
    $('#lock').hidden = true; $('#app').hidden = false;
    var u = pf(data.actualizado); $('#updated').textContent = u ? 'Datos a ' + u.short : '';
    readHash();
    renderAll();
    window.addEventListener('hashchange', function () { readHash(); renderAll(); });
    var t; window.addEventListener('resize', function () { clearTimeout(t); t = setTimeout(function () { if (S.view === 'inicio') renderMap(); }, 150); });
  }

  /* ---------- navegación ---------- */
  function readHash() {
    var h = decodeURIComponent((location.hash || '').slice(1)).split('/');
    S.view = ['inicio', 'lista', 'agenda'].indexOf(h[0]) >= 0 ? h[0] : 'inicio';
    S.area = (S.view === 'inicio' && AREAS.indexOf(h[1]) >= 0) ? h[1] : null;
  }
  function go(view, area) {
    var h = '#' + view + (area ? '/' + encodeURIComponent(area) : '');
    if (location.hash === h) { readHash(); renderAll(); } else location.hash = h;
  }
  document.querySelectorAll('[data-view]').forEach(function (b) {
    b.addEventListener('click', function () { go(b.getAttribute('data-view'), null); window.scrollTo({ top: 0, behavior: reduce ? 'auto' : 'smooth' }); });
  });
  $('#map-back').addEventListener('click', function () { go('inicio', null); });
  $('#show-parados').addEventListener('change', function (e) { S.showParados = e.target.checked; renderMap(); renderAreaChips(); });
  $('#q').addEventListener('input', function (e) { S.q = e.target.value.trim(); renderList(); });
  document.querySelectorAll('.tile-more').forEach(function (b) {
    b.addEventListener('click', function () { S.fSt = b.getAttribute('data-st'); S.fArea = null; go('lista'); });
  });

  function renderAll() {
    ['inicio', 'lista', 'agenda'].forEach(function (v) { $('#v-' + v).hidden = v !== S.view; });
    document.querySelectorAll('[data-view]').forEach(function (b) { if (b.getAttribute('data-view') === S.view) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
    if (S.view === 'inicio') { renderToday(); renderAreaChips(); renderMap(); renderLegend(); }
    if (S.view === 'lista') renderList();
    if (S.view === 'agenda') renderAgenda();
  }

  /* ---------- hoy ---------- */
  function renderToday() {
    var c = counts(S.rows);
    var f = $('#frase'); f.replaceChildren();
    f.append('Te tocan ', el('b', null, String(c.toca)), ' cosas, hay ', el('b', null, String(c.bloqueado)), ' bloqueadas y ', el('b', null, String(c.esperando)), ' esperando respuesta.');
    $('#n-toca').textContent = c.toca; $('#n-bloq').textContent = c.bloqueado;
    fillTop($('#toca-top'), S.rows.filter(function (r) { return r.estado === 'toca'; }).sort(cmp).slice(0, 4));
    fillTop($('#bloq-top'), S.rows.filter(function (r) { return r.estado === 'bloqueado'; }).sort(cmp).slice(0, 4));
    var m = $('#minis'); m.replaceChildren();
    ['esperando', 'marcha', 'sinempezar', 'hecho'].forEach(function (s, i) {
      var b = el('button', 'mini'); b.type = 'button'; b.style.animationDelay = (i * 40) + 'ms';
      var l = el('span'); l.setAttribute('data-st', s); l.append(dot(s), ST[s].s || ST[s].l);
      b.append(l, el('b', null, String(c[s])));
      b.addEventListener('click', function () { S.fSt = s; S.fArea = null; go('lista'); });
      m.append(b);
    });
  }
  function fillTop(ul, rows) {
    ul.replaceChildren();
    if (!rows.length) { ul.append(el('li', 'empty', 'Nada aquí.')); return; }
    rows.forEach(function (r) {
      var li = el('li'); var b = el('button'); b.type = 'button';
      b.append(el('span', 't-name', r.nombre));
      var w = whenEl(r); b.append(w || el('span'));
      if (r.siguiente) b.append(el('span', 't-next', clean(r.siguiente)));
      b.addEventListener('click', function () { openSheet(r.id); });
      li.append(b); ul.append(li);
    });
  }

  /* ---------- mapa ---------- */
  function renderAreaChips() {
    var box = $('#area-chips'); box.replaceChildren();
    function chip(a, label, n) {
      var b = el('button', 'chip'); b.type = 'button'; b.setAttribute('role', 'tab'); b.setAttribute('aria-selected', String(S.area === a));
      b.append(label + ' ', el('span', 'n', String(n)));
      b.addEventListener('click', function () { go('inicio', a); });
      box.append(b);
    }
    chip(null, 'Todas', active(S.rows).length);
    AREAS.forEach(function (a) { var n = active(S.rows.filter(function (r) { return r.area === a; })).length; if (n) chip(a, areaName(a), n); });
    var sel = box.querySelector('[aria-selected="true"]'); if (sel && sel.scrollIntoView) sel.scrollIntoView({ block: 'nearest', inline: 'center' });
  }
  function renderLegend() {
    var lg = $('#legend'); lg.replaceChildren();
    ORDER.forEach(function (s) { if (s === 'parado' && !S.showParados) return; var sp = el('span'); sp.setAttribute('data-st', s); sp.append(dot(s), ST[s].s || ST[s].l); lg.append(sp); });
  }
  function renderMap() {
    var a = S.area;
    $('#map-title').textContent = a ? areaName(a) : 'Mapa del proyecto';
    $('#map-sub').textContent = a ? AREA_DESC[a] + ' Cada burbuja es una ficha; más grande cuanto más prioritaria.' : 'Cada burbuja es un área. El anillo muestra cómo están sus fichas. Toca una para entrar.';
    $('#map-back').hidden = !a;
    var box = $('#viz'); var W = Math.max(280, Math.round(box.clientWidth || 340));
    var svg = d3.select('#svg');
    svg.selectAll('*').remove();
    if (a) {
      var Ha = drawArea(svg, a, W);
      svg.attr('viewBox', '0 0 ' + W + ' ' + Ha);
    } else {
      var H = W < 520 ? W : Math.round(Math.min(W, 560) * 0.86);
      svg.attr('viewBox', '0 0 ' + W + ' ' + H);
      drawRoot(svg, W, H);
    }
    renderSide();
  }
  function drawRoot(svg, W, H) {
    var data = AREAS.map(function (a) { var rows = active(S.rows.filter(function (r) { return r.area === a; })); return { area: a, rows: rows, n: rows.length }; }).filter(function (d) { return d.n; });
    var root = d3.pack().size([W, H]).padding(Math.max(8, W * 0.02))(d3.hierarchy({ children: data }).sum(function (d) { return d.n ? Math.max(Math.sqrt(d.n) * 4, 12) : 0; }));
    fitLeaves(root.leaves(), W, H, 6);
    var outer = svg.selectAll('g.area-g').data(root.leaves()).join('g').attr('class', 'area-g')
      .attr('transform', function (d) { return 'translate(' + d.x + ',' + d.y + ')'; })
      .attr('tabindex', 0).attr('role', 'button')
      .attr('aria-label', function (d) { return areaName(d.data.area) + ': ' + d.data.n + ' fichas'; })
      .on('click', function (e, d) { go('inicio', d.data.area); })
      .on('keydown', function (e, d) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go('inicio', d.data.area); } });
    var g = outer.append('g').attr('class', 'bub-in').style('animation-delay', function (d, i) { return (i * 45) + 'ms'; });
    g.append('circle').attr('class', 'area-bg').attr('r', function (d) { return d.r; });
    g.each(function (d) {
      var c = counts(d.data.rows); var parts = ORDER.filter(function (s) { return c[s]; }).map(function (s) { return { s: s, v: c[s] }; });
      var ring = Math.max(5, Math.min(10, d.r * 0.09));
      var arc = d3.arc().innerRadius(d.r - ring - 3).outerRadius(d.r - 3).padAngle(parts.length > 1 ? 0.025 : 0).cornerRadius(2);
      d3.select(this).selectAll('path').data(d3.pie().sort(null).value(function (p) { return p.v; })(parts)).join('path')
        .attr('class', function (p) { return 'arc ' + p.data.s; }).attr('d', arc);
      var gg = d3.select(this);
      var nSize = Math.max(16, Math.min(44, d.r * 0.42));
      var inner = (d.r - ring - 6) * 2;
      var nm = d.r > 80 ? areaName(d.data.area) : d.data.area;
      var nameSize = Math.max(10, Math.min(16, d.r * 0.2, inner / (nm.length * 0.6)));
      gg.append('text').attr('class', 'area-n').attr('y', -nameSize * 0.2).style('font-size', nSize + 'px').text(d.data.n);
      gg.append('text').attr('class', 'area-name').attr('y', nSize * 0.55).style('font-size', nameSize + 'px').text(nm);
      if (c.toca + c.bloqueado && d.r > 52) {
        var urg = (c.bloqueado ? c.bloqueado + ' bloq. ' : '') + (c.toca ? c.toca + ' te toca' + (c.toca > 1 ? 'n' : '') : '');
        gg.append('text').attr('class', 'area-toca').attr('y', nSize * 0.55 + nameSize * 1.35).text(urg.trim());
      }
    });
  }
  function fitLeaves(nodes, W, H, pad) {
    var x0 = d3.min(nodes, function (d) { return d.x - d.r; }), x1 = d3.max(nodes, function (d) { return d.x + d.r; });
    var y0 = d3.min(nodes, function (d) { return d.y - d.r; }), y1 = d3.max(nodes, function (d) { return d.y + d.r; });
    var k = Math.min((W - pad * 2) / (x1 - x0), (H - pad * 2) / (y1 - y0));
    var cx = (x0 + x1) / 2, cy = (y0 + y1) / 2;
    nodes.forEach(function (d) { d.x = (d.x - cx) * k + W / 2; d.y = (d.y - cy) * k + H / 2; d.r = d.r * k; });
  }
  function drawArea(svg, a, W) {
    var rows = active(S.rows.filter(function (r) { return r.area === a; }));
    if (!rows.length) { svg.append('text').attr('x', W / 2).attr('y', 60).attr('text-anchor', 'middle').attr('class', 'grp-l').text('No hay fichas activas en esta área.'); return 120; }
    var tipos = {}; var order = [];
    rows.slice().sort(cmp).forEach(function (r) { var t = r.tipo || 'Otros'; if (!tipos[t]) { tipos[t] = []; order.push(t); } tipos[t].push(r); });
    order.sort(function (x, y) { return tipos[y].length - tipos[x].length; });
    var nMax = tipos[order[0]].length; var gap = 14; var labH = order.length > 1 ? 24 : 0; var pad = 8;
    var groups = order.map(function (t) {
      var n = tipos[t].length;
      var s = Math.round(W * Math.max(0.3, Math.min(1, Math.sqrt(n / nMax))));
      if (n === 1) s = Math.round(Math.min(s, W * 0.22));
      return { tipo: t, items: tipos[t], s: Math.min(s, W) };
    });
    // filas
    var y = pad, row = [], rowW = 0, placed = [];
    function flush() {
      if (!row.length) return;
      var total = row.reduce(function (acc, g) { return acc + g.s; }, 0) + gap * (row.length - 1);
      var x = (W - total) / 2, h = 0;
      row.forEach(function (g) { g.x = x; g.y = y + labH; x += g.s + gap; h = Math.max(h, g.s); placed.push(g); });
      y += labH + h + gap; row = []; rowW = 0;
    }
    groups.forEach(function (g) { if (row.length && rowW + gap + g.s > W) flush(); rowW += (row.length ? gap : 0) + g.s; row.push(g); });
    flush();
    var idx = 0;
    placed.forEach(function (g) {
      var root = d3.pack().size([g.s, g.s]).padding(3)(d3.hierarchy({ children: g.items.map(function (r) { return { r: r }; }) })
        .sum(function (d) { return d.r ? (PESO[d.r.prioridad] || 1.6) : 0; }).sort(function (x1, y1) { return y1.value - x1.value; }));
      var leaves = root.leaves();
      fitLeaves(leaves, g.s, g.s, 2);
      if (labH) svg.append('text').attr('class', 'grp-l').attr('x', g.x + g.s / 2).attr('y', g.y - 8).text(g.tipo + ' · ' + g.items.length);
      var it = svg.append('g').attr('transform', 'translate(' + g.x + ',' + g.y + ')').selectAll('g.it').data(leaves).join('g')
        .attr('class', function (d) { return 'it' + (d.data.r.prioridad === 'A' ? ' is-a' : '') + (S.sel === d.data.r.id ? ' sel' : ''); })
        .attr('data-st', function (d) { return d.data.r.estado; })
        .attr('transform', function (d) { return 'translate(' + d.x + ',' + d.y + ')'; })
        .attr('tabindex', 0).attr('role', 'button')
        .attr('aria-label', function (d) { return d.data.r.nombre + ', ' + ST[d.data.r.estado].l; })
        .on('click', function (e, d) { openSheet(d.data.r.id); })
        .on('keydown', function (e, d) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openSheet(d.data.r.id); } });
      it.append('title').text(function (d) { return d.data.r.nombre + ' · ' + ST[d.data.r.estado].l; });
      var inner = it.append('g').attr('class', 'bub-in').style('animation-delay', function () { return Math.min((idx++) * 12, 420) + 'ms'; });
      inner.append('circle').attr('r', function (d) { return Math.max(1, d.r - 1.5); });
      inner.each(function (d) { label(d3.select(this), d.data.r.nombre, d.r); });
    });
    return Math.ceil(y - gap + pad);
  }
  function label(g, name, r) {
    if (r < 12) return;
    var parts = String(name).split(/\s+/);
    if (r < 28 && parts.length > 1 && parts[1].length > 1) name = parts[0] + ' ' + parts[1].charAt(0) + '.';
    var fs = Math.max(8.5, Math.min(13, r * 0.32));
    var maxW = r * 1.6; var cw = fs * 0.56; var maxC = Math.max(3, Math.floor(maxW / cw));
    var words = String(name).split(/\s+/); var lines = []; var cur = '';
    words.forEach(function (w) { if ((cur + ' ' + w).trim().length <= maxC) cur = (cur + ' ' + w).trim(); else { if (cur) lines.push(cur); cur = w; } });
    if (cur) lines.push(cur);
    var maxL = r > 34 ? 3 : 2;
    if (lines.length > maxL) { lines = lines.slice(0, maxL); lines[maxL - 1] = lines[maxL - 1].slice(0, Math.max(1, maxC - 1)) + '…'; }
    lines = lines.map(function (l) { return l.length > maxC ? l.slice(0, maxC - 1) + '…' : l; });
    var t = g.append('text').style('font-size', fs + 'px');
    var lh = fs * 1.12; var y0 = -((lines.length - 1) * lh) / 2;
    lines.forEach(function (l, i) { t.append('tspan').attr('x', 0).attr('y', y0 + i * lh).attr('dy', '0.35em').text(l); });
  }

  /* ---------- panel lateral ---------- */
  function rowBtn(r, showArea) {
    var b = el('button', 'row'); b.type = 'button'; b.setAttribute('data-st', r.estado);
    b.append(dot(r.estado), el('span', 'r-name', r.nombre));
    var w = whenEl(r); b.append(w || el('span'));
    var meta = [showArea ? areaName(r.area) : '', r.tipo, r.detalle].filter(Boolean).map(clean).join('. ');
    if (meta) b.append(el('span', 'r-meta', meta));
    if (r.siguiente) { var n = el('span', 'r-next'); n.append(el('b', null, 'Siguiente: '), clean(r.siguiente)); b.append(n); }
    b.addEventListener('click', function () { openSheet(r.id); });
    return b;
  }
  function group(title, rows, showArea, subKey) {
    var g = el('div', 'group');
    var h = el('div', 'group-h'); h.append(el('h3', null, title), el('span', 'count', String(rows.length))); g.append(h);
    if (subKey) {
      var subs = {}; var order = [];
      rows.forEach(function (r) { var k = r[subKey] || 'Otros'; if (!subs[k]) { subs[k] = []; order.push(k); } subs[k].push(r); });
      if (order.length > 1) { order.forEach(function (k) { g.append(el('div', 'sub-h', k + ' · ' + subs[k].length)); subs[k].forEach(function (r) { g.append(rowBtn(r, showArea)); }); }); return g; }
    }
    rows.forEach(function (r) { g.append(rowBtn(r, showArea)); });
    return g;
  }
  function countsLine(rows) {
    var c = counts(rows); var box = el('div', 'counts');
    ORDER.forEach(function (s) { if (!c[s]) return; var sp = el('span'); sp.setAttribute('data-st', s); sp.append(dot(s), el('b', null, String(c[s])), ' ' + (ST[s].s || ST[s].l).toLowerCase()); box.append(sp); });
    return box;
  }
  function renderSide() {
    var side = $('#side'); side.replaceChildren();
    if (!S.area) {
      var urg = S.rows.filter(function (r) { return r.estado === 'bloqueado' || r.estado === 'toca'; }).sort(cmp);
      var t = el('div', 'side-title'); t.append(el('h3', null, 'Lo urgente'), el('span', 'count', String(urg.length)));
      side.append(t, group('Bloqueado y te toca', urg, true));
      return;
    }
    var rows = active(S.rows.filter(function (r) { return r.area === S.area; })).sort(cmp);
    var tt = el('div', 'side-title'); tt.append(el('h3', null, 'Fichas de ' + areaName(S.area).toLowerCase()), el('span', 'count', String(rows.length)));
    side.append(tt, countsLine(rows), group(areaName(S.area), rows, false, 'tipo'));
    var par = S.rows.filter(function (r) { return r.area === S.area && r.estado === 'parado'; }).length;
    if (par && !S.showParados) side.append(el('p', 'empty', 'Hay ' + par + ' parados o descartados. Marca «Ver lo parado o descartado» para verlos.'));
  }

  /* ---------- lista ---------- */
  function renderList() {
    var fa = $('#f-area'); fa.replaceChildren();
    function chip(box, label, n, on, fn, st) {
      var b = el('button', 'chip'); b.type = 'button'; b.setAttribute('aria-pressed', String(on));
      if (st) b.append(dot(st));
      b.append(label + ' ', el('span', 'n', String(n)));
      b.addEventListener('click', fn); box.append(b);
    }
    var base = S.rows.filter(function (r) { return S.fSt ? r.estado === S.fSt : r.estado !== 'parado'; });
    chip(fa, 'Todas las áreas', base.length, !S.fArea, function () { S.fArea = null; renderList(); });
    AREAS.forEach(function (a) { var n = base.filter(function (r) { return r.area === a; }).length; if (n) chip(fa, areaName(a), n, S.fArea === a, function () { S.fArea = S.fArea === a ? null : a; renderList(); }); });
    var fs = $('#f-st'); fs.replaceChildren();
    var inArea = S.rows.filter(function (r) { return !S.fArea || r.area === S.fArea; });
    var c = counts(inArea);
    chip(fs, 'Activas', inArea.length - c.parado, !S.fSt, function () { S.fSt = null; renderList(); });
    ORDER.forEach(function (s) { if (c[s]) chip(fs, ST[s].s || ST[s].l, c[s], S.fSt === s, function () { S.fSt = S.fSt === s ? null : s; renderList(); }, s); });

    var q = S.q.toLowerCase();
    var rows = S.rows.filter(function (r) {
      if (S.fArea && r.area !== S.fArea) return false;
      if (q) return [r.nombre, r.tipo, r.detalle, r.ultimo, r.siguiente, r.canal, r.cifra, r.area].join(' ').toLowerCase().indexOf(q) >= 0 && (!S.fSt || r.estado === S.fSt);
      return S.fSt ? r.estado === S.fSt : r.estado !== 'parado';
    }).sort(cmp);
    var body = $('#list-body'); body.replaceChildren();
    if (!rows.length) { body.append(el('p', 'empty', q ? 'Nada coincide con «' + S.q + '».' : 'No hay fichas con este filtro.')); return; }
    AREAS.forEach(function (a) { var g = rows.filter(function (r) { return r.area === a; }); if (g.length) body.append(group(areaName(a), g, false, 'tipo')); });
  }

  /* ---------- agenda ---------- */
  function renderAgenda() {
    var body = $('#agenda-body'); body.replaceChildren();
    var rows = S.rows.filter(function (r) { var p = pf(r.fecha); return p && p.diff >= -7 && r.estado !== 'parado'; }).sort(function (x, y) { return ft(x) - ft(y); });
    if (!rows.length) { body.append(el('p', 'empty', 'No hay nada con fecha.')); return; }
    var months = {}; var order = [];
    rows.forEach(function (r) { var p = pf(r.fecha); var k = p.d.getFullYear() + '-' + p.d.getMonth(); if (!months[k]) { months[k] = []; order.push(k); } months[k].push(r); });
    order.forEach(function (k) {
      var parts = k.split('-'); var m = el('section', 'month');
      m.append(el('h3', null, MES_L[+parts[1]] + ' ' + parts[0]));
      var days = {}; var dord = [];
      months[k].forEach(function (r) { if (!days[r.fecha]) { days[r.fecha] = []; dord.push(r.fecha); } days[r.fecha].push(r); });
      dord.forEach(function (f) {
        var p = pf(f); var d = el('div', 'day' + (p.past ? ' past' : p.soon ? ' soon' : ''));
        var cal = el('div', 'cal'); cal.append(el('b', null, String(p.day)), el('small', null, p.rel));
        var g = el('div', 'group'); days[f].sort(cmp).forEach(function (r) { g.append(rowBtn(r, true)); });
        d.append(cal, g); m.append(d);
      });
      body.append(m);
    });
  }

  /* ---------- ficha ---------- */
  var lastFocus = null;
  function openSheet(id) {
    var r = S.rows.filter(function (x) { return x.id === id; })[0]; if (!r) return;
    lastFocus = document.activeElement; S.sel = id;
    var sh = $('#sheet'); sh.replaceChildren();
    sh.append(el('div', 'grab'));
    var top = el('div', 'sheet-top'); var pill = el('span', 'pill'); pill.setAttribute('data-st', r.estado); pill.append(dot(r.estado), ST[r.estado].l);
    var x = el('button', 'close', '×'); x.type = 'button'; x.setAttribute('aria-label', 'Cerrar'); x.addEventListener('click', closeSheet);
    top.append(pill, x); sh.append(top);
    var h = el('h2', null, r.nombre); h.id = 'sheet-title'; h.tabIndex = -1; sh.append(h);
    sh.append(el('p', 's-meta', [areaName(r.area), r.tipo].filter(Boolean).map(clean).join(' · ')));
    if (r.siguiente) { var nx = el('div', 's-next'); var p = pf(r.fecha); nx.append(el('small', null, 'Siguiente paso' + (p ? ' · ' + p.short + ' (' + p.rel + ')' : '')), el('p', null, r.siguiente)); sh.append(nx); }
    if (r.detalle) { var b1 = el('div', 's-block'); b1.append(el('h3', null, 'Quién o qué es'), el('p', null, r.detalle)); sh.append(b1); }
    if (r.ultimo) { var b2 = el('div', 's-block'); b2.append(el('h3', null, 'Qué ha pasado'), el('p', null, r.ultimo)); sh.append(b2); }
    var dl = el('dl', 's-dl');
    [['Cifra', r.cifra], ['Canal', r.canal], ['Prioridad', r.prioridad], ['Actualizado', r.actualizado ? (pf(r.actualizado) || {}).short || r.actualizado : '']].forEach(function (q) { if (q[1]) dl.append(el('dt', null, q[0]), el('dd', null, q[1])); });
    if (dl.children.length) sh.append(dl);
    if (r.enlace && /^https:\/\//.test(r.enlace)) {
      var acts = el('div', 's-actions'); var a = el('a', 'btn-ghost', 'Abrir enlace'); a.href = r.enlace; a.target = '_blank'; a.rel = 'noopener'; acts.append(a); sh.append(acts);
    }
    $('#scrim').hidden = false; sh.hidden = false; h.focus({ preventScroll: true });
    if (S.view === 'inicio' && S.area) d3.selectAll('g.it').classed('sel', function (d) { return d.data.r.id === id; });
  }
  function closeSheet() {
    $('#sheet').hidden = true; $('#scrim').hidden = true; S.sel = null;
    d3.selectAll('g.it').classed('sel', false);
    if (lastFocus && lastFocus.focus) lastFocus.focus({ preventScroll: true });
  }
  $('#scrim').addEventListener('click', closeSheet);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !$('#sheet').hidden) closeSheet(); });
})();
