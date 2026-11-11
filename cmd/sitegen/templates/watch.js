/* The night-watch scroll. Scrolling down walks the guardian to the right through
   six stations; the scenes move under it at their own depths. Only transform and
   opacity change while scrolling, geometry is read on resize, the page scroll is
   never held. With reduced motion the stations stand as still cards. */
(function () {
  var d = document, root = d.documentElement, run = d.getElementById('watch');
  if (!run) return;
  var still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  var q = function (s) { return run.querySelector(s); }, qa = function (s) { return run.querySelectorAll(s); };

  /* the report: words that type themselves, choices that answer */
  var talk = q('.talk'), text = q('.talk-text'), full = text.dataset.full, typed = false, typing = 0;
  function type(str) {
    clearInterval(typing);
    if (still) { text.textContent = str; return; }
    var i = 0; text.textContent = '';
    typing = setInterval(function () { i += 2; text.textContent = str.slice(0, i); if (i >= str.length) clearInterval(typing); }, 28);
  }
  text.addEventListener('click', function () { clearInterval(typing); text.textContent = text.dataset.now || full; });
  qa('.talk-opts button').forEach(function (b) {
    b.addEventListener('click', function () {
      qa('.talk-opts button').forEach(function (o) { o.setAttribute('aria-pressed', o === b); });
      text.dataset.now = b.dataset.say; type(b.dataset.say);
      talk.classList.add('answered');
    });
  });
  if (still) return;

  root.classList.add('walking');
  var stage = q('.stage'), sky = q('.sky'), world = q('.world'), haze = q('.haze'), boughs = q('.boughs'), scenes = qa('.scene'), walker = q('.walker'), evil = q('.evil'),
      st = qa('.station'), checks = q('.checks'), items = qa('.checks li'), hudName = q('.hud-name'), hudBar = q('.hud b'), cue = q('.cue');
  var hud = JSON.parse(run.dataset.hud || '[]');
  var top = 0, span = 1, vw = 1, vh = 1, last = -1, ticking = false, moving = 0, N = scenes.length - 1;

  function measure() {
    vw = innerWidth; vh = innerHeight;
    top = run.getBoundingClientRect().top + scrollY; span = Math.max(1, run.offsetHeight - vh);
    last = -1; frame();
  }
  function clamp(x) { return x < 0 ? 0 : x > 1 ? 1 : x; }
  function ramp(x, a, b) { return clamp((x - a) / (b - a)); }
  function ease(x) { return x * x * (3 - 2 * x); }
  /* how much a station shows when the walk is at s; its own scene is at k */
  function near(s, k, w) { return ease(clamp(1 - Math.abs(s - k) / w)); }

  function frame() {
    ticking = false;
    var p = clamp((scrollY - top) / span), s = p * N;
    if (s === last) return; last = s;
    world.style.transform = 'translate3d(' + (-s * vw).toFixed(1) + 'px,0,0)';
    sky.style.transform = 'translate3d(' + (-s * vw * .18).toFixed(1) + 'px,0,0)';
    haze.style.transform = 'translate3d(' + (-s * vw * 1.12).toFixed(1) + 'px,0,0)';
    boughs.style.transform = 'translate3d(' + (-s * vw * 1.25).toFixed(1) + 'px,0,0)';
    /* scenes come in as the walk nears them */
    for (var i = 0; i < scenes.length; i++) if (scenes[i].dataset.bg && s > i - 1.6) { scenes[i].style.backgroundImage = 'url(' + scenes[i].dataset.bg + ')'; delete scenes[i].dataset.bg; }
    /* stations: the hero at the gate, then one text per scene */
    for (var k = 0; k < st.length; k++) {
      var o = k === 0 ? 1 - ease(ramp(s, .12, .45)) : near(s, k, .55);
      st[k].style.opacity = o.toFixed(3); st[k].style.transform = 'translate3d(0,' + (18 * (1 - o)).toFixed(1) + 'px,0)';
    }
    cue.style.opacity = (1 - ease(ramp(s, 0, .12))).toFixed(3);
    /* the checks: lit as the lantern passes them */
    checks.style.opacity = (ease(ramp(s, .65, .95)) * (1 - ease(ramp(s, 4.45, 4.75)))).toFixed(3);
    for (var j = 0; j < items.length; j++) items[j].classList.toggle('lit', s >= +items[j].dataset.at);
    /* the find: the door shakes, the miasma rises, the light turns red */
    var red = near(s, 4, .7);
    evil.style.opacity = red.toFixed(3);
    scenes[4].classList.toggle('shake', s > 3.75 && s < 4.35);
    /* the report: the guardian turns to face you, the words come */
    var show = ease(ramp(s, 4.5, 4.85));
    talk.style.opacity = show.toFixed(3); talk.style.transform = 'translate3d(0,' + (30 * (1 - show)).toFixed(1) + 'px,0)';
    talk.inert = show < .5;
    if (show > .6 && !typed) { typed = true; type(full); }
    scenes[5].style.transform = 'scale(' + (1.18 - .18 * ease(ramp(s, 4.2, 5))).toFixed(4) + ')';
    walker.style.opacity = (ease(ramp(s, .2, .5)) * (1 - ease(ramp(s, 4.4, 4.8)))).toFixed(3);
    var at = Math.min(N, Math.round(s));
    if (hudName.dataset.at != at) { hudName.dataset.at = at; hudName.textContent = hud[at] || ''; }
    hudBar.style.transform = 'scaleX(' + p.toFixed(4) + ')';
    /* a step in the walk while the page moves */
    walker.classList.add('step'); clearTimeout(moving); moving = setTimeout(function () { walker.classList.remove('step'); }, 160);
  }
  addEventListener('scroll', function () { if (!ticking) { ticking = true; requestAnimationFrame(frame); } }, { passive: true });
  addEventListener('resize', measure);
  measure();

  /* incense smoke at the burner and the back hall, dust in the air, miasma at the red door */
  var c = q('canvas.near'), x = c.getContext('2d'), dpr = Math.min(devicePixelRatio || 1, 2), W = 0, H = 0, on = true, P = [];
  function size() { W = c.clientWidth; H = c.clientHeight; c.width = W * dpr; c.height = H * dpr; x.setTransform(dpr, 0, 0, dpr, 0, 0); }
  size(); addEventListener('resize', size);
  /* one soft puff for each colour, drawn once */
  function sprite(rgb) {
    var o = d.createElement('canvas'); o.width = o.height = 64; var g = o.getContext('2d'), r = g.createRadialGradient(32, 32, 0, 32, 32, 32);
    r.addColorStop(0, 'rgba(' + rgb + ',1)'); r.addColorStop(.45, 'rgba(' + rgb + ',.35)'); r.addColorStop(1, 'rgba(' + rgb + ',0)');
    g.fillStyle = r; g.fillRect(0, 0, 64, 64); return o;
  }
  var SMOKE = sprite('235,215,190'), EVIL = sprite('200,40,25');
  function puff(kind) {
    var at = { smoke: [1.5, 3.25], evil: [4.5] }[kind], a = at[Math.floor(Math.random() * at.length)];
    return { kind: kind, wx: a + (Math.random() - .5) * .08, y: .78 + Math.random() * .08, r: 6 + Math.random() * 10, v: .0006 + Math.random() * .0008, life: 0, ph: Math.random() * 6.28 };
  }
  for (var n = 0; n < 34; n++) { var a = puff('smoke'); a.life = Math.random(); P.push(a); }
  for (var m = 0; m < 26; m++) { var e = puff('evil'); e.life = Math.random(); P.push(e); }
  var dust = []; for (var u = 0; u < 60; u++) dust.push({ x: Math.random(), y: Math.random(), r: Math.random() * 1.4 + .3, v: Math.random() * .0002 + .00006, ph: Math.random() * 6.28 });
  function draw(t) {
    if (!on) return;
    var s = last < 0 ? 0 : last;
    x.clearRect(0, 0, W, H);
    for (var i = 0; i < P.length; i++) {
      var e = P[i]; e.life += e.v * (e.kind === 'evil' ? 1.6 : 1);
      if (e.life > 1) { P[i] = puff(e.kind); continue; }
      /* world-anchored: they move with the scene they belong to (and a little faster, the near layer) */
      var sx = (e.wx - s) * W * 1.08 + W * .5 + Math.sin(t / 1300 + e.ph) * 18 * e.life + (e.kind === 'evil' ? (e.life * 160 * Math.sin(e.ph)) : 0);
      if (sx < -80 || sx > W + 80) continue;
      var sy = (e.y - e.life * (e.kind === 'evil' ? .35 : .55)) * H, rr = e.r * (2 + e.life * 6);
      x.globalAlpha = Math.sin(e.life * 3.14) * (e.kind === 'evil' ? .38 : .2);
      x.drawImage(e.kind === 'evil' ? EVIL : SMOKE, sx - rr, sy - rr, rr * 2, rr * 2);
    }
    x.globalAlpha = 1;
    for (var k = 0; k < dust.length; k++) {
      var g = dust[k], f = Math.sin(t / 900 + g.ph); g.y -= g.v; if (g.y < 0) g.y = 1;
      x.fillStyle = 'rgba(255, 214, 150,' + (.15 + .3 * f * f) + ')';
      x.beginPath(); x.arc(((g.x - s * .25) % 1 + 1) % 1 * W, g.y * H, g.r, 0, 6.29); x.fill();
    }
    requestAnimationFrame(draw);
  }
  new IntersectionObserver(function (es) { var was = on; on = es[0].isIntersecting; if (on && !was) requestAnimationFrame(draw); }).observe(stage);
  requestAnimationFrame(draw);
})();

/* sections after the walk rise out of the light */
(function () {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches || !('IntersectionObserver' in window)) return;
  document.documentElement.classList.add('reveal');
  var io = new IntersectionObserver(function (es) { es.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('seen'); io.unobserve(e.target); } }); }, { rootMargin: '0px 0px -10% 0px' });
  document.querySelectorAll('[data-reveal]').forEach(function (el) { io.observe(el); });
})();
