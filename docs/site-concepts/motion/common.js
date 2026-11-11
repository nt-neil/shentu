/* Dust in the beam, drawn only while the hero is on screen, never with reduced motion. */
function shentuDust(canvas, watch) {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  var x = canvas.getContext('2d'), P = [], w, h, on = true, dpr = Math.min(devicePixelRatio || 1, 2);
  function size() { w = canvas.clientWidth; h = canvas.clientHeight; canvas.width = w * dpr; canvas.height = h * dpr; x.setTransform(dpr, 0, 0, dpr, 0, 0); }
  size(); addEventListener('resize', size);
  for (var k = 0; k < 80; k++) P.push({ x: Math.random(), y: Math.random(), r: Math.random() * 1.5 + .3, v: Math.random() * .00025 + .00008, p: Math.random() * 6.28 });
  function frame(t) {
    if (!on) return;
    x.clearRect(0, 0, w, h);
    for (var k = 0; k < P.length; k++) {
      var e = P[k]; e.y -= e.v; if (e.y < 0) e.y = 1;
      var s = Math.sin(t / 900 + e.p);
      x.fillStyle = 'rgba(255, 214, 150,' + (.22 + .35 * s * s) + ')';
      x.beginPath(); x.arc((.5 + (e.x - .5) * .16 + Math.sin(t / 2400 + e.p) * .005) * w, e.y * h, e.r, 0, 6.29); x.fill();
    }
    requestAnimationFrame(frame);
  }
  new IntersectionObserver(function (es) { var was = on; on = es[0].isIntersecting; if (on && !was) requestAnimationFrame(frame); }).observe(watch);
  requestAnimationFrame(frame);
}
/* Sections fade in and rise (24 px at most) when they come into view. */
function shentuReveal() {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches || !('IntersectionObserver' in window)) return;
  document.documentElement.classList.add('reveal');
  var io = new IntersectionObserver(function (es) {
    es.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('seen'); io.unobserve(e.target); } });
  }, { rootMargin: '0px 0px -12% 0px' });
  document.querySelectorAll('[data-reveal]').forEach(function (el) { io.observe(el); });
}
