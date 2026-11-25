// Checks that the home page's rising sections ([data-reveal], watch.js) are
// never left blank, at 1440, 844 and 390px wide, in both languages:
//   - jump: load the page, jump straight into the middle of a section (as a
//     link, a restored scroll position or a fast fling does) and it shows;
//   - load: a section in the window when the page loads shows at once, and one
//     below the window still waits to rise (it is not "seen" yet);
//   - hash: a page opened on a hash anchor shows every section at once.
// A section shows when it has the class "seen" and a point inside it, taken
// from the window, hits the section (its starting clip-path is gone). Run it
// on any change to watch.js or to those sections, after go generate, with
// docs/site served on 127.0.0.1:8785. ego-browser nodejs prints the result on
// stderr; the last line is "reveal: ok" or "reveal: FAIL <n>":
//   ego-browser nodejs < cmd/sitegen/testdata/check-reveal.js
const task = await taskSpace("shentu reveal check", { profileId: "Default" });
const fails = [], runs = [];
try {
  const page = (await task.pages())[0] ?? (await task.adopt((await task.tabs())[0].page));
  await page.cdp("Network.enable", {});
  await page.cdp("Network.setCacheDisabled", { cacheDisabled: true }); // watch.js as it is now
  for (const w of [1440, 844, 390]) {
    await page.cdp("Emulation.setDeviceMetricsOverride", { width: w, height: 900, deviceScaleFactor: 1, mobile: w < 600 });
    for (const pre of ["", "zh-TW/"]) {
      const url = "http://127.0.0.1:8785/" + pre;
      const n = await (async () => {
        await page.goto(url + "?cb=" + Date.now()); await page.waitForLoadState("load");
        return page.evaluate(() => document.querySelectorAll("[data-reveal]").length);
      })();
      for (let i = 0; i < n; i++) {
        await page.goto(url + "?cb=" + Date.now()); await page.waitForLoadState("load");
        const r = await page.evaluate(async (i) => {
          const el = document.querySelectorAll("[data-reveal]")[i], b = el.getBoundingClientRect();
          window.scrollTo(0, scrollY + b.top + b.height / 2 - innerHeight / 2);
          await new Promise(res => setTimeout(res, 1500));
          const c = el.getBoundingClientRect(), y = Math.min(Math.max(c.top, 0) + 20, innerHeight - 20);
          return { el: el.className, seen: el.classList.contains("seen"), hit: el.contains(document.elementFromPoint(innerWidth / 2, y)) };
        }, i);
        runs.push({ w, pre, how: "jump", ...r });
        if (!r.seen || !r.hit) fails.push(`${w} ${pre || "en/"} jump into ${r.el}: seen=${r.seen} hit=${r.hit}`);
      }
      await page.goto(url + "?cb=" + Date.now()); await page.waitForLoadState("load");
      const l = await page.evaluate(() => [...document.querySelectorAll("[data-reveal]")].map(el => { const b = el.getBoundingClientRect(); return { el: el.className, inside: b.top < innerHeight && b.bottom > 0, below: b.top >= innerHeight, seen: el.classList.contains("seen") }; }));
      for (const r of l) {
        runs.push({ w, pre, how: "load", ...r });
        if (r.inside && !r.seen) fails.push(`${w} ${pre || "en/"} in the window at load, ${r.el}: not seen`);
        if (r.below && r.seen) fails.push(`${w} ${pre || "en/"} below the window at load, ${r.el}: seen already (no rise left)`);
      }
      await page.goto(url + "?cb=" + Date.now() + "#latest-title"); await page.waitForLoadState("load");
      const h = await page.evaluate(() => [...document.querySelectorAll("[data-reveal]")].map(el => ({ el: el.className, seen: el.classList.contains("seen") })));
      for (const r of h) { runs.push({ w, pre, how: "hash", ...r }); if (!r.seen) fails.push(`${w} ${pre || "en/"} opened on #latest-title, ${r.el}: not seen`); }
    }
  }
} finally { await task.finish({ keep: [] }); }
console.log(JSON.stringify({ runs: runs.length, fails }, null, 1));
console.log(fails.length ? `reveal: FAIL ${fails.length}` : "reveal: ok");
