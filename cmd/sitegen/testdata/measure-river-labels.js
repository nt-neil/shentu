// Measures the river's labels as a browser draws them, for
// river-label-widths.json (TestRiverLabelsAtLeastRendered). Serve docs/site on
// 127.0.0.1:8785 and run it with ego-browser (`ego-browser nodejs < this`); it
// prints the rows, every label made visible, at a 1920px-wide page.
const task = await taskSpace("shentu river label widths", { profileId: "Default" });
const res = {};
try {
  const page = (await task.pages())[0] ?? (await task.adopt((await task.tabs())[0].page));
  await page.cdp("Emulation.setDeviceMetricsOverride", { width: 1920, height: 1000, deviceScaleFactor: 1, mobile: false });
  for (const [lang, pre] of [["en", ""], ["zh-TW", "zh-TW/"]]) {
    await page.goto("http://127.0.0.1:8785/" + pre + "?cb=" + Date.now()); await page.waitForLoadState("load");
    await page.evaluate(async () => { await document.fonts.ready; });
    res[lang] = await page.evaluate(() => {
      const st = document.createElement("style");
      st.textContent = ".era-node :is(.lamp .ver, .lamp time, .lamp .badge, .acc) { visibility: visible !important; }";
      document.head.append(st);
      return [...document.querySelectorAll(".era-node")].map(n => {
        const rs = [...n.querySelectorAll(".lamp .ver, .lamp time, .lamp .badge, .acc > span")].map(e => e.getBoundingClientRect());
        return {
          version: n.querySelector(".ver").textContent.trim().slice(1),
          date: n.querySelector("time")?.getAttribute("datetime") || "",
          acc: [...n.querySelectorAll(".acc > span")].map(e => e.textContent.trim().replace(/\s+/g, " ")),
          width: Math.ceil(Math.max(...rs.map(r => r.right)) - Math.min(...rs.map(r => r.left))),
        };
      });
    });
  }
} finally { await task.finish({ keep: [] }); }
console.log(JSON.stringify(res));
