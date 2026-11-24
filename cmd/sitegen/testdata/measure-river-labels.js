// Measures the river's labels as a browser draws them and prints
// river-label-widths.json as it is (TestRiverLabelsAtLeastRendered): every
// release's date, its rule-count/bench lines and its label's width, edge to
// edge, every label made visible, at a 1920px-wide page. Run it on release
// day, after go generate, with docs/site served on 127.0.0.1:8785:
//   ego-browser nodejs < cmd/sitegen/testdata/measure-river-labels.js > cmd/sitegen/testdata/river-label-widths.json
const task = await taskSpace("shentu river label widths", { profileId: "Default" });
const out = { measured: "", languages: {} };
try {
  const page = (await task.pages())[0] ?? (await task.adopt((await task.tabs())[0].page));
  await page.cdp("Emulation.setDeviceMetricsOverride", { width: 1920, height: 1000, deviceScaleFactor: 1, mobile: false });
  const ua = await page.evaluate(() => navigator.userAgent.match(/Chrome\/[\d.]+/)?.[0] || "");
  const d = new Date(), p2 = v => String(v).padStart(2, "0");
  out.measured = `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}, ` + ua + ", docs/site at 1920px, every label visible";
  for (const [lang, pre] of [["en", ""], ["zh-TW", "zh-TW/"]]) {
    await page.goto("http://127.0.0.1:8785/" + pre + "?cb=" + Date.now()); await page.waitForLoadState("load");
    await page.evaluate(async () => { await document.fonts.ready; });
    out.languages[lang] = await page.evaluate(() => {
      const st = document.createElement("style");
      st.textContent = ".era-node :is(.lamp .ver, .lamp time, .lamp .badge, .acc) { visibility: visible !important; }";
      document.head.append(st);
      const rows = {};
      for (const n of document.querySelectorAll(".era-node")) {
        const rs = [...n.querySelectorAll(".lamp .ver, .lamp time, .lamp .badge, .acc > span")].map(e => e.getBoundingClientRect());
        rows[n.querySelector(".ver").textContent.trim().slice(1)] = {
          date: n.querySelector("time")?.getAttribute("datetime") || "",
          acc: [...n.querySelectorAll(".acc > span")].map(e => e.textContent.trim().replace(/\s+/g, " ")),
          width: Math.ceil(Math.max(...rs.map(r => r.right)) - Math.min(...rs.map(r => r.left))),
        };
      }
      return rows;
    });
  }
} finally { await task.finish({ keep: [] }); }
console.log(JSON.stringify(out, null, 1));
