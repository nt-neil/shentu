#!/usr/bin/env python3
"""Rebuild the site's display fonts: Noto Serif TC Light and Black, cut down to the
characters the site uses (all text of docs/site, plus printable ASCII and CJK
punctuation).

    go generate ./cmd/sitegen        # build the pages first
    python3 cmd/sitegen/fontsubset.py NotoSerifTC-Light.otf NotoSerifTC-Black.otf
    go generate ./cmd/sitegen        # embed the new subsets

Needs fonttools and brotli (pip install fonttools brotli). The source font is
https://github.com/notofonts/noto-cjk (Serif/SubsetOTF/TC), under the SIL Open
Font License 1.1 (templates/fonts/OFL.txt). TestFontCoversSite fails when the
site gains a character the subset lacks.
"""
import glob, html, os, re, subprocess, sys

here = os.path.dirname(os.path.abspath(__file__))
site = os.path.join(here, "..", "..", "docs", "site")
text = set(chr(c) for c in range(0x20, 0x7F)) | set("　、。，．：；？！「」『』（）《》〈〉…—–·・％／～")
for f in glob.glob(os.path.join(site, "**", "*.html"), recursive=True):
    s = open(f, encoding="utf-8").read()
    s = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", s, flags=re.S)
    text |= set(html.unescape(re.sub(r"<[^>]+>", " ", s)))
text = "".join(sorted(c for c in text if c.isprintable()))
fonts = os.path.join(here, "templates", "fonts")
with open(os.path.join(fonts, "chars.txt"), "w", encoding="utf-8") as f:
    f.write(text + "\n")
for src, name in ((sys.argv[1], "serif-light.woff2"), (sys.argv[2], "serif-black.woff2")):
    subprocess.run(["pyftsubset", src, "--text-file=" + os.path.join(fonts, "chars.txt"),
                    "--flavor=woff2", "--layout-features=kern,palt,vert,vrt2,locl",
                    "--no-hinting", "--desubroutinize",
                    "--output-file=" + os.path.join(fonts, name)], check=True)
    print(name, len(text), "characters,", os.path.getsize(os.path.join(fonts, name)), "bytes")
