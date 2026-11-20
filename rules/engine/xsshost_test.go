package engine

import (
	"slices"
	"testing"
)

// The P3-2 decisions for XSS (v0.4.3): PHP's and Python's XSS rules keep the
// Host header as input, as JavaScript's js-xss-response does not; NestJS's
// whole @Headers() object is js-xss-response's input, Host under it not.
func TestXSSHostAndHeaders(t *testing.T) {
	e := engineForTest(t)
	nest := func(v string) string {
		return "import { Controller, Get, Headers, Res } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  p(@Headers() h: any, @Res() res: any) {\n    res.send('<p>' + " + v + " + '</p>');\n  }\n}\n"
	}
	cases := []struct {
		name, lang, path, src string
		want                  []string
	}{
		{"php: $_SERVER['HTTP_HOST'] echoed", "php", "a.php", "<?php\necho '<p>' . $_SERVER['HTTP_HOST'] . '</p>';\n", []string{"php-xss-echo-html"}},
		{"python: request.headers['Host'] in an HttpResponse", "python", "a.py", "def p(request):\n    return HttpResponse('<p>' + request.headers['Host'] + '</p>')\n", []string{"python-xss-response"}},
		{"nest: @Headers() h, h['user-agent']", "ts", "a.ts", nest("h['user-agent']"), []string{"js-xss-response"}},
		{"nest: @Headers() h, the whole object", "ts", "a.ts", nest("JSON.stringify(h)"), []string{"js-xss-response"}},
		{"nest: @Headers() h, h.host is no XSS input", "ts", "a.ts", nest("h.host"), nil},
		{"nest: @Req() r, r.headers['user-agent']", "ts", "a.ts", "import { Controller, Get, Req, Res } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  p(@Req() r: any, @Res() res: any) {\n    res.send('<p>' + r.headers['user-agent'] + '</p>');\n  }\n}\n", []string{"js-xss-response"}},
		{"nest: @Req() r, r.query.q", "ts", "a.ts", "import { Controller, Get, Req, Res } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  p(@Req() r: any, @Res() res: any) {\n    res.send('<p>' + r.query.q + '</p>');\n  }\n}\n", []string{"js-xss-response"}},
		{"nest: @Req() r, r.headers.host is no XSS input", "ts", "a.ts", "import { Controller, Get, Req, Res } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  p(@Req() r: any, @Res() res: any) {\n    res.send('<p>' + r.headers.host + '</p>');\n  }\n}\n", nil},
		{"nest: @Body() b, b.name", "ts", "a.ts", "import { Controller, Post, Body, Res } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Post('p')\n  p(@Body() b: any, @Res() res: any) {\n    res.send('<p>' + b.name + '</p>');\n  }\n}\n", []string{"js-xss-response"}},
		{"nest: @Headers('host') is no XSS input", "ts", "a.ts", "import { Controller, Get, Headers, Res } from '@nestjs/common';\n@Controller()\nexport class C {\n  @Get('p')\n  p(@Headers('host') v: string, @Res() res: any) {\n    res.send('<p>' + v + '</p>');\n  }\n}\n", nil},
	}
	for _, c := range cases {
		fs, err := e.Scan(c.lang, c.path, []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range fs {
			if f.CWE == "CWE-79" && !slices.Contains(got, f.RuleID) {
				got = append(got, f.RuleID)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: XSS reported by %v, want %v", c.name, got, c.want)
		}
	}
}
