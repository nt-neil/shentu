package main

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
)

// Ordinary requests to the applications of the E7 corpus, for the false
// positive rate. Each route is one the application serves out of the box;
// its source is said by the app. A route's {name} is filled from words of
// that name, its query parameters likewise. No real host or account:
// referers are example.com.
type app struct {
	Name, Source string
	Routes       []route
}

type route struct {
	Method, Path string
	Query        []string // parameter names, filled from fillers
}

var apps = []app{
	{"wordpress", "WordPress core: wp-includes/class-wp-rewrite.php (permalinks), wp-login.php, wp-includes/rest-api/endpoints/*.php (REST API handbook, developer.wordpress.org/rest-api/reference)", []route{
		{"GET", "/", nil},
		{"GET", "/", []string{"s"}},
		{"GET", "/", []string{"p"}},
		{"GET", "/", []string{"page_id"}},
		{"GET", "/", []string{"cat"}},
		{"GET", "/{year}/{month}/{slug}/", nil},
		{"GET", "/category/{slug}/", nil},
		{"GET", "/tag/{slug}/", nil},
		{"GET", "/author/{user}/", nil},
		{"GET", "/page/{n}/", nil},
		{"GET", "/{slug}/", []string{"replytocom"}},
		{"GET", "/feed/", nil},
		{"GET", "/comments/feed/", nil},
		{"GET", "/wp-login.php", nil},
		{"GET", "/wp-login.php", []string{"redirect_to", "reauth"}},
		{"POST", "/wp-login.php", nil},
		{"GET", "/wp-login.php", []string{"action"}},
		{"GET", "/wp-admin/", nil},
		{"GET", "/wp-admin/edit.php", []string{"post_type", "paged"}},
		{"GET", "/wp-admin/post.php", []string{"post", "action"}},
		{"GET", "/wp-admin/upload.php", []string{"mode"}},
		{"GET", "/wp-admin/media-new.php", nil},
		{"POST", "/wp-admin/async-upload.php", nil},
		{"POST", "/wp-admin/admin-ajax.php", nil},
		{"GET", "/wp-admin/admin-ajax.php", []string{"action"}},
		{"POST", "/wp-comments-post.php", nil},
		{"GET", "/wp-json/", nil},
		{"GET", "/wp-json/wp/v2/posts", []string{"per_page", "page", "search"}},
		{"GET", "/wp-json/wp/v2/posts/{n}", nil},
		{"GET", "/wp-json/wp/v2/categories", []string{"per_page"}},
		{"GET", "/wp-json/wp/v2/media", []string{"media_type"}},
		{"GET", "/wp-content/uploads/{year}/{month}/{file}", nil},
		{"GET", "/wp-content/themes/twentytwentyfive/style.css", []string{"ver"}},
		{"GET", "/wp-includes/js/jquery/jquery.min.js", []string{"ver"}},
		{"GET", "/xmlrpc.php", []string{"rsd"}},
		{"GET", "/wp-cron.php", []string{"doing_wp_cron"}},
	}},
	{"django", "Django: django/contrib/admin/sites.py (AdminSite.get_urls), django/contrib/admin/options.py (ModelAdmin.get_urls, changelist ?q= ?o= ?p=), django/contrib/auth/urls.py", []route{
		{"GET", "/admin/", nil},
		{"GET", "/admin/login/", []string{"next"}},
		{"POST", "/admin/login/", nil},
		{"GET", "/admin/logout/", nil},
		{"GET", "/admin/{model}/", []string{"q"}},
		{"GET", "/admin/{model}/", []string{"o", "p"}},
		{"GET", "/admin/{model}/add/", nil},
		{"POST", "/admin/{model}/add/", nil},
		{"GET", "/admin/{model}/{n}/change/", nil},
		{"GET", "/admin/{model}/{n}/history/", nil},
		{"GET", "/admin/jsi18n/", nil},
		{"GET", "/accounts/login/", []string{"next"}},
		{"GET", "/accounts/password_reset/", nil},
		{"GET", "/accounts/reset/done/", nil},
		{"GET", "/static/admin/css/base.css", nil},
		{"GET", "/static/admin/js/core.js", nil},
	}},
	{"flask", "Flask: docs/tutorial (flaskr: flaskr/auth.py, flaskr/blog.py), docs/patterns/fileuploads.rst, docs/patterns/viewdecorators.rst", []route{
		{"GET", "/", nil},
		{"GET", "/auth/register", nil},
		{"POST", "/auth/register", nil},
		{"GET", "/auth/login", []string{"next"}},
		{"POST", "/auth/login", nil},
		{"GET", "/auth/logout", nil},
		{"GET", "/create", nil},
		{"POST", "/create", nil},
		{"GET", "/{n}/update", nil},
		{"POST", "/{n}/delete", nil},
		{"GET", "/upload", nil},
		{"POST", "/upload", nil},
		{"GET", "/uploads/{file}", nil},
		{"GET", "/search", []string{"q"}},
		{"GET", "/static/style.css", nil},
	}},
	{"laravel", "Laravel: laravel/breeze stubs/default/routes/auth.php and routes/web.php, laravel/framework src/Illuminate/Pagination (?page=), src/Illuminate/Foundation/Configuration/ApplicationBuilder.php (/up)", []route{
		{"GET", "/", nil},
		{"GET", "/login", nil},
		{"POST", "/login", nil},
		{"POST", "/logout", nil},
		{"GET", "/register", nil},
		{"POST", "/register", nil},
		{"GET", "/forgot-password", nil},
		{"GET", "/reset-password/{token}", []string{"email"}},
		{"GET", "/verify-email", nil},
		{"GET", "/dashboard", nil},
		{"GET", "/profile", nil},
		{"PATCH", "/profile", nil},
		{"GET", "/posts", []string{"page"}},
		{"GET", "/posts", []string{"search", "sort"}},
		{"GET", "/posts/{n}", nil},
		{"GET", "/posts/{n}/edit", nil},
		{"POST", "/posts", nil},
		{"GET", "/up", nil},
		{"GET", "/build/assets/app-{token}.js", nil},
		{"GET", "/build/assets/app-{token}.css", nil},
		{"GET", "/storage/{file}", nil},
	}},
	{"express", "Express: expressjs.com/en/guide/routing.html, examples/ in expressjs/express (auth, search, downloads, static-files)", []route{
		{"GET", "/", nil},
		{"GET", "/login", nil},
		{"POST", "/login", nil},
		{"GET", "/logout", nil},
		{"GET", "/restricted", nil},
		{"GET", "/search/{word}", nil},
		{"GET", "/search", []string{"q"}},
		{"GET", "/users/{n}", nil},
		{"GET", "/users", []string{"page", "limit"}},
		{"GET", "/files/{file}", nil},
		{"GET", "/css/style.css", nil},
		{"GET", "/js/app.js", nil},
		{"POST", "/upload", nil},
	}},
	{"immich", "Immich: server/src/controllers/*.controller.ts (asset, album, search, auth, server, user)", []route{
		{"POST", "/api/auth/login", nil},
		{"POST", "/api/auth/logout", nil},
		{"GET", "/api/server/ping", nil},
		{"GET", "/api/server/version", nil},
		{"GET", "/api/server/features", nil},
		{"GET", "/api/users/me", nil},
		{"GET", "/api/albums", []string{"shared"}},
		{"GET", "/api/albums/{uuid}", []string{"withoutAssets"}},
		{"GET", "/api/assets/{uuid}", nil},
		{"GET", "/api/assets/{uuid}/thumbnail", []string{"size"}},
		{"GET", "/api/assets/{uuid}/original", nil},
		{"POST", "/api/assets", nil},
		{"POST", "/api/search/metadata", nil},
		{"POST", "/api/search/smart", nil},
		{"GET", "/api/search/explore", nil},
		{"GET", "/api/timeline/buckets", []string{"size", "isArchived"}},
		{"GET", "/photos/{uuid}", nil},
		{"GET", "/albums", nil},
		{"GET", "/search", []string{"query"}},
		{"GET", "/_app/immutable/chunks/{token}.js", nil},
	}},
	{"nest", "NestJS: docs.nestjs.com (controllers, techniques/file-upload, security/authentication, recipes/swagger, techniques/pagination examples), sample/ in nestjs/nest", []route{
		{"GET", "/", nil},
		{"POST", "/auth/login", nil},
		{"GET", "/auth/profile", nil},
		{"GET", "/cats", []string{"limit", "offset"}},
		{"GET", "/cats/{n}", nil},
		{"POST", "/cats", nil},
		{"PUT", "/cats/{n}", nil},
		{"DELETE", "/cats/{n}", nil},
		{"POST", "/upload", nil},
		{"GET", "/api", nil},
		{"GET", "/api-json", nil},
		{"GET", "/health", nil},
		{"GET", "/users", []string{"search", "page"}},
	}},
	{"next", "Next.js: nextjs.org/docs (app router: dynamic routes, route handlers, search params; next/image /_next/image; static assets /_next/static), examples/ in vercel/next.js", []route{
		{"GET", "/", nil},
		{"GET", "/blog", []string{"page"}},
		{"GET", "/blog/{slug}", nil},
		{"GET", "/search", []string{"q"}},
		{"GET", "/products/{slug}", []string{"color", "size"}},
		{"GET", "/dashboard", nil},
		{"GET", "/login", []string{"callbackUrl"}},
		{"GET", "/api/auth/session", nil},
		{"GET", "/api/auth/csrf", nil},
		{"POST", "/api/auth/callback/credentials", nil},
		{"GET", "/api/posts", []string{"cursor", "limit"}},
		{"POST", "/api/upload", nil},
		{"GET", "/_next/static/chunks/{token}.js", nil},
		{"GET", "/_next/image", []string{"url", "w", "q"}},
		{"GET", "/_next/data/{token}/blog/{slug}.json", nil},
		{"GET", "/favicon.ico", nil},
		{"GET", "/robots.txt", nil},
		{"GET", "/sitemap.xml", nil},
	}},
}

// fillers: what people put in each kind of slot. Words an ordinary user
// types, punctuation included (an apostrophe in a name, an ampersand in a
// title, a percent sign in a price).
var fillers = map[string][]string{
	"s":           {"hello world", "privacy policy", "C++ tutorial", "rock & roll", "O'Brien", "50% off", "café menu", "2026 annual report", "how to reset password", "日本 旅行", "dog-friendly hotels", "what is SELECT in SQL"},
	"q":           {"cats", "summer dresses", "Tom's diner", "price < 100", "node.js streams", "a/b testing", "new york", "1+1", "resume template", "email: help", "C# vs Java", "quotes \"to be or not\""},
	"query":       {"beach", "birthday 2025", "my dog", "sunset at the lake", "Grandma's 80th"},
	"search":      {"laravel", "draft", "John Smith", "Q3 numbers", "release notes", "order #1234"},
	"word":        {"hello", "laptops", "ice-cream", "tokyo"},
	"p":           {"1", "42", "128", "7"},
	"page_id":     {"2", "15", "301"},
	"cat":         {"1", "3", "12"},
	"page":        {"1", "2", "3", "10"},
	"paged":       {"1", "2"},
	"per_page":    {"10", "20", "100"},
	"limit":       {"10", "25", "50"},
	"offset":      {"0", "20", "40"},
	"cursor":      {"eyJpZCI6MTIzfQ", "abc123", "MTY5OTk5"},
	"o":           {"1", "-2", "2.1"},
	"sort":        {"newest", "title", "-created_at"},
	"n":           {"1", "7", "42", "1001"},
	"year":        {"2024", "2025", "2026"},
	"month":       {"01", "06", "11"},
	"slug":        {"hello-world", "about-us", "summer-sale-2026", "how-we-work", "faq"},
	"user":        {"admin", "editor", "jane"},
	"model":       {"auth/user", "blog/post", "shop/order"},
	"file":        {"photo.jpg", "report-2026.pdf", "logo.png", "IMG_2041.HEIC", "my resume (final).docx"},
	"token":       {"a1b2c3d4", "Bk9xQ2", "7f3e9a0c11"},
	"uuid":        {"3fa85f64-5717-4562-b3fc-2c963f66afa6", "9b2d1c7e-0d4b-4c1a-8e9f-1a2b3c4d5e6f"},
	"next":        {"/admin/", "/dashboard/", "/accounts/profile/"},
	"redirect_to": {"https://example.com/wp-admin/", "/wp-admin/edit.php"},
	"callbackUrl": {"/dashboard", "https://example.com/dashboard"},
	"reauth":      {"1"},
	"action":      {"lostpassword", "logout", "edit", "heartbeat", "rp"},
	"post_type":   {"page", "post"},
	"post":        {"12", "340"},
	"mode":        {"grid", "list"},
	"media_type":  {"image", "video"},
	"ver":         {"6.8.1", "3.7.1", "1.0.2"},
	"rsd":         {""},
	"doing_wp_cron": {
		"1763380800.1234560000",
	},
	"replytocom":    {"17", "203"},
	"email":         {"jane@example.com", "j.doe+news@example.com"},
	"shared":        {"true", "false"},
	"withoutAssets": {"true"},
	"size":          {"thumbnail", "preview", "M", "42"},
	"isArchived":    {"false"},
	"color":         {"navy blue", "red"},
	"url":           {"/images/hero.png", "/uploads/team photo.jpg"},
	"w":             {"640", "1080", "1920"},
}

var referers = []string{"-", "https://example.com/", "https://example.com/blog/", "https://www.example.com/search?q=shoes"}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
	"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
}

// normalRequest is one generated request: an id (app#route#n) and the
// combined log line.
type normalRequest struct{ ID, App, Line string }

// perRoute: the requests made of each route.
const perRoute = 8

// normalRequests makes the ordinary requests, the same ones every run.
func normalRequests() ([]normalRequest, error) {
	rnd := rand.New(rand.NewPCG(7, 17))
	pick := func(k string) (string, error) {
		xs, ok := fillers[k]
		if !ok {
			return "", fmt.Errorf("no filler for %q", k)
		}
		return xs[rnd.IntN(len(xs))], nil
	}
	var out []normalRequest
	for _, a := range apps {
		for ri, r := range a.Routes {
			for n := 0; n < perRoute; n++ {
				p, err := fillPath(r.Path, pick)
				if err != nil {
					return nil, err
				}
				v := url.Values{}
				for _, k := range r.Query {
					x, err := pick(k)
					if err != nil {
						return nil, err
					}
					v.Set(k, x)
				}
				tg := p
				if len(v) > 0 {
					tg += "?" + v.Encode()
				}
				line := fmt.Sprintf(`198.51.100.%d - - [17/Nov/2026:12:00:00 +0000] "%s %s HTTP/1.1" 200 2048 "%s" "%s"`,
					10+rnd.IntN(200), r.Method, tg, referers[rnd.IntN(len(referers))], userAgents[rnd.IntN(len(userAgents))])
				out = append(out, normalRequest{fmt.Sprintf("%s#%d#%d", a.Name, ri, n), a.Name, line})
			}
		}
	}
	return out, nil
}

func fillPath(p string, pick func(string) (string, error)) (string, error) {
	var b strings.Builder
	for {
		i := strings.IndexByte(p, '{')
		if i < 0 {
			b.WriteString(p)
			return b.String(), nil
		}
		j := strings.IndexByte(p[i:], '}')
		if j < 0 {
			return "", fmt.Errorf("unclosed {} in %q", p)
		}
		x, err := pick(p[i+1 : i+j])
		if err != nil {
			return "", err
		}
		b.WriteString(p[:i])
		segs := strings.Split(x, "/") // a filler of several segments (auth/user) keeps its slashes
		for k := range segs {
			segs[k] = url.PathEscape(segs[k])
		}
		b.WriteString(strings.Join(segs, "/"))
		p = p[i+j+1:]
	}
}
