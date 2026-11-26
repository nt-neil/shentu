// Package rules holds Shentu's own rules for injection-class vulnerabilities in
// application code (PHP, Python, JavaScript). Each rule is one TOML file at
// rules/<lang>/<class>/<id>.toml; the format and the way rules are added are in
// README.md. Package rules/engine applies them; rules_test.go checks the format.
package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed */*/*.toml
var files embed.FS

// Rule describes one source-to-sink pattern: user input (Sources) that reaches a
// dangerous call (Sinks) without passing through a sanitizer is a finding. A rule
// with no sources is about how a call is made (a weak cipher, a password written
// in the code): every sink call whose argument conditions hold is a finding.
type Rule struct {
	ID         string   `toml:"id"`
	Lang       string   `toml:"lang"`
	Class      string   `toml:"class"`
	CWE        string   `toml:"cwe"`
	Severity   string   `toml:"severity"`
	Tier       string   `toml:"tier"` // "info" (the default): shown in app_code_audit and chat only; "alert": also in the patrol report; "reference" (no sources only): listed last, counted in one line of the daily report, never given to attack detection
	Title      string   `toml:"title"`
	Frameworks []string `toml:"frameworks"`
	// RouteInput false: a route handler's parameters are not this rule's
	// input, only its sources are (a rule for the Host header: the query a
	// route model makes input is not the host).
	RouteInput *bool        `toml:"route_input"`
	Sources    []string     `toml:"sources"`
	Sinks      []string     `toml:"sinks"`
	Sanitizers []string     `toml:"sanitizers"`
	Text       []string     `toml:"text"`        // entries of Sources or Sinks matched inside string literals
	Args       []Args       `toml:"args"`        // conditions on a sink call's arguments
	SourceArgs []SourceArgs `toml:"source_args"` // sources that are input only with a given argument
	Fix        string       `toml:"fix"`
	Refs       []string     `toml:"refs"`
	Samples    []Sample     `toml:"samples"`

	// RouteMembers: of the members a route model makes input (Express req.query,
	// req.params), only these are this rule's (a rule for a query object: a
	// path parameter is always a string). Unset: all of them.
	RouteMembers []string `toml:"route_members"`
	// RouteNot: values under those members that are not this rule's input,
	// written member.name (headers.host: the Host header, which another rule
	// takes), read as req.headers.host or req.headers['host'].
	RouteNot []string `toml:"route_not"`
	// RouteOnly: with it, a route model's input is this rule's only for these
	// values, written as in route_not, whatever the handler's parameter is
	// called (the Host header under (r, s) => r.headers.host, which another
	// rule leaves with route_not); route_input = false does not turn it off.
	RouteOnly []string `toml:"route_only"`
	// YieldsTo: rules (of the same language and CWE) this one leaves a sink
	// to when both report it: a finding of this rule is left out where one of
	// them reports the same line through the same sink call, one call holding
	// the other (DB::raw(...) inside DB::select(...)). Another sink on that
	// line, or a sink the analysis did not see written out (a function's
	// summary, a text sink), still reports.
	YieldsTo []string `toml:"yields_to"`

	// ChainNot: calls the chain form of the rule's receiver.method( sinks may
	// not go through (chain.go): they make another object, another rule's
	// (httpx.AsyncClient().get( is an async client's call, not httpx.get().
	ChainNot []string `toml:"chain_not"`

	// RoutesNot: route models (by id) whose handlers' input is not this
	// rule's: another rule is for it (wp-shortcode's attributes are
	// php-xss-shortcode-attribute's).
	RoutesNot []string `toml:"routes_not"`

	File string `toml:"-"` // path inside rules/, set by Load
}

// Args describes which argument of a sink call carries the attack, and when the
// call is or is not dangerous because of its other arguments.
type Args struct {
	Sinks    []string `toml:"sinks"`    // the rule's sinks this applies to; empty means all
	Arg      *int     `toml:"arg"`      // the argument (from 1) that must be tainted; 0 is the receiver; nil is any
	Name     string   `toml:"name"`     // that argument's parameter name, for PHP named (name: $x) and Python keyword (name=x) arguments
	When     []string `toml:"when"`     // the call is a sink only if one of these is among its arguments
	Unless   []string `toml:"unless"`   // the call is not a sink if one of these is among its arguments
	Whole    bool     `toml:"whole"`    // the argument must be the input itself, not a literal holding a part of it
	Leading  bool     `toml:"leading"`  // the input must be at the start of the argument; a fixed prefix makes the call safe
	Context  []string `toml:"context"`  // output sinks: only input written in one of these HTML contexts counts (html, attr, url, js)
	Markup   bool     `toml:"markup"`   // with context: only input written after markup in the same value ('<p>' + x); a body with none may be JSON or text
	Literal  bool     `toml:"literal"`  // the argument (arg, or the value of a when option) must be a non-empty string literal
	Key      string   `toml:"key"`      // the argument is an object, dict or array: only the value under this key counts (any case)
	Keys     bool     `toml:"keys"`     // an argument that is an array, object or dict literal counts by its keys only, not its values
	MinLen   int      `toml:"min_len"`  // with literal: the string must be at least this long
	Exclude  []string `toml:"exclude"`  // with literal: a string matching one of these regular expressions (any case) does not count
	Receiver []string `toml:"receiver"` // a method sink counts only when its receiver, followed through the file's assignments and annotations, holds one of these
	// NotReceiver: a method sink does not count on an object surely made by
	// one of these classes: new Class(...), or a name every assignment of the
	// file gives such an object ($q = new WP_Query; $q->query($args)). A
	// receiver the file says nothing about still counts. An entry written as a
	// variable ($wpdb) names the object itself: WordPress's global wpdb.
	NotReceiver []string `toml:"not_receiver"`
	// UnlessAfter: the SQL text (or other text) does not count when every
	// value from the input in it comes after one of these texts (any case)
	// in a string written in the call: "... ORDER BY $col" is
	// php-sqli-orderby-identifier's, which reports it at that text.
	UnlessAfter []string `toml:"unless_after"`
	// UnlessAt narrows where unless looks: "start", only at the start of the
	// argument (arg, or the first): a Server-Sent Events line "data: " + x;
	// "top", only as an element or key of the argument itself (arg, or any
	// one), not inside what it holds: TypeORM's { relations: [...] }, not
	// { projection: { relations: 1 } }. Empty: anywhere among the arguments.
	UnlessAt string `toml:"unless_at"`
	// UnlessContentType: the call is not a sink once the response's
	// Content-Type was set to one of these on every path before it, in the
	// same function (res.setHeader("Content-Type", "text/event-stream"),
	// res.type(...), res.writeHead(200, {...})): a
	// Server-Sent Events stream is read by EventSource, not rendered.
	UnlessContentType []string `toml:"unless_content_type"`
	// UnlessImports: a method sink does not count in a file importing one of
	// these modules (import ... from 'typeorm', require('typeorm')), unless the
	// file also names one of UnlessImportsNot (an identifier or an imported
	// module) or the receiver does: a TypeORM repository's find() on an SQL
	// database binds its where as parameters, its MongoRepository does not.
	UnlessImports    []string `toml:"unless_imports"`
	UnlessImportsNot []string `toml:"unless_imports_not"`
	// UnlessSubscript: the argument does not count when it is, as a whole, one
	// item of one of these (request.files["f"]): an uploaded file's stream,
	// which zipfile.ZipFile reads as a file object, not a path. Written in the
	// call only, not through a variable.
	UnlessSubscript []string `toml:"unless_subscript"`
}

// SourceArgs makes call sources input only when an argument is one of a few
// strings: Joomla's $input->get($name, $default, 'raw') returns the raw value,
// while the default filter ('cmd') leaves only safe characters.
type SourceArgs struct {
	Sources []string `toml:"sources"` // the rule's call sources this applies to
	Arg     int      `toml:"arg"`     // the argument (from 1) that must be a string literal
	Values  []string `toml:"values"`  // the values (any case) that make the call a source; any other value, or none, does not; "*": any string literal; "!x": never x; "?": an argument that is not a string literal
}

// Sample is a minimal, self-written snippet: "vulnerable" must be reported, "safe" must not.
type Sample struct {
	Kind    string `toml:"kind"`
	Code    string `toml:"code"`
	Note    string `toml:"note"`
	Dialect string `toml:"dialect"` // js rules only: "ts" or "tsx" when the sample is TypeScript
}

// Load parses every rule file. Unknown keys are an error, so a typo in a field
// name cannot silently drop it.
func Load() ([]Rule, error) {
	var out []Rule
	err := fs.WalkDir(files, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".toml") || strings.HasPrefix(path, "routes/") {
			return err
		}
		b, err := files.ReadFile(path)
		if err != nil {
			return err
		}
		var r Rule
		md, err := toml.Decode(string(b), &r)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if extra := md.Undecoded(); len(extra) > 0 {
			return fmt.Errorf("%s: unknown keys %v", path, extra)
		}
		if !md.IsDefined("sources") {
			return fmt.Errorf("%s: sources must be present (use [] for a rule about how a call is made, not about input)", path)
		}
		if !md.IsDefined("sanitizers") {
			return fmt.Errorf("%s: sanitizers must be present (use [] when nothing makes input safe for these sinks)", path)
		}
		if r.Tier == "" {
			r.Tier = "info"
		}
		r.File = path
		out = append(out, r)
		return nil
	})
	return out, err
}

// Route is a framework's route model (rules/routes/<lang>/<framework>.toml):
// how the framework hands request data to the application's own functions,
// so that their parameters count as input for every rule of the language,
// without each rule listing them as sources.
//
// A handler is found three ways: a call registering it (Register: the
// handler is argument Handler, or the value of Key in that argument);
// a decorator above it (Decorator, Python); or a method of that name in a
// class extending Extends. Its parameters carrying input are Params (from
// 1; empty: all), or with Template only those named in the route's path
// (the first argument: Flask <name>, FastAPI and Laravel {name}); Members
// limits the input to those members of the parameter (Express req.query).
type Route struct {
	ID        string   `toml:"id"`
	Lang      string   `toml:"lang"`
	Framework string   `toml:"framework"`
	Title     string   `toml:"title"`
	Register  []string `toml:"register"`  // calls registering a handler: add_shortcode, Route::get, *.get (any receiver)
	Decorator []string `toml:"decorator"` // decorators marking the function under them: *.route
	Extends   string   `toml:"extends"`   // with Method: a method of a class extending this one (WP_Widget::widget)
	Method    string   `toml:"method"`
	Handler   int      `toml:"handler"`  // the argument (from 1) holding the handler; -1: the last
	Key       string   `toml:"key"`      // the handler is this key of that argument (register_rest_route's 'callback')
	Path      bool     `toml:"path"`     // the call counts only when its first argument is a path ('/...')
	Params    []int    `toml:"params"`   // the handler's parameters (from 1) carrying input; empty: all
	Template  bool     `toml:"template"` // only the parameters the path template names
	Members   []string `toml:"members"`  // only these members of the parameters (query, params, body)
	// NamedMembers: for a parameter of that name, these members instead (Koa's
	// ctx under an Express-like registration: ctx.body is the response, the
	// request's body is ctx.request.body).
	NamedMembers map[string][]string `toml:"named_members"`
	Requires     []string            `toml:"requires"`   // the model applies to a file naming one of these (an import: fastapi)
	Exclude      []string            `toml:"exclude"`    // a parameter declared with one of these is no input (Depends)
	Bound        bool                `toml:"bound"`      // a parameter declared with a class type is an object the framework looked up (Laravel route model binding), no input
	Sources      []string            `toml:"sources"`    // further sources (get_settings_for_display), for the rules the model is for
	InClasses    []string            `toml:"in_classes"` // a source called on $this counts only in a class extending one of these; on another object ($widget->), everywhere
	ThisOnly     bool                `toml:"this_only"`  // a source counts only on $this or $this->parent (an Elementor skin's widget), not on another object ($section->get_settings(): a settings page's)
	Clears       []string            `toml:"clears"`     // calls returning what the framework itself stored for an id (get_attached_file(): a path it wrote), not the request's input
	ClearsFor    []string            `toml:"clears_for"` // the rule classes Clears is for (path-traversal): a stored value may still be one an attacker wrote, so not for every class
	Applies      []string            `toml:"applies"`    // the request's roots ($_POST, req.body): a rule all of whose sources are one field under them (a password) is not one the model is for
	Note         string              `toml:"note"`
	Refs         []string            `toml:"refs"`
	Samples      []Sample            `toml:"samples"`

	File string `toml:"-"`
}

// LoadRoutes parses the route models. As with rules, unknown keys are an error.
func LoadRoutes() ([]Route, error) {
	var out []Route
	err := fs.WalkDir(files, "routes", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".toml") {
			return err
		}
		b, err := files.ReadFile(path)
		if err != nil {
			return err
		}
		var f struct {
			Route []Route `toml:"route"`
		}
		md, err := toml.Decode(string(b), &f)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if extra := md.Undecoded(); len(extra) > 0 {
			return fmt.Errorf("%s: unknown keys %v", path, extra)
		}
		for i := range f.Route {
			f.Route[i].File = path
		}
		out = append(out, f.Route...)
		return nil
	})
	return out, err
}
