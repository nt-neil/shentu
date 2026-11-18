module github.com/nt-neil/shentu/tools/detecteval

go 1.26.0

// The Go every run uses, here and in CI: the graded hash is of what the
// matching makes of the requests, which a Go release may change.
toolchain go1.27.4

require (
	github.com/BurntSushi/toml v1.4.0
	github.com/nt-neil/shentu v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

require golang.org/x/sys v0.50.0 // indirect

replace github.com/nt-neil/shentu => ../..
