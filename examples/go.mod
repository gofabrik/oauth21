module github.com/gofabrik/oauth21/examples

go 1.26.0

toolchain go1.26.10

replace github.com/gofabrik/oauth21 => ../

require (
	github.com/gofabrik/oauth21 v0.0.0
	go.uber.org/goleak v1.3.0
	golang.org/x/oauth2 v0.36.0
)
