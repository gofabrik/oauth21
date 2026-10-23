module github.com/gofabrik/oauth21/conformance

go 1.26.0

toolchain go1.26.9

require (
	github.com/gofabrik/oauth21 v0.0.0
	go.uber.org/goleak v1.3.0
)

replace github.com/gofabrik/oauth21 => ../
