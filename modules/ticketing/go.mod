module github.com/periapsis-im/periapsis/modules/ticketing

go 1.26.0

toolchain go1.26.7

replace github.com/periapsis-im/periapsis/modules/customfields => ../customfields

require (
	github.com/periapsis-im/periapsis/modules/customfields v0.0.0
	github.com/yuin/goldmark v1.8.5
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
