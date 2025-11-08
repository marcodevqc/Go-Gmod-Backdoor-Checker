# Hello World (Go)

This is a minimal Go "Hello, world!" project.

Files:
- `main.go` — entrypoint and `Hello()` function
- `hello_test.go` — simple unit test
- `go.mod` — module file

How to run:

```bash
# Run tests
go test ./...

# Run the program
go run main.go
```

GMod addon scanner
-------------------

This repository now includes a simple Garry's Mod addon backdoor scanner implemented as a CLI.

Usage:

```bash
# scan the default ./addons folder
go run main.go -path ./addons

# write JSON output
go run main.go -path ./addons -json findings.json
```

The scanner looks for suspicious Lua and other file contents: calls to RunString/CompileString/loadstring/load, http fetches, string.char usage, high-entropy quoted strings (possible encoded payloads), and more. It's heuristic-based and intended as a first-pass scanner — review results manually.
