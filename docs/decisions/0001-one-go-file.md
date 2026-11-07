# 0001: One standard-library Go file

**Decision:** the tool is a single Go file, `plugin/scripts/rbacgap.go`, using only the standard library.

**Why:** anyone writing a Go operator already has Go, so `go run` is the whole install, with no npm package or release binaries. A single file runs with `go run path/to/rbacgap.go` from inside the operator's module, which is how the skill calls it from the plugin folder, where there is no go.mod. Running inside the operator's module also means the same Go toolchain builds the tool and the operator, so the export data formats match.

**Alternatives:** `golang.org/x/tools/go/packages` would load packages with less code, but adds a dependency and still calls `go list` underneath. An MCP server would give an agent the same command with more setup and nothing a script can't do.
