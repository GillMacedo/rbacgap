# rbacgap

Claude Code skill and Go CLI that finds Kubernetes API calls in a Go operator or controller that its `+kubebuilder:rbac` markers or role YAML don't grant, and markers that controller-gen ignores.

## Architecture
`plugin/scripts/rbacgap.go` holds all the logic in one standard-library file, so `go run` needs no setup. `goList` runs `go list -e -export -compiled -deps -json` and `crossCheck` confirms no matched package is missing. `typeCheck` parses the module's packages and type-checks them with `go/types`, importing dependencies from export data. `markers` reads live `+kubebuilder:rbac` markers and flags inert ones the way controller-gen places them. `walk` and `call` map controller-runtime and client-go calls to needs (group, resource, verb). `compare` matches needs with grants using Kubernetes RBAC rules. `readRoleFile` reads `--role` YAML or JSON. `plugin/skills/checking-operator-rbac/SKILL.md` tells Claude how to use it. See `docs/architecture.md`.

## Commands
- `make test`: gofmt, vet, unit tests and the integration tests in `tests/`
- `make lint`: plugin and marketplace manifest validation
- `make demo`: the two README examples on `examples/bakery` and `examples/bakery-fixed`

## Conventions
- Standard library only. Never run the code being checked and never contact a cluster; `go list` is the only command it runs.
- Any input it can't fully trust (a package that doesn't type-check, a `go list` failure or short output, a malformed live marker, an unreadable role file, a cut-off CRD file) exits 2 and never prints a clean summary.
- A call it can't map to a permission is UNCHECKED, never granted. A plural it had to guess is GUESSED.
- Match RBAC the way the API server does: verbs and resources are compared exactly, `*` and `*/sub` are wildcards, resourceNames never grant list, watch, create or deletecollection.
- Marker placement must follow controller-gen: only markers that stand alone or sit in the package doc comment count. Check any change against real controller-gen output.
- Tests must not assume the host GOOS or GOARCH.

## Do and don't
- Do keep README examples as real output from `make demo-broken` and `make demo-fixed`.
- Do add a test with the real API shape for every new call pattern, plus a healthy case that stays quiet.
- Don't claim a finding is a bug in a real project without checking its role files and cache settings.

## Definition of done
`make test`, `make lint` and `make demo` pass, and `ROADMAP.md`, `README.md` and docs are updated when relevant.
