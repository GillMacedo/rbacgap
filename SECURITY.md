# Security

Report vulnerabilities through [GitHub's private vulnerability reporting](https://github.com/GillMacedo/rbacgap/security/advisories/new), not in a public issue.

`rbacgap` runs `go list -export` on the module you point it at, which compiles the module's packages and dependencies as `go build` would (including cgo, if a package uses it). It never links or runs the code it checks, never contacts a cluster, and only reads the `--role` files you name. Please report privately if a crafted module could make it do anything else.

A missed permission or a wrong finding is a normal bug, unless it could lead someone to grant much broader access than the code needs. If it could, report it privately. `rbacgap` is a diagnostic aid and doesn't enforce anything.
