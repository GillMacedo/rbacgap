---
name: checking-operator-rbac
description: Checks a Go Kubernetes operator or controller for API calls its RBAC doesn't grant. Type-checks the code, maps every controller-runtime and client-go call (Get, List, Create, Update, Patch, Delete, Status().Update, CreateOrUpdate, For/Owns watches, event recorders, typed clientsets, shared informers) to the group, resource and verb it needs, and compares them with +kubebuilder:rbac markers or a Role/ClusterRole YAML file. Use when an operator logs "forbidden" or "cannot list resource", when a cached Get hangs, after adding a new resource or client call, when reviewing a controller PR, or before releasing an operator.
---

# Checking an operator's RBAC against its code

The bundled tool needs Go 1.22 or newer and the operator's module dependencies (it runs `go list -export`, which compiles packages without linking). It never runs the operator's code, never talks to a cluster, and never edits files.

## 1. Find what to check

- **The binary.** Find the manager's `main` package: `cmd/main.go`, `cmd/manager/main.go` or `main.go` in kubebuilder and Operator SDK projects. Each binary with its own ServiceAccount has its own RBAC, so check each one separately by passing its package. The tool checks that package and every package of the module it imports.
- **The RBAC.** If the code has `// +kubebuilder:rbac:` markers, the tool reads them itself. If the RBAC is a hand-written file, pass it with `--role`, once per file: `config/rbac/role.yaml`, a file under `deploy/`, or `kubectl get clusterrole NAME -o yaml` saved to a file. Helm templates must be rendered first with `helm template`, then split so each file holds plain Role or ClusterRole documents. Leader election RBAC (leases, and configmaps for old versions) usually lives in a separate role that isn't in the markers; that's expected and not checked.

## 2. Run it

Run from the operator's module directory, so the same Go toolchain builds the tool and the code:

    go run "${CLAUDE_PLUGIN_ROOT}/scripts/rbacgap.go" ./cmd

Add `--role config/rbac/role.yaml` for a role file, `--format json` to parse the result, `--calls` to list every call and what it needs, and `--unused` to list granted verbs no call needs. If the project needs a non-default modfile or vendoring, set `GOFLAGS` as its Makefile does.

## Exit codes

0 means every call the tool resolved is granted. It doesn't prove the operator has every permission it needs: read the UNCHECKED and GUESSED lines. 1 means MISSING permissions, or markers and role rules that grant nothing. 2 means the tool couldn't trust its input: a package that doesn't compile, a `go list` failure, a malformed live marker, a role file it can't read, no markers and no `--role`, or no API calls at all. Treat 2 as unknown, never as a pass. `--fail-on unchecked` also exits 1 for UNCHECKED and GUESSED lines, and `--fail-on none` only reports.

## Report

1. For each MISSING line, show the resource, the verbs and the call sites, and the `fix:` marker or rule. Explain the "cached client" reason when it appears: the manager's default client serves Get and List from an informer, which needs list and watch even when the code only calls Get.
2. For each MARKER line, say why it grants nothing: attached to a declaration (controller-gen ignores it, so it needs a blank line after it), an uppercase verb, or a verb that isn't a Kubernetes verb.
3. List UNCHECKED calls as not verified: unstructured objects, dynamic clients, helpers that take `client.Object`, and subresource writers held in variables. Offer to trace a helper's callers by hand if the user wants.
4. Mention PARTIAL lines (granted only in one namespace or for named objects) and MAYBE lines (only needed with some admission plugins, or if a mutate function changes status) as things to confirm, not errors.
5. Calls through a client built for another cluster are checked against this module's RBAC too. If a finding's call site uses such a client, say so instead of suggesting a marker.
6. Permissions granted by other bindings in the cluster (aggregated roles, OpenShift defaults) aren't visible to the tool. Say so if a finding may be covered that way.
7. Don't edit markers or role files unless the user asks. After an edit, rerun the tool, and for markers remind them to run `make manifests`.
