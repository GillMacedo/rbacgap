# rbacgap: find Kubernetes operator RBAC gaps before the pod logs "forbidden"

[![CI](https://github.com/GillMacedo/rbacgap/actions/workflows/ci.yml/badge.svg)](https://github.com/GillMacedo/rbacgap/actions/workflows/ci.yml) [![MIT license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**A Claude Code skill and Go CLI for people who write Kubernetes operators and controllers in Go with kubebuilder, Operator SDK, controller-runtime or client-go. It type-checks the operator's code, works out the API group, resource and verb that every client call needs, and lists the ones your `+kubebuilder:rbac` markers or Role YAML don't grant.**

RBAC mistakes in operators pass every unit test and every envtest run, because envtest's client is an admin. They show up in a real cluster as `secrets is forbidden: User "system:serviceaccount:..." cannot list resource "secrets"`, often only on the code path that runs once a week. The common causes are easy to miss in review:

- `r.Get(ctx, key, &secret)` with only `verbs=get`. The manager's default client serves reads from an informer cache, which needs `list` and `watch` too.
- `CreateOrUpdate` with `create` but no `update`, or `r.Status().Patch` with only `update` on `x/status`.
- A marker written directly above the `Reconcile` function's doc comment. controller-gen ignores markers attached to a declaration, so the permission is never generated.
- `verbs=List` or a typo like `wacth`. RBAC compares verbs exactly, so these grant nothing.
- An event recorder with no `events` marker, or a marker for `events.k8s.io` when the recorder writes core `Events`.

`rbacgap` finds these from the source, with no cluster.

## What you can ask Claude

- "Our operator logs `cannot list resource secrets`, but we only call Get. Why?"
- "I added a controller that creates Deployments and records events. Are our kubebuilder RBAC markers complete?"
- "Check the controller code against `deploy/rbac/clusterrole.yaml`."
- "Which of our `+kubebuilder:rbac` markers does controller-gen ignore?"
- "Review this PR's new client calls for missing RBAC."

## Install

As a Claude Code plugin:

    claude plugin marketplace add GillMacedo/rbacgap
    claude plugin install rbacgap@rbacgap-marketplace

Or run it directly with Go 1.22 or newer, from your operator's module directory. It has no dependencies:

    go run github.com/GillMacedo/rbacgap/plugin/scripts@latest ./cmd

## Example

`examples/bakery` is a made-up kubebuilder-style operator with five RBAC mistakes. Its markers grant `get` on secrets, `get;list;watch;create` on deployments, `List;watch` on pods, and nothing for events. Its configmaps marker sits in the `Reconcile` doc comment:

    $ make demo-broken
    MISSING  core secrets: list, watch
             internal/controller/bakery_controller.go:45 r.Get: list, watch (cached client: its informer lists and watches)
             fix:  // +kubebuilder:rbac:groups=core,resources=secrets,verbs=list;watch

    MISSING  apps deployments: update
             internal/controller/bakery_controller.go:51 ctrl.CreateOrUpdate: update (controllerutil.CreateOrUpdate)
             fix:  // +kubebuilder:rbac:groups=apps,resources=deployments,verbs=update

    MISSING  core configmaps: get, list, watch, create, update
             internal/controller/bakery_controller.go:60 ctrl.CreateOrUpdate: get (controllerutil.CreateOrUpdate reads first); list, watch (cached client: its informer lists and watches); create, update (controllerutil.CreateOrUpdate)
             fix:  // +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update

    MISSING  core pods: list
             internal/controller/bakery_controller.go:68 r.List: list (List)
             fix:  // +kubebuilder:rbac:groups=core,resources=pods,verbs=list

    MISSING  core events: create, patch
             internal/controller/bakery_controller.go:86 mgr.GetEventRecorderFor: create, patch (GetEventRecorderFor writes core/v1 Events)
             fix:  // +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

    MARKER   internal/controller/bakery_controller.go:25 +kubebuilder:rbac:groups=core,resources=pods,verbs=List;watch
             verb "List" isn't lowercase; RBAC compares verbs exactly, so it grants nothing

    MARKER   internal/controller/bakery_controller.go:35 +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update
             attached to a declaration (its doc comment, a comment inside it, or the end of its line), so controller-gen ignores it; give it its own comment with a blank line after

    UNCHECKED internal/controller/bakery_controller.go:81 r.Update: the object has interface type client.Object, so its kind is only known at runtime

    Checked 10 API calls in 2 packages against 6 +kubebuilder:rbac markers.
    2 markers or role rules don't grant what they say (MARKER or ROLE above).
    5 resources have calls that nothing checked grants. The pod will get "forbidden" errors for them.

It exits 1. `examples/bakery-fixed` is the same operator with the markers fixed. It stays quiet and exits 0:

    $ make demo-fixed
    Checked 10 API calls in 2 packages against 8 +kubebuilder:rbac markers.
    Every call rbacgap found is granted.

The examples import small stand-ins for controller-runtime, client-go and the Kubernetes API types, under `examples/stubs`, so they run offline. The stand-ins use the real import paths, type names and method signatures, which is all `rbacgap` reads. The tests also run it on a module that uses the real controller-runtime and client-go, and the results below come from real operators.

## Usage

    rbacgap [--dir DIR] [--role FILE]... [--format text|json] [--fail-on missing|unchecked|none]
            [--calls] [--unused] [packages]

Run it in the operator's module directory, or point `--dir` at it. Packages default to `./...`. Pass a manager's `main` package, such as `./cmd` or `./cmd/manager`, to check only that binary and the module packages it imports. Markers are read from the same packages.

1. **Load.** It runs `go list -e -export -compiled -deps -json` on the packages, then lists them again to make sure none is missing. The go command compiles the packages to export data, without linking or running anything.
2. **Type-check.** Each package of your module is parsed and type-checked with `go/types`, importing dependencies from that export data.
3. **Find calls.** Every call to a controller-runtime client, builder, `controllerutil` helper, event recorder, cache or field indexer, and every client-go typed client or shared informer, is mapped to an API group, resource, subresource and verb from the static type of its object argument. Generated files (`Code generated ... DO NOT EDIT.`) are skipped, since their callers are checked.
4. **Compare.** The needs are matched with the live `+kubebuilder:rbac` markers and any `--role` files, the way the API server matches RBAC rules.

- **`--role FILE`** adds the rules of every Role and ClusterRole in a YAML or JSON file, such as `config/rbac/role.yaml`, a file from `kustomize build`, or `kubectl get clusterrole NAME -o yaml`. Repeat it for more files. Other kinds in the file are skipped.
- **`--calls`** lists every call site and what it needs. **`--unused`** lists granted verbs that no call needs.
- **`--format json`** prints the same report for scripts and agents.
- **`--fail-on`** picks what exits 1: `missing` (the default: missing permissions, and markers or role rules that grant nothing), `unchecked` (also UNCHECKED calls and GUESSED plurals) or `none`.

Exit 0 means every call it resolved is granted. Exit 1 means findings, as set by `--fail-on`. Exit 2 means bad usage or input it couldn't trust: a package that doesn't compile, `go list` failing or returning short or invalid output, a malformed live marker (controller-gen would fail on it too), a role file that's empty, not a role or possibly cut off, a CRD file missing its names, no markers and no `--role`, or no API calls at all. Exit 2 ignores `--fail-on` and prints no summary.

## What it reports

| Line | Exit 1? | Meaning |
|---|---|---|
| `MISSING` | yes | A call needs this verb on this resource and nothing grants it. A `fix:` line shows the marker or rule to add |
| `MARKER` / `ROLE` | yes | A marker or role rule grants nothing: attached to a declaration, a verb that isn't lowercase or isn't a Kubernetes verb, or an uppercase resource |
| `PARTIAL` | no | Granted only in one namespace (`namespace=` markers, Role files) or only for named objects (`resourceNames`) |
| `MAYBE` | no | Needed only with some cluster settings: update on the owner's `finalizers` for `SetControllerReference` with the `OwnerReferencesPermissionEnforcement` admission plugin, or a status patch from `CreateOrPatch` |
| `UNCHECKED` | with `--fail-on unchecked` | A call whose kind is only known at runtime: an `Unstructured` or `PartialObjectMetadata` object, a dynamic client, a helper that takes `client.Object`, a subresource writer held in a variable |
| `GUESSED` | with `--fail-on unchecked` | A custom resource whose plural came from English rules, because no `+kubebuilder:resource:path` marker or CRD file in the module names it |
| `UNUSED` | no | With `--unused`: a granted verb that no call found needs |

What each call needs:

| Call | Needs |
|---|---|
| `Get`, `List` on the manager's client | get or list, plus list and watch for the informer cache |
| `Get`, `List` on `mgr.GetAPIReader()`, or a field named like `APIReader` | get or list only |
| `Create`, `Update`, `Patch`, `Apply`, `Delete`, `DeleteAllOf` | create, update, patch, patch, delete, deletecollection |
| `Status().Update` / `Patch`, `SubResource("scale").Update` | update or patch on `x/status`, `x/scale` |
| `SubResource("eviction").Create` | create on `pods/eviction` |
| `For`, `Owns`, `Watches`, `source.Kind`, `IndexField`, `GetInformer` | list, watch |
| `controllerutil.CreateOrUpdate` / `CreateOrPatch` | get (plus list and watch through the cache), create, update or patch |
| `GetEventRecorderFor` / `GetEventRecorder` | create, patch on `events` in the core group / in `events.k8s.io` |
| client-go `Pods(ns).Get`, `UpdateStatus`, `GetScale`, `Evict`, `GetLogs`, ... | the verb and subresource of the method |
| client-go `Informer()`, `Lister()` | list, watch |

## How it compares

- **controller-gen** turns markers into a role. It doesn't know what the code calls.
- **audit2rbac and audicia** build roles from a cluster's audit log, after the operator has run. They need a cluster and a run that reaches every code path. `rbacgap` reads the code, so it works in a pull request.
- **krane, rbac-tool and kube-rbac-extractor** analyze roles and manifests. They don't read Go code.
- **envtest** runs with an admin client, so it never sees a missing permission.

I searched GitHub and the web for tools that compare an operator's client calls with its RBAC markers and found none. Keyword search can miss projects.

## Limits

- **Calls through a client for another cluster** are checked against this module's RBAC too. It can't tell which cluster a client talks to.
- **Permissions from other bindings** in the cluster, such as aggregated roles or OpenShift defaults, aren't visible.
- **Cache settings aren't read.** `cache.Options{ByObject: ...}` and `client.CacheOptions{DisableFor: ...}` can make a read skip the cache. The tool assumes the manager's client caches, apart from the API reader and fields or variables named like `APIReader` or `uncached`.
- **Method values and generic helpers** (`del := r.Delete`, a function that takes `client.Object`) are UNCHECKED, not followed.
- **Files from Kubernetes' client generators** (`client-gen`, `informer-gen`, `lister-gen`, `applyconfiguration-gen`) are skipped, since their callers are checked. Other generated files are checked.
- **Leader election RBAC** (leases) usually lives in its own role and isn't checked.
- **Helm templates** must be rendered with `helm template` before `--role` can read them, and kustomize patches with `kustomize build`.
- **The role file reader** understands the plain YAML layout that kubectl, kustomize and controller-gen write, with block or one-line flow lists, and the `kind: List` layout `kubectl get -o yaml` prints, in YAML or JSON. Anchors, multi-line flow lists and tabs are rejected with exit 2, not guessed.
- **The Go toolchain must match.** Run it from the operator's module so the same `go` builds both. A tool built with an older Go can't read newer export data and exits 2.

## FAQ

**Why does my operator need `list` and `watch` when it only calls `Get`?** controller-runtime's manager client reads from an informer cache. The first `Get` for a type starts an informer, which lists and watches that type. Without those verbs the informer can't sync, and the `Get` fails or waits. Reading through `mgr.GetAPIReader()` skips the cache and needs only `get`.

**Why is my `+kubebuilder:rbac` marker ignored?** controller-gen reads RBAC markers only from comments that stand alone, or from the package doc comment. A marker directly above `func Reconcile`, inside the function's doc comment, is attached to the function and skipped. Leave a blank line between the markers and the doc comment, as the kubebuilder scaffold does. `rbacgap` reports these as `MARKER` lines.

**Does it need a cluster?** No. It reads source code and never connects to anything.

**Does it run my code?** No. `go list -export` compiles packages to export data, without linking or running them.

**Does it need network access?** Only if the module's dependencies aren't in the module cache yet, in which case `go list` downloads them as `go build` would.

**What about Operator SDK, OLM bundles or Helm-based RBAC?** Operator SDK Go projects use the same markers. For a hand-written role, a `kustomize build` output or a rendered Helm chart, pass the file with `--role`.

**Is it an MCP server?** No. It's a skill with one standard-library Go file, so `go run` is the whole install.

## Tested on

- Unit tests for marker parsing (checked against controller-gen), RBAC matching, plural rules, the placement rules for inert markers, the role file reader, generated-file detection and exit codes.
- Marker placement and syntax were checked against real controller-gen v0.17.0, v0.20.0 and v0.23.0 output: only standalone markers and the package doc comment count, `core` and `""` both mean the core group, verbs keep their case, and `verbs=get;create,update;list` makes controller-gen fail. v0.14.0 wouldn't build with Go 1.27, so older versions weren't checked.
- Integration tests in `tests/` that run the built tool on `examples/bakery`, its fixed copy, and `tests/testdata/realop`, a module written against the real controller-runtime v0.18.6 and client-go v0.30.1. It covers cached and API-reader reads, `CreateOrUpdate`, status patches, `DeleteAllOf`, eviction, typed clientsets, shared informers and event recorders, plus a fixed copy that must stay quiet. Every Go file, `go.mod`, a stub dependency file, the CRD file and the `--role` file were replaced with an empty file, garbage, a file cut off partway, `go build` failure output and `go test` failure output. A fake `go` command returned empty, garbage, cut-off, short, failing and export-less `go list` output. None of these prints a clean result, and none exits 0 under `--fail-on missing` or `--fail-on unchecked`.
- An independent review that tried to make it report a false pass. It found ten problems, all fixed with tests: method values such as `del := r.Delete` and user interfaces wrapping the client were skipped, end-of-line markers on one-line declarations were counted though controller-gen ignores them, any "Code generated" file was skipped (which also hid cgo files), the metadata client, generic informers and raw REST requests were skipped, a namespaced grant was accepted for a cluster-scoped resource, quoted commas and misindented items in role YAML were misread, two CRD files with different plurals were accepted, and a self-referential list type crashed the tool.
- Go 1.22.12 and Go 1.27.3 on linux/arm64, with `-race`. The CI workflow runs the same tests on linux/amd64 with Go 1.22 and the latest stable Go.

Run on real operators on 2026-11-07, at the commit before a merged RBAC fix:

- **Randsw/schema-registry-operator-strimzi** (base of PR 272): MISSING `kafkas: get, list, watch` and `kafkausers: list, watch`, the two markers that PR added.
- **ironcore-dev/metal-maintenance-operator** (base of PR 108): MISSING patch on `servers` and `servers/status`, everything on `serverclaims`, and create on `secrets`. PR 108 added markers for each of these.
- **openshift/lightspeed-hub** (base of PR 28): MISSING `watch` on deployments, which PR 28 added. It also reports namespaces and configmaps calls made through a client for another cluster, which this tool can't tell apart.
- **VictoriaMetrics/operator** (base of PR 2543): all 146 of its markers are reported as MARKER, because they're attached to `Reconcile` functions. PR 2543 found the same and added a check for it. With `--role config/rbac/role.yaml`, it reports MISSING `pods: patch, delete`, both of which PR 2543 granted.

Run on default branches, where nothing was known to be broken:

- **kubebuilder's CronJob tutorial and its three testdata projects**: no MISSING lines, exit 0. Two of them get a GUESSED note for cert-manager's `certificates`, a third-party type with no CRD file in the module.
- **kubernetes-sigs/node-feature-discovery** `nfd-master` with `--role` on its ClusterRole: no MISSING lines. Removing `watch` from one of its rules gives three MISSING lines.
- **kubernetes-sigs/lws**: MISSING for the NVIDIA ComputeDomain and Volcano integrations, which lws grants through optional kustomize components that the default `kustomize build` output doesn't include. That output, 20 documents, was read with `--role`.
- **kubernetes-sigs/jobset**: MISSING `update` on `pods/status` for the exclusive placement code path, where its markers grant update on `pods` only. I couldn't confirm in a cluster whether that's a real bug.
- **red-hat-storage/odf-operator** manager: MISSING list and watch on three `console.openshift.io` resources read through the cached client. OpenShift may grant those reads through a default role, which the tool can't see.

Not tested: running the operators in a cluster, Windows or macOS as the machine running the tool, controller-runtime versions before v0.18, Helm charts rendered with `helm template`, and use in a fresh Claude session.

## Contributing

Contributions are welcome, from people and from people working with AI agents. See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues are [listed here](https://github.com/GillMacedo/rbacgap/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).

### How pull requests work

1. **Open a PR.** Fork the repo, work on a branch, and keep it to one change. Write a title that says what changes for users, because it becomes the changelog line: `feat:` goes under Added and `fix:` under Fixed.
2. **Automatic check.** Code changes need tests, and `make test` must pass. Changes over 30 lines need a linked open issue (`Closes #<number>`), and a PR can have at most 800 changed lines. If something is missing, a comment tells you what to fix.
3. **Review.** Claude reviews each PR automatically. Code PRs also get a security review and are tested in a sandbox. The review then merges the PR or asks for changes, and a small problem may become a follow-up issue instead. A PR with no new commit 14 days after a change request is closed, and you can reopen it. PRs that change CI, agent settings, npm or Python dependencies, vendored code or build files can't be merged this way, and a comment says so. The same goes for anything the security review doesn't clear.
4. **Release.** A merge that changes what users install becomes a new version within about two hours, with a GitHub Release and, if the project has one, its npm package. Docs and CI changes wait for the next release.

## AI disclosure

This project was largely generated with Claude Code and reviewed by its maintainer.

## About me

I'm Giulliano Macedo, and I build developer tools at GoTech Solutions. Follow along or get in touch:

- GitHub: [GillMacedo](https://github.com/GillMacedo)
- LinkedIn: [giulliano](https://www.linkedin.com/in/giulliano/)
- X: [@giumacedo](https://x.com/giumacedo)

If `rbacgap` saved you some prompts, a star helps others find it.

---

Built by [Giulliano Macedo](https://github.com/GillMacedo), GoTech Solutions · [LinkedIn](https://www.linkedin.com/in/giulliano/) · [X](https://x.com/giumacedo)
