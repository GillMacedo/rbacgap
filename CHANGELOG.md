# Changelog

All notable changes are documented here, in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-07

### Added
- Type-checks a Go operator's packages with export data from `go list -export` and maps controller-runtime calls to RBAC needs: client Get, List, Watch, Create, Update, Patch, Apply, Delete and DeleteAllOf, `Status()` and `SubResource()` writers, builder `For`, `Owns` and `Watches`, `source.Kind`, `controllerutil.CreateOrUpdate` and `CreateOrPatch`, `SetControllerReference`, event recorders, `IndexField` and `GetInformer`.
- Adds the list and watch that a Get or List through the manager's cached client needs, and leaves them out for the API reader.
- Maps client-go typed clientsets (including subresources such as `UpdateStatus`, `GetScale`, `Evict` and `GetLogs`) and shared informers, and generated clientsets for custom resources.
- Finds API groups from `+groupName` or a `GroupVersion` literal, and plurals from `+kubebuilder:resource:path`, CRD YAML in the module, or English rules, which it labels as guessed.
- Reads `+kubebuilder:rbac` markers and reports markers controller-gen ignores (attached to a declaration), verbs that aren't lowercase or aren't Kubernetes verbs, and resources that aren't lowercase.
- Reports method values, the metadata and dynamic clients, generic informers and raw REST requests as UNCHECKED, checks calls through user interfaces that wrap the client, and never lets a Role or `namespace=` marker grant a cluster-scoped resource.
- `--role` to compare with Role and ClusterRole YAML or JSON files.
- MISSING, PARTIAL (one namespace or named objects only), MAYBE, UNCHECKED and GUESSED lines, `--calls`, `--unused`, `--format json`, `--fail-on`, and exit 2 for any input it can't trust.
- `checking-operator-rbac` skill and plugin manifest.
