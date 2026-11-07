# 0003: Read markers the way controller-gen does

**Decision:** a `+kubebuilder:rbac` marker only counts if controller-gen would put it in the generated role. Markers in a declaration's doc comment or inside a declaration are reported as inert, verbs keep their case, and a live marker controller-gen can't parse stops the run with exit 2.

**Why:** the role that reaches the cluster is the one controller-gen generates from the comments. Running controller-gen v0.17.0, v0.20.0 and v0.23.0 on the same test file kept only standalone markers and the package doc comment, and kept `verbs=GET` as written, which RBAC then never matches. VictoriaMetrics/operator had 146 markers attached to `Reconcile` functions, all ignored. A marker with `verbs=get;create,update;list` makes controller-gen fail, so the tool fails too instead of guessing.

**Alternatives:** reading `config/rbac/role.yaml` alone would trust a file that may be stale. Both are supported: markers by default, role files with `--role`.
