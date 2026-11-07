# Examples

- `bakery/` is a made-up kubebuilder-style operator with five RBAC mistakes: a Secret read through the cached client with only `get` granted, a `CreateOrUpdate` on Deployments without `update`, a configmaps marker attached to the `Reconcile` doc comment (controller-gen ignores it), a `verbs=List` marker, and an event recorder with no events marker. It also has a helper that takes `client.Object`, which can't be checked. Run `make demo-broken`.
- `bakery-fixed/` is the same operator with the mistakes fixed. Run `make demo-fixed`, and it exits 0.
- `stubs/` holds small stand-ins for `sigs.k8s.io/controller-runtime`, `k8s.io/api`, `k8s.io/apimachinery` and `k8s.io/client-go`, with the same import paths, type names and method signatures that rbacgap reads. They let the examples run offline without downloading Kubernetes modules. They are not usable libraries. `tests/testdata/realop` uses the real modules instead.

All of these are separate modules, so the repo's own `go vet ./...` and `go test ./...` don't build them.
