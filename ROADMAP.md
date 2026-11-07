# Roadmap

## Next
- Follow helpers that take `client.Object` to their callers, so `ensure(ctx, &appsv1.Deployment{})` is checked instead of UNCHECKED
- Resolve `unstructured.Unstructured` objects whose `SetGroupVersionKind` is a constant in the same function
- Read `cache.Options{ByObject: ...}` and `client.CacheOptions{DisableFor: ...}` so reads that skip the cache don't need list and watch

## Later
- A GitHub Action example that runs `rbacgap` on each manager binary in a pull request
- Read the Role a controller-runtime `LeaderElection` option needs, and check it against the leader election role file
- Check Operator Lifecycle Manager ClusterServiceVersion permissions with `--role`
