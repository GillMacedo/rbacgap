# 0002: Static types, not a cluster or audit logs

**Decision:** needs come from type-checking the operator's code. The tool never contacts a cluster or reads audit logs.

**Why:** tools like `audit2rbac` and `audicia` build roles from what a running operator did, which needs a cluster, a run that exercises every code path, and audit logging. A missing permission is easiest to fix before the operator is deployed, in the pull request that adds the call. Type information is what makes this reliable: the object passed to `r.Get` has a static type, and that type's package names its API group.

**Costs:** calls whose kind is only known at runtime (unstructured objects, dynamic clients, helpers that take `client.Object`) can't be checked, so they are listed as UNCHECKED instead of being guessed. Calls through a client for another cluster look the same as calls through the manager's client.
