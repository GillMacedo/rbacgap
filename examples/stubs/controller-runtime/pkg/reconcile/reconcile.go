// Package reconcile is a small stand-in for sigs.k8s.io/controller-runtime/pkg/reconcile.
package reconcile

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
)

type Request struct {
	types.NamespacedName
}

type Result struct{}

type TypedReconciler[request comparable] interface {
	Reconcile(ctx context.Context, req request) (Result, error)
}
