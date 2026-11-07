// Package builder is a small stand-in for sigs.k8s.io/controller-runtime/pkg/builder.
package builder

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type TypedBuilder[request comparable] struct{}

type Builder = TypedBuilder[reconcile.Request]

func ControllerManagedBy(m manager.Manager) *Builder { return &Builder{} }

func (b *TypedBuilder[request]) For(object client.Object) *TypedBuilder[request] { return b }

func (b *TypedBuilder[request]) Owns(object client.Object) *TypedBuilder[request] { return b }

func (b *TypedBuilder[request]) Complete(r reconcile.TypedReconciler[request]) error { return nil }
