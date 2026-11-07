// Package runtime is a small stand-in for k8s.io/apimachinery/pkg/runtime.
package runtime

import "k8s.io/apimachinery/pkg/runtime/schema"

type Object interface {
	GetObjectKind() schema.ObjectKind
	DeepCopyObject() Object
}

type Scheme struct{}

type ApplyConfiguration interface {
	IsApplyConfiguration()
}
