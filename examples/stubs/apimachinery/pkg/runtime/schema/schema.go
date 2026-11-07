// Package schema is a small stand-in for k8s.io/apimachinery/pkg/runtime/schema.
package schema

type GroupVersion struct {
	Group   string
	Version string
}

type GroupVersionKind struct {
	Group   string
	Version string
	Kind    string
}

type ObjectKind interface {
	GroupVersionKind() GroupVersionKind
}
