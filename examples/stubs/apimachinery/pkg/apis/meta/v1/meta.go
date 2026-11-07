// Package v1 is a small stand-in for k8s.io/apimachinery/pkg/apis/meta/v1.
package v1

import "k8s.io/apimachinery/pkg/runtime/schema"

type Object interface {
	GetName() string
	GetNamespace() string
}

type TypeMeta struct {
	Kind       string
	APIVersion string
}

func (t *TypeMeta) GetObjectKind() schema.ObjectKind { return t }

func (t *TypeMeta) GroupVersionKind() schema.GroupVersionKind { return schema.GroupVersionKind{} }

type ObjectMeta struct {
	Name      string
	Namespace string
}

func (m *ObjectMeta) GetName() string      { return m.Name }
func (m *ObjectMeta) GetNamespace() string { return m.Namespace }

type ListMeta struct{}
