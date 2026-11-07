// Package types is a small stand-in for k8s.io/apimachinery/pkg/types.
package types

type NamespacedName struct {
	Namespace string
	Name      string
}
