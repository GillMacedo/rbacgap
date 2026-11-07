// Package client is a small stand-in for
// sigs.k8s.io/controller-runtime/pkg/client, with the same interface and
// method names, so the example runs without downloading Kubernetes modules.
package client

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

type Object interface {
	metav1.Object
	runtime.Object
}

type ObjectList interface {
	runtime.Object
}

type ObjectKey = types.NamespacedName

type Patch interface {
	Data(obj Object) ([]byte, error)
}

type (
	GetOption         interface{}
	ListOption        interface{}
	CreateOption      interface{}
	DeleteOption      interface{}
	UpdateOption      interface{}
	PatchOption       interface{}
	DeleteAllOfOption interface{}
	SubResourceOption interface{}
)

type Reader interface {
	Get(ctx context.Context, key ObjectKey, obj Object, opts ...GetOption) error
	List(ctx context.Context, list ObjectList, opts ...ListOption) error
}

type Writer interface {
	Create(ctx context.Context, obj Object, opts ...CreateOption) error
	Delete(ctx context.Context, obj Object, opts ...DeleteOption) error
	Update(ctx context.Context, obj Object, opts ...UpdateOption) error
	Patch(ctx context.Context, obj Object, patch Patch, opts ...PatchOption) error
	DeleteAllOf(ctx context.Context, obj Object, opts ...DeleteAllOfOption) error
}

type SubResourceWriter interface {
	Create(ctx context.Context, obj Object, subResource Object, opts ...SubResourceOption) error
	Update(ctx context.Context, obj Object, opts ...SubResourceOption) error
	Patch(ctx context.Context, obj Object, patch Patch, opts ...SubResourceOption) error
}

type SubResourceReader interface {
	Get(ctx context.Context, obj Object, subResource Object, opts ...SubResourceOption) error
}

type SubResourceClient interface {
	SubResourceReader
	SubResourceWriter
}

type StatusClient interface {
	Status() SubResourceWriter
}

type SubResourceClientConstructor interface {
	SubResource(subResource string) SubResourceClient
}

type Client interface {
	Reader
	Writer
	StatusClient
	SubResourceClientConstructor
}

func IgnoreNotFound(err error) error { return err }
