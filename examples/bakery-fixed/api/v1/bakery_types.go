package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// BakeryStatus is the observed state of a Bakery.
type BakeryStatus struct {
	ReadyOvens int32
}

// Bakery runs a set of ovens as a Deployment.
type Bakery struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Ovens  int32
	Status BakeryStatus
}

// DeepCopyObject implements runtime.Object.
func (b *Bakery) DeepCopyObject() runtime.Object { c := *b; return &c }
