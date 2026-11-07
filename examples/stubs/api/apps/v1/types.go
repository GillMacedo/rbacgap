package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type Deployment struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Replicas int32
}

func (d *Deployment) DeepCopyObject() runtime.Object { c := *d; return &c }
