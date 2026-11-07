package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type Secret struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Data map[string][]byte
}

func (s *Secret) DeepCopyObject() runtime.Object { c := *s; return &c }

type ConfigMap struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Data map[string]string
}

func (c *ConfigMap) DeepCopyObject() runtime.Object { d := *c; return &d }

type Pod struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

func (p *Pod) DeepCopyObject() runtime.Object { c := *p; return &c }

type PodList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []Pod
}

func (p *PodList) DeepCopyObject() runtime.Object { c := *p; return &c }

type Node struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

func (n *Node) DeepCopyObject() runtime.Object { c := *n; return &c }
