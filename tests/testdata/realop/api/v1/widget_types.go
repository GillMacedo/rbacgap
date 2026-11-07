package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// WidgetStatus is the observed state.
type WidgetStatus struct {
	Ready bool `json:"ready"`
}

// Widget is a test kind.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=widgetries
type Widget struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            WidgetStatus `json:"status,omitempty"`
}

// WidgetList is a list of Widgets.
// +kubebuilder:object:root=true
type WidgetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Widget `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (w *Widget) DeepCopyObject() runtime.Object { c := *w; return &c }

// DeepCopyObject implements runtime.Object.
func (w *WidgetList) DeepCopyObject() runtime.Object {
	c := *w
	c.Items = append([]Widget(nil), w.Items...)
	return &c
}

func init() {
	SchemeBuilder.Register(&Widget{}, &WidgetList{})
}
