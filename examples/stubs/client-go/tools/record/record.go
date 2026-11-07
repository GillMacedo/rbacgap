// Package record is a small stand-in for k8s.io/client-go/tools/record.
package record

import "k8s.io/apimachinery/pkg/runtime"

type EventRecorder interface {
	Event(object runtime.Object, eventtype, reason, message string)
	Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...any)
}
