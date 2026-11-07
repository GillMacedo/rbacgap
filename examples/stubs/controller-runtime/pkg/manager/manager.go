// Package manager is a small stand-in for sigs.k8s.io/controller-runtime/pkg/manager.
package manager

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Manager interface {
	GetClient() client.Client
	GetAPIReader() client.Reader
	GetScheme() *runtime.Scheme
	GetEventRecorderFor(name string) record.EventRecorder
}
