// Package controllerutil is a small stand-in for
// sigs.k8s.io/controller-runtime/pkg/controller/controllerutil.
package controllerutil

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type OperationResult string

type MutateFn func() error

func CreateOrUpdate(ctx context.Context, c client.Client, obj client.Object, f MutateFn) (OperationResult, error) {
	return "", f()
}

func SetControllerReference(owner, controlled metav1.Object, scheme *runtime.Scheme) error {
	return nil
}
