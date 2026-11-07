// Package controllerruntime is a small stand-in for sigs.k8s.io/controller-runtime.
package controllerruntime

import (
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type (
	Manager = manager.Manager
	Request = reconcile.Request
	Result  = reconcile.Result
)

var (
	NewControllerManagedBy = builder.ControllerManagedBy
	CreateOrUpdate         = controllerutil.CreateOrUpdate
	SetControllerReference = controllerutil.SetControllerReference
)
