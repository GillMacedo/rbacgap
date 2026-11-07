// Package controller reconciles Bakery objects.
//
// This is ../bakery with its RBAC mistakes fixed.
package controller

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bakeryv1 "example.com/bakery/api/v1"
)

// +kubebuilder:rbac:groups=bakery.example.com,resources=bakeries,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=bakery.example.com,resources=bakeries/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=bakery.example.com,resources=bakeries/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=list;watch
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// BakeryReconciler reconciles a Bakery object.
type BakeryReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// Reconcile makes the ovens Deployment match the Bakery.
func (r *BakeryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var bakery bakeryv1.Bakery
	if err := r.Get(ctx, req.NamespacedName, &bakery); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// The recipe key lives in a Secret next to the Bakery.
	var recipe corev1.Secret
	key := types.NamespacedName{Namespace: req.Namespace, Name: bakery.Name + "-recipe"}
	if err := r.Get(ctx, key, &recipe); err != nil {
		return ctrl.Result{}, err
	}

	ovens := &appsv1.Deployment{}
	ovens.Name, ovens.Namespace = bakery.Name+"-ovens", req.Namespace
	if _, err := ctrl.CreateOrUpdate(ctx, r.Client, ovens, func() error {
		ovens.Replicas = bakery.Ovens
		return ctrl.SetControllerReference(&bakery, ovens, r.Scheme)
	}); err != nil {
		return ctrl.Result{}, err
	}

	menu := &corev1.ConfigMap{}
	menu.Name, menu.Namespace = bakery.Name+"-menu", req.Namespace
	if _, err := ctrl.CreateOrUpdate(ctx, r.Client, menu, func() error {
		menu.Data = map[string]string{"ovens": "on"}
		return nil
	}); err != nil {
		return ctrl.Result{}, err
	}

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.ListOption(nil)); err != nil {
		return ctrl.Result{}, err
	}
	bakery.Status.ReadyOvens = int32(len(pods.Items))
	if err := r.Status().Update(ctx, &bakery); err != nil {
		return ctrl.Result{}, err
	}
	r.Recorder.Event(&bakery, "Normal", "Baked", "ovens are running")
	return ctrl.Result{}, r.Update(ctx, &bakery)
}

// SetupWithManager registers the controller.
func (r *BakeryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Recorder = mgr.GetEventRecorderFor("bakery")
	return ctrl.NewControllerManagedBy(mgr).
		For(&bakeryv1.Bakery{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
