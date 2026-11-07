// Package controller is a test controller written against the real
// controller-runtime and client-go APIs. Its RBAC has known gaps, listed in
// tests/integration_test.go.
package controller

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	widgetsv1 "example.com/realop/api/v1"
)

// +kubebuilder:rbac:groups=widgets.example.com,resources=widgetries,verbs=get;list;watch
// +kubebuilder:rbac:groups=widgets.example.com,resources=widgetries/status,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// WidgetReconciler reconciles Widgets.
type WidgetReconciler struct {
	client.Client
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Clientset kubernetes.Interface
}

// Reconcile is the test reconciler.
func (r *WidgetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var w widgetsv1.Widget
	if err := r.Get(ctx, req.NamespacedName, &w); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Cached read of a Secret: needs list and watch too. Not granted.
	var s corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &s); err != nil {
		return ctrl.Result{}, err
	}
	// Uncached read through the API reader: get is enough.
	var cm corev1.ConfigMap
	if err := r.APIReader.Get(ctx, req.NamespacedName, &cm); err != nil {
		return ctrl.Result{}, err
	}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: w.Name, Namespace: w.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, dep, func() error {
		return controllerutil.SetControllerReference(&w, dep, r.Scheme)
	}); err != nil {
		return ctrl.Result{}, err
	}
	// Status patch: only update is granted.
	if err := r.Status().Patch(ctx, &w, client.MergeFrom(w.DeepCopyObject().(*widgetsv1.Widget))); err != nil {
		return ctrl.Result{}, err
	}
	// Delete all pods with a label: deletecollection, not granted.
	if err := r.DeleteAllOf(ctx, &corev1.Pod{}, client.InNamespace(w.Namespace)); err != nil {
		return ctrl.Result{}, err
	}
	// Evict a pod through the subresource client: pods/eviction create, not granted.
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: w.Namespace}}
	if err := r.SubResource("eviction").Create(ctx, pod, &policyv1.Eviction{}); err != nil {
		return ctrl.Result{}, err
	}
	// Typed clientset: nodes get is granted, nodes/status update is not.
	node, err := r.Clientset.CoreV1().Nodes().Get(ctx, "n", metav1.GetOptions{})
	if err != nil {
		return ctrl.Result{}, err
	}
	if _, err := r.Clientset.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// Informers starts a shared informer for services: list and watch, not granted.
func Informers(cs kubernetes.Interface) {
	f := informers.NewSharedInformerFactory(cs, 0)
	_ = f.Core().V1().Services().Informer()
}

// SetupWithManager registers the controller.
func (r *WidgetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	_ = mgr.GetEventRecorderFor("widget")
	return ctrl.NewControllerManagedBy(mgr).
		For(&widgetsv1.Widget{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
