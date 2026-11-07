// Command manager runs the test controller.
package main

import (
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

	"example.com/realop/internal/controller"
)

func main() {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{})
	if err != nil {
		panic(err)
	}
	cs := kubernetes.NewForConfigOrDie(mgr.GetConfig())
	r := &controller.WidgetReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), Clientset: cs}
	if err := r.SetupWithManager(mgr); err != nil {
		panic(err)
	}
	controller.Informers(cs)
}
