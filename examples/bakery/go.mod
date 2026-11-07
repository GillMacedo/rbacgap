module example.com/bakery

go 1.22

require (
	k8s.io/api v0.0.0
	k8s.io/apimachinery v0.0.0
	k8s.io/client-go v0.0.0
	sigs.k8s.io/controller-runtime v0.0.0
)

replace (
	k8s.io/api => ../stubs/api
	k8s.io/apimachinery => ../stubs/apimachinery
	k8s.io/client-go => ../stubs/client-go
	sigs.k8s.io/controller-runtime => ../stubs/controller-runtime
)
