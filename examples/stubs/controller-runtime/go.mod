module sigs.k8s.io/controller-runtime

go 1.22

require (
	k8s.io/apimachinery v0.0.0
	k8s.io/client-go v0.0.0
)

replace (
	k8s.io/apimachinery => ../apimachinery
	k8s.io/client-go => ../client-go
)
