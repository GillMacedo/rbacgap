// Package v1 contains the Bakery API.
// +groupName=bakery.example.com
package v1

import "k8s.io/apimachinery/pkg/runtime/schema"

// GroupVersion is the group and version of the Bakery API.
var GroupVersion = schema.GroupVersion{Group: "bakery.example.com", Version: "v1"}
