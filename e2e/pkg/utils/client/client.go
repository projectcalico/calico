package client

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// New returns a new controller-runtime client configured to use the projectcalico.org/v3 API group.
func New(cfg *rest.Config) (client.Client, error) {
	// Create a new Scheme and add the projectcalico.org/v3 API group to it.
	scheme := runtime.NewScheme()
	if err := v3.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return client.New(cfg, client.Options{})
}
