package main

import (
	"github.com/projectcalico/fixham/pkg/api"
)

// ProjectCalicoBuilder is a struct that represents projectcalico
//
// This will be used to define the tasks for the projectcalico
// such as cutting new branch, hashrelease and release
type ProjectCalicoBuilder struct {
	api.Builder
}

func main() {
	c := api.NewBuilder("projectcalico", "github.com/projectcalico/calico")
	c.Register()
}
