package main

import (
	"github.com/projectcalico/fixham/pkg/api"
)

// Calico is a struct that represents projectcalico
//
// This will be used to define the tasks for the projectcalico
// such as cutting new branch, hashrelease and release
type Calico struct {
	api.Component
}

func main() {
	c := &Calico{
		Component: *api.NewComponent("calico", "github.com/projectcalico/calico"),
	}
	c.Register()
}
