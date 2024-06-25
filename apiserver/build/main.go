package main

import (
	"github.com/projectcalico/fixham/pkg/api"
)

// APIServer is a struct that represents projectcalico
//
// This will be used to define the tasks for the projectcalico
// such as cutting new branch, hashrelease and release
type APIServer struct {
	api.CalicoComponent
}

func main() {
	c := api.NewCalicoComponent("apiserver")
	c.Register()
}
