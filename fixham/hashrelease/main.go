package main

import (
	"github.com/projectcalico/calico/fixham/pkg/api"
)

func main() {
	f := api.NewCalicoBuilder()
	f.Register()
}
