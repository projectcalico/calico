package main

import (
	"github.com/projectcalico/fixham/pkg/api"
)

func main() {
	c := api.NewBuilder("projectcalico", "github.com/projectcalico/calico")
	c.Register()
}
