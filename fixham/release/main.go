package main

import (
	"github.com/projectcalico/calico/fixham/pkg/api"
	"github.com/projectcalico/calico/fixham/pkg/goyek"
)

func main() {
	b := api.NewCalicoBuilder()
	b.AddTask(goyek.ReleaseNotes(b.Config()))
	b.Register()
}
