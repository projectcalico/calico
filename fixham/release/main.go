package main

import (
	"github.com/projectcalico/calico/fixham/pkg/api"
	"github.com/projectcalico/calico/fixham/pkg/goyek"
)

func main() {
	b := api.NewBuilder()
	b.AddTask(goyek.ReleaseNotes(b.Config()))
	b.Register()
}
