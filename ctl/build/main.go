package main

import (
	"github.com/goyek/goyek/v2"
	"github.com/projectcalico/ctl/pkg/bootstrap"
)

const packageName = "github.com/projectcalico/ctl"

var _ = bootstrap.DefineCleanTask([]string{"./bin/*"}, nil, nil)

var _ = bootstrap.DefineUt(func(a *goyek.A) {
	bootstrap.NewGoBuildRunner().
		WithBashCmd("go test -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./... -v -failfast").
		Run()
}, nil, false)

func main() {
	bootstrap.Main(packageName)
}
