package bootstrap

import (
	"github.com/goyek/goyek/v2"

	"github.com/projectcalico/fixham/pkg/ctl"
)

func clientInstance() *ctl.Client {
	return ctl.NewClient(*pkgName).WithRoot(*rootBind)
}

// Lint is a goyek task that runs the linter using golangci-lint.
var Lint = goyek.Define(goyek.Task{
	Name:  "lint",
	Usage: "Run linter",
	Action: func(a *goyek.A) {
		a.Log("Running linter")
		clientInstance().Lint()
	},
	Parallel: true,
})

// Fmt is a goyek task that checks code formatting using goimports.
var Fmt = goyek.Define(goyek.Task{
	Name:  "check-fmt",
	Usage: "Check code formatting",
	Action: func(a *goyek.A) {
		a.Log("Checking code formatting.  Any listed files don't match goimports:")
		clientInstance().CheckFmt()
	},
	Parallel: true,
})

// FixFmt is a goyek task that fixes code formatting using goimports.
var FixFmt = goyek.Define(goyek.Task{
	Name:  "fix-fmt",
	Usage: "Fix code formatting",
	Action: func(a *goyek.A) {
		clientInstance().FixFmt()
	},
})

// StaticChecks is a goyek task that runs the linter and checks code formatting.
var StaticChecks = goyek.Define(goyek.Task{
	Name:  "static-checks",
	Usage: "Run linter and check formatting",
	Deps:  []*goyek.DefinedTask{Lint, Fmt},
})
