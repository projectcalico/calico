package api

import (
	goyekAutomation "github.com/goyek/goyek/v2"
	"github.com/goyek/x/boot"
	"github.com/projectcalico/fixham/internal/config"
	"github.com/projectcalico/fixham/pkg/goyek"
)

type Package interface {
	Name() string
	PackageName() string
	Config() *config.Config
	Tasks() map[string]*goyek.GoyekTask
	Register()
}

func Register(p Package) {
	definedTaskMap := make(map[string]*goyekAutomation.DefinedTask, 0)
	for name, task := range p.Tasks() {
		definedTaskMap[name] = goyekAutomation.Define(task.Task)
	}
	for _, task := range p.Tasks() {
		if task.Deps != nil {
			deps := goyekAutomation.Deps{}
			for _, dep := range task.Deps {
				deps = append(deps, definedTaskMap[dep])
			}
			definedTaskMap[task.Name].SetDeps(deps)
		}
	}
	boot.Main()
}
