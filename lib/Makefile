include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/lib

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

gen-mocks:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'cd httpmachinery && mockery'

gen-compact:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'cd std/uniquelabels && go generate'

gen-files: gen-mocks gen-compact

ci: static-checks ut

# The ut target runs go test for every immediate subfolder that has a go.mod file. This ensures that we run tests for any
# new modules added without requiring that the developer explicitly enable running the tests for the new module.
ut:
	mkdir -p report
	@for dir in $$(find . -maxdepth 2 -name "go.mod" -exec dirname {} \; | sort -u); do \
		echo "Testing $$dir..."; \
		$(DOCKER_GO_BUILD) sh -c "cd $$dir && gotestsum --junitfile /go/src/$(PACKAGE_NAME)/report/lib_$$(basename $$dir)_ut.xml -- ./... -cover -count 1"; \
	done

# The static-checks target runs the go linter for every immediate subfolder that has a go.mod file. This ensures that we
# run tests for any new modules added without requiring that the developer explicitly enable running the tests for the new module.
static-checks:
	@for dir in $$(find . -maxdepth 2 -name "go.mod" -exec dirname {} \; | sort -u); do \
		echo "Static checking $$dir..."; \
		$(DOCKER_RUN) $(CALICO_BUILD) sh -c "$(GIT_CONFIG_SSH) cd $$dir && golangci-lint run $(LINT_ARGS)"; \
	done
