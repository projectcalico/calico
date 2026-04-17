include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/typha

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

BINDIR=./bin

.PHONY: clean
clean:
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -rf bin \
		build \
		report/*.xml \
		release-notes-*
	find . -name "coverprofile.out" -type f -delete
	find . -name "coverage.xml" -type f -delete
	find . -name ".coverage" -type f -delete
	find . -name "*.pyc" -type f -delete

###############################################################################
# Unit Tests
###############################################################################
.PHONY: ut
ut combined.coverprofile: $(SRC_FILES)
	@echo Running Go UTs.
	$(DOCKER_RUN) $(CALICO_BUILD) ./utils/run-coverage

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci version
# Uses the combined calico/calico image (loaded from the calico-image prerequisite
# in CI, or built locally via `make -C cmd/calico image`).
version:
	docker run --rm calico/calico:latest-$(ARCH) version

ci: mod-download version static-checks ut
ifeq (,$(filter k8sfv-test, $(EXCEPT)))
	@$(MAKE) k8sfv-test
endif

fv: k8sfv-test

# k8sfv-test runs the combined calico/calico image with `component typha` as the
# command. The image is loaded from GCS in CI or built locally.
k8sfv-test:
	$(MAKE) -C ../felix JUST_A_MINUTE=true USE_TYPHA=true \
		FV_TYPHAIMAGE=calico/calico:latest-$(ARCH) \
		FV_TYPHACMD="component typha" \
		TYPHA_VERSION=latest k8sfv-test

st:
	@echo "No STs available."

###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
.PHONY: ut-no-cover
ut-no-cover: $(SRC_FILES)
	@echo Running Go UTs without coverage.
	$(DOCKER_RUN) $(CALICO_BUILD) ginkgo -r

.PHONY: ut-watch
ut-watch: $(SRC_FILES)
	@echo Watching go UTs for changes...
	$(DOCKER_RUN) $(CALICO_BUILD) ginkgo watch -r

# Launch a browser with Go coverage stats for the whole project.
.PHONY: cover-browser
cover-browser: combined.coverprofile
	go tool cover -html="combined.coverprofile"

.PHONY: cover-report
cover-report: combined.coverprofile
	# Print the coverage.  We use sed to remove the verbose prefix and trim down
	# the whitespace.
	@echo
	@echo ======== All coverage =========
	@echo
	@$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'go tool cover -func combined.coverprofile | \
				   sed 's=$(PACKAGE_NAME)/==' | \
				   column -t'
	@echo
	@echo ======== Missing coverage only =========
	@echo
	@$(DOCKER_RUN) $(CALICO_BUILD) sh -c "go tool cover -func combined.coverprofile | \
				   sed 's=$(PACKAGE_NAME)/==' | \
				   column -t | \
				   grep -v '100\.0%'"
