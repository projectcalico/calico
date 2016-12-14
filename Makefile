# This Makefile builds Felix and packages it in various forms:
#
#               Python install                                         Go install
#                 PyInstaller                                             Glide
#             Key library packages                                          |
#                      |                                                    |
#                      |                                                    |
#                      v              +--------+     +-------+              v
#           +---------------------+   | Felix  |     | Felix |   +---------------------+
#           | calico-build/python |   | Python |     |  Go   |   | calico-build/golang |
#           +---------------------+   |  code  |     |  code |   +---------------------+
#                             \       +--------+     +-------+         /
#                              \         /                  \         /
#                               \       /                    \       /
#                                \     /                      \     /
#                              pip install                    go build
#                           run-pyinstaller.sh                    \
#                                    |                             \
#                                    |                              \
# +----------------------+           |                               :
# | calico-build/centos7 |           v                               v
# | calico-build/xenial  |     +------------------------+      +--------------+
# | calico-build/trusty  |     | calico-iptables-plugin |      | calico-felix |
# +----------------------+     +------------------------+      +--------------+
#                     \          /          |        \           /   /      |
#                      \        /    .------|---------\---------'   /       |
#                       \      /    /       |          \           /        |
#                        \    /    /        |           \ .-------'         |
#                         \  /    /         :            \                  |
#                     rpm/build-rpms         '-----.    / '-------------.   |
#                   debian/build-debs               \  /                 \  |
#                           |                        \/                   \ |
#                           |                   docker build              tar
#                           v                         |                    |
#            +----------------------------+           |                    |
#            |  RPM packages for Centos7  |           v                    v
#            | Debian packages for Xenial |    +--------------+   +--------------------+
#            | Debian packages for Trusty |    | calico/felix |   | PyInstaller bundle |
#            +----------------------------+    +--------------+   | (tarball of two    |
#                                                                 |  executables)      |
#                                                                 +--------------------+

help:
	@echo "Felix Makefile"
	@echo
	@echo "Dependencies: docker 1.12+; go 1.7+; python 2.7; tox; virtualenv"
	@echo
	@echo "Note: initial builds can be slow because they generate docker-based"
	@echo "build environments."
	@echo
	@echo "Initial set-up:"
	@echo
	@echo "  make update-tools  Update/install the go build dependencies."
	@echo "  make env           Create a Python virtualenv for UT dev."
	@echo
	@echo "Builds:"
	@echo
	@echo "  make all           Build all the binary packages."
	@echo "  make pyinstaller   Build pyinstaller bundle in ./dist."
	@echo "  make deb           Build debs in ./dist."
	@echo "  make rpm           Build rpms in ./dist."
	@echo "  make calico/felix  Build calico/felix docker image."
	@echo
	@echo "Tests:"
	@echo
	@echo "  make ut            Run all UTs."
	@echo "  make go-ut         Run go UTs (and coverage)."
	@echo "  make python-ut     Run Python UTs (and coverage)."
	@echo "  make go-cover-browser  Display go code coverage in browser."
	@echo
	@echo "Maintenance:"
	@echo
	@echo "  make update-vendor  Update the go/vendor directory with new "
	@echo "                     versions ofupstream packages.  Record results"
	@echo "                     in go/glide.lock."
	@echo "  make update-frozen-reqs  Update the frozen python requirements."
	@echo "                     Should be run after revving or adding a new"
	@echo "                     python dependency."
	@echo "  make go-fmt        Format our go code."
	@echo "  make clean         Remove binary files."

# Disable make's implicit rules, which are not useful for golang, and slow down the build
# considerably.
.SUFFIXES:

all: pyinstaller deb rpm calico/felix
test: ut

# re-define default --compare-branch=origin/master to some custom name
UT_COMPARE_BRANCH?=

# Generate and return the python package version.
PY_VERSION:=$(shell utils/gen-version.sh)

# Figure out what git commit we have checked out.  We'll bake that into the
# executable.
GIT_COMMIT:=$(shell git rev-parse HEAD)
GIT_COMMIT_SHORT:=$(shell git rev-parse --short HEAD)
GIT_DESCRIPTION:=$(shell git describe --tags)

# Calculate a timestamp for any build artefacts.
DATE:=$(shell date -u +'%FT%T%z')

# Calculate the versioned name of the pyinstaller bundle tgz.
BUNDLE_FILENAME:=dist/calico-felix-${GIT_DESCRIPTION}.tgz

# List of Go files that are generated by the build process.  Builds should
# depend on these, clean removes them.
GENERATED_GO_FILES:=go/felix/proto/felixbackend.pb.go

# All go files.
GO_FILES:=$(shell find go/ -type f -name '*.go') $(GENERATED_GO_FILES)

# Generated python files, builds should depend on these, clean removes them.
GENERATED_PYTHON_FILES=python/calico/felix/felixbackend_pb2.py

# All our python files.
PY_FILES:=$(GENERATED_PYTHON_FILES) \
          $(shell find python/  -type f -name '*.py' | grep -v /.tox/)

# Figure out the users UID/GID.  These are needed to run docker containers
# as the current user and ensure that files built inside containers are
# owned by the current user.
MY_UID:=$(shell id -u)
MY_GID:=$(shell id -g)

# (optional) Local path to the repository with 'libcalico-go' code
LIBCALICOGO_PATH?=none

# Build a docker image used for building our go code into a binary.
.PHONY: calico-build/golang
calico-build/golang:
	@echo "Checking freshness of calico-build/golang container image."
	cd docker-build-images && \
	  docker build \
	  --build-arg=UID=$(MY_UID) \
	  --build-arg=GID=$(MY_GID) \
	  -f golang-build.Dockerfile \
	  -t calico-build/golang .

# Build a docker image used for building debs for trusty.
.PHONY: calico-build/trusty
calico-build/trusty:
	cd docker-build-images && docker build -f ubuntu-trusty-build.Dockerfile -t calico-build/trusty .

# Build a docker image used for building debs for xenial.
.PHONY: calico-build/xenial
calico-build/xenial:
	cd docker-build-images && docker build -f ubuntu-xenial-build.Dockerfile -t calico-build/xenial .

# Construct a docker image for building Centos 7 RPMs.
.PHONY: calico-build/centos7
calico-build/centos7:
	cd docker-build-images && \
	  docker build \
	  --build-arg=UID=$(MY_UID) \
	  --build-arg=GID=$(MY_GID) \
	  -f centos7-build.Dockerfile \
	  -t calico-build/centos7 .

.PHONY: calico-build/python
calico-build/python:
	# Rebuild the container image.  Docker will do its own newness checks.
	docker build \
	  --build-arg=UID=$(MY_UID) \
	  --build-arg=GID=$(MY_GID) \
	  -t calico-build/python \
	  -f docker-build-images/pyi/Dockerfile .

.PHONY: update-frozen-reqs
update-frozen-reqs python/requirements_frozen.txt: python/requirements.txt python/test_requirements.txt
	$(MAKE) calico-build/python
	$(DOCKER_RUN_RM_ROOT) -w /code/python calico-build/python sh -c \
	"pip --no-cache-dir install -U -r requirements.txt -r test_requirements.txt"\
	" && pip --no-cache-dir freeze > requirements_frozen.txt"\
	" && chown $(MY_UID):$(MY_GID) requirements_frozen.txt"

# Build the calico/felix docker image, which contains only Felix.
.PHONY: calico/felix
calico/felix: dist/calico-felix/calico-iptables-plugin dist/calico-felix/calico-felix
	docker build -t calico/felix .

# Create or rebuild a python virtualenv suitable for developing Python UTs.
.PHONY: env
env:
	virtualenv env
	. env/bin/activate && \
	    pip install -U pip && \
	    pip install -U hypothesis mock nose unittest2 && \
	    pip install -e ./python

# Pre-configured docker run command that runs as this user with the repo
# checked out to /code, uses the --rm flag to avoid leaving the container
# around afterwards.
DOCKER_RUN_RM:=docker run --rm --user $(MY_UID):$(MY_GID) -v $${PWD}:/code
DOCKER_RUN_RM_ROOT:=docker run --rm -v $${PWD}:/code

# Build all the debs.
.PHONY: deb
deb: dist/calico-felix/calico-iptables-plugin dist/calico-felix/calico-felix
	$(MAKE) calico-build/trusty
	$(MAKE) calico-build/xenial
	utils/make-packages.sh deb

# Build RPMs.
.PHONY: rpm
rpm: dist/calico-felix/calico-iptables-plugin dist/calico-felix/calico-felix
	$(MAKE) calico-build/centos7
	utils/make-packages.sh rpm

.PHONY: protobuf
protobuf: python/calico/felix/felixbackend_pb2.py go/felix/proto/felixbackend.pb.go

# Generate the protobuf bindings for go.
go/felix/proto/felixbackend.pb.go: go/felix/proto/felixbackend.proto
	$(DOCKER_RUN_RM) -v $${PWD}/go/felix/proto:/src:rw \
	              calico/protoc \
	              --gogofaster_out=. \
	              felixbackend.proto

# Generate the protobuf bindings for Python.
python/calico/felix/felixbackend_pb2.py: go/felix/proto/felixbackend.proto
	$(DOCKER_RUN_RM) -v $${PWD}/go/felix/proto:/src:rw \
	              -v $${PWD}/python/calico/felix/:/dst:rw \
	              calico/protoc \
	              --python_out=/dst/ \
	              felixbackend.proto

# Update the vendored dependencies with the latest upstream versions matching
# our glide.yaml.  If there area any changes, this updates go/glide.lock
# as a side effect.  Unless you're adding/updating a dependency, you probably
# want to use the vendor target to install the versions from glide.lock.
.PHONY: update-vendor
update-vendor:
	cd go && glide up --strip-vendor

# vendor is a shortcut for force rebuilding the go vendor directory.
.PHONY: vendor
vendor go/vendor go/vendor/.up-to-date: go/glide.lock
	# Make sure the docker image exists.  Since it's a PHONY, we can't add it
	# as a dependency or this job will run every time.  Docker does its own
	# freshness checking for us.
	$(MAKE) calico-build/golang
	mkdir -p $$HOME/.glide
	if [ "$(LIBCALICOGO_PATH)" != "none" ]; then \
	  EXTRA_DOCKER_BIND="-v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro"; \
	fi; \
	$(DOCKER_RUN_RM) \
	    --net=host \
	    -v $${PWD}:/go/src/github.com/projectcalico/felix:rw \
	    -v $$HOME/.glide:/.glide:rw $$EXTRA_DOCKER_BIND \
	    -w /go/src/github.com/projectcalico/felix/go \
	    calico-build/golang \
	    glide install --strip-vendor
	touch go/vendor/.up-to-date

# Linker flags for building Felix.
#
# We use -X to insert the version information into the placeholder variables
# in the buildinfo package.
#
# We use -B to insert a build ID note into the executable, without which, the
# RPM build tools complain.
LDFLAGS:=-ldflags "\
        -X github.com/projectcalico/felix/go/felix/buildinfo.GitVersion=$(GIT_DESCRIPTION) \
        -X github.com/projectcalico/felix/go/felix/buildinfo.BuildDate=$(DATE) \
        -X github.com/projectcalico/felix/go/felix/buildinfo.GitRevision=$(GIT_COMMIT) \
        -B 0x$(GIT_COMMIT)"

bin/calico-felix: $(GO_FILES) \
                  go/vendor/.up-to-date \
                  docker-build-images/golang-build.Dockerfile
	# Make sure the docker image exists.  Since it's a PHONY, we can't add it
	# as a dependency or this job will run every time.  Docker does its own
	# freshness checking for us.
	$(MAKE) calico-build/golang
	mkdir -p bin
	mkdir -p .go-pkg-cache
	@echo Building felix...
	$(DOCKER_RUN_RM) \
	    -v $${PWD}:/go/src/github.com/projectcalico/felix:rw \
	    -v $${PWD}/.go-pkg-cache:/go/pkg/:rw \
	    calico-build/golang \
	    sh -c 'go build -i -o $@ -v $(LDFLAGS) "github.com/projectcalico/felix/go/felix" && \
               ( ldd bin/calico-felix | grep -q "not a dynamic executable" || \
	             ( echo "Error: bin/calico-felix was not statically linked"; false ) )'

# Build the pyinstaller bundle, which is an output artefact in its own right
# as well as being the input to our Deb and RPM builds.
.PHONY: pyinstaller
pyinstaller: $(BUNDLE_FILENAME)

$(BUNDLE_FILENAME): dist/calico-felix/calico-iptables-plugin dist/calico-felix/calico-felix
	tar -czf $(BUNDLE_FILENAME) -C dist calico-felix

dist/calico-felix/calico-iptables-plugin: $(PY_FILES) python/requirements.txt docker-build-images/pyi/*
	$(MAKE) calico-build/python

	# Output version information
	echo "Felix version: $(GIT_DESCRIPTION) \n" \
	     "Git revision: $(GIT_COMMIT)\n" > version.txt

	# Create and run build container.
	$(DOCKER_RUN_RM_ROOT) -w /code/python calico-build/python sh -c \
	'pip install .'\
	' && ../docker-build-images/pyi/run-pyinstaller.sh'\
	' && rm -rf ../build `find . -name "*.pyc"`'\
	' && chown -R $(MY_UID):$(MY_GID) ../dist'

	# Check that the build succeeded and update the mtimes on the target file
	# since pyinstaller doesn't seem to do so.
	test -e dist/calico-felix/calico-iptables-plugin && touch dist/calico-felix/calico-iptables-plugin

# This target adds the calico-felix binary to the PyInstaller build directory.
# It requires an order-only dependency to ensure that it only gets run after
# the PyInstaller build itself because the PyInstaller build clobbers the
# directory.
dist/calico-felix/calico-felix: bin/calico-felix | dist/calico-felix/calico-iptables-plugin
	cp bin/calico-felix dist/calico-felix/calico-felix

# Install or update the tools used by the build
.PHONY: update-tools
update-tools:
	go get -u github.com/Masterminds/glide
	go get -u github.com/onsi/ginkgo/ginkgo
	go get -u github.com/wadey/gocovmerge

# Run go fmt on all our go files.
.PHONY: go-fmt
go-fmt:
	$(MAKE) calico-build/golang
	$(DOCKER_RUN_RM) -w /code/go calico-build/golang sh -c 'glide nv | xargs go fmt'

.PHONY: ut
ut: python-ut go-ut

.PHONY: python-ut
python-ut: python/calico/felix/felixbackend_pb2.py
	$(MAKE) calico-build/python
	$(DOCKER_RUN_RM_ROOT) -w /code/python calico-build/python sh -c \
	"pip install ."\
	" && COMPARE_BRANCH=$(UT_COMPARE_BRANCH) ./run-unit-test.sh"\
	" && chown -R $(MY_UID):$(MY_GID) coverage.xml .coverage htmlcov"

.PHONY: go-ut
go-ut go/combined.coverprofile: go/vendor/.up-to-date $(GO_FILES)
	@echo Running Go UTs.
	$(MAKE) calico-build/golang
	mkdir -p .go-pkg-cache
	$(DOCKER_RUN_RM) \
	    --net=host \
	    -v $${PWD}:/go/src/github.com/projectcalico/felix:rw \
	    -v $${PWD}/.go-pkg-cache:/go/pkg/:rw \
	    -w /go/src/github.com/projectcalico/felix/go \
	    calico-build/golang \
	    ./run-coverage

# Launch a browser with Go coverage stats for the whole project.
.PHONY: go-cover-browser
go-cover-browser: go/combined.coverprofile
	go tool cover -html="go/combined.coverprofile"

.PHONY: go-cover-report
go-cover-report: go/combined.coverprofile
	# Print the coverage.  We use sed to remove the verbose prefix and trim down
	# the whitespace.
	@echo
	@echo ======== All coverage =========
	@echo
	@go tool cover -func go/combined.coverprofile | \
	  sed 's=github.com/projectcalico/felix/go/==' | \
	  column -t
	@echo
	@echo ======== Missing coverage only =========
	@echo
	@go tool cover -func go/combined.coverprofile | \
	  sed 's=github.com/projectcalico/felix/go/==' | \
	  column -t | \
	  grep -v '100\.0%'

bin/calico-felix.transfer-url: bin/calico-felix
	curl --upload-file bin/calico-felix https://transfer.sh/calico-felix > $@

.PHONY: patch-script
patch-script: bin/calico-felix.transfer-url
	utils/make-patch-script.sh $$(cat bin/calico-felix.transfer-url)

# Generate a diagram of Felix's internal calculation graph.
go/docs/calc.pdf: go/docs/calc.dot
	cd go/docs/ && dot -Tpdf calc.dot -o calc.pdf

.PHONY: clean
clean:
	rm -rf bin \
	       dist \
	       build \
	       $(GENERATED_PYTHON_FILES) \
	       $(GENERATED_GO_FILES) \
	       go/docs/calc.pdf \
	       go/.glide \
	       go/vendor \
	       .go-pkg-cache \
	       python/.tox \
	       htmlcov \
	       python/htmlcov
	find . -name "*.coverprofile" -type f -delete
	find . -name "coverage.xml" -type f -delete
	find . -name ".coverage" -type f -delete
	find . -name "*.pyc" -type f -delete

.PHONY: release release-once-tagged
release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=X.Y.Z)
endif
	utils/tag-release.sh $(VERSION)
	# Now decouple onto another make invocation, as we want some variables
	# (GIT_DESCRIPTION and BUNDLE_FILENAME) to be recalculated based on the
	# new tag.
	$(MAKE) release-once-tagged

release-once-tagged:
	@echo
	@echo "Will now build release artifacts..."
	@echo
	$(MAKE) pyinstaller calico/felix
	docker tag calico/felix calico/felix:$(VERSION)
	docker tag calico/felix quay.io/calico/felix:$(VERSION)
	@echo
	@echo "Felix release artifacts have been built:"
	@echo
	@echo "- PyInstaller bundle:     $(BUNDLE_FILENAME)"
	@echo "- Docker container image: calico/felix:$(VERSION)"
	@echo "- Same, tagged for Quay:  quay.io/calico/felix:$(VERSION)"
	@echo
	@echo "Now to publish this release to Github:"
	@echo
	@echo "- Push the new tag ($(VERSION)) to https://github.com/projectcalico/felix"
	@echo "- Go to https://github.com/projectcalico/felix/releases/tag/$(VERSION)"
	@echo "- Copy the tag content (release notes) shown on that page"
	@echo "- Go to https://github.com/projectcalico/felix/releases/new?tag=$(VERSION)"
	@echo "- Paste the copied tag content into the large textbox"
	@echo "- Attach the PyInstaller bundle"
	@echo "- Click the 'This is a pre-release' checkbox, if appropriate"
	@echo "- Click 'Publish release'"
	@echo
	@echo "Then, push the docker images to Dockerhub and Quay:"
	@echo
	@echo "- docker push calico/felix:$(VERSION)"
	@echo "- docker push quay.io/calico/felix:$(VERSION)"
	@echo
	@echo "If you also want to build Debian/Ubuntu and RPM packages for"
	@echo "the new release, use 'make deb' and 'make rpm'."
	@echo
