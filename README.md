# libcalico-go
This repositiory contains Calico's Go components:

- `libcalico`, which can be imported as `"github.com/tigera/libcalico-go/lib"`
- `calicoctl`

## Common set-up

Assuming you have already installed **go v1.6+**, perform the following simple steps to get building:

- [Install Glide](https://github.com/Masterminds/glide#install)

- Clone this repository to your Go project path: 
```
git clone git@github.com:tigera/libcalico-go.git $GOPATH/src/github.com/tigera/libcalico-go
```

- Switch to your project directory:
```
cd $GOPATH/src/github.com/tigera/libcalico-go
```

- Populate the `vendor/` directory in the project's root with this project's dependencies:
```
glide install
```

## Building calicoctl

### Non-release build
To do a quick, non-release build of calicoctl, suitable for local testing, run
```
make bin/calicoctl
```

The binary will be put in ./bin:
```
./bin/calicoctl --help
```

### Release build

For releases, we use a Docker-based build to ensure a clean environment with an appropriate glibc.  Specifically, we use a CentOS 6.6 container image to build against glibc v2.12.  this ensures compatibility with any later glibc.

To do a release build, run:
```
make release/calicoctl
```
The binary will be emitted to `./releases/calicoctl-<version>`
