# Release

This is a tool using for building Calico components for internal and external releases.

## Getting started

```sh
make clean
make build
```

## Usage

```sh
./bin/release --help
```

By default, it builds hash release. For actual releases, set `IS_HASHRELEASE=false`
