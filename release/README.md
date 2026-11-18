# Release

`release` is the CLI that builds and publishes releases and hashreleases.

- To run a release or a hashrelease, see [`RELEASING.md`](RELEASING.md).
- For how the code works and the rules a change must keep, see
  [`DESIGN.md`](DESIGN.md).

## Build

```sh
make build
```

This writes `bin/release`.

## Usage

```sh
./bin/release --help
```

Every command takes `--help`, which lists its flags and the environment
variables that set them.
