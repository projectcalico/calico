# Open-source postrelease tests

## How to run

You can use `go test`` to run the tests:

```bash
go test -v ./...
```

Or, for slightly nicer/cleaner progress output, `gotestsum`:

```bash
gotestsum --format dots-v2 ./...
```

## How to lint

This package has been linted with [revive](https://github.com/mgechev/revive); if you're
adding new tests or functionality, please consider doing the same.

## Structure

```text
pkg/*           # All the various utility functions
tests/          # The actual test suites
  oss/          # Test suites for Calico OSS specifically
    openstack/  # Openstack-related tests
    images/     # Tests to validate container images were published
    helm/       # Fetches and validates the helm chart
    github/*    # Github-related validations for various repositories
```

In future, more test suites will be added to `tests`; for example, maybe `tests/operator` for
operator-related validations.
