#!/bin/bash

set -e

# Make sure that go list works because IDEs and tooling rely on it.
go list -m -json -mod=mod all > /dev/null || {
  echo "go list failed. This may be due to missing replace"
  echo "directives for new transitive dependencies."
  exit 1
}

# Run a tidy so that go.mod will be left dirty if it's not tidy.
go mod tidy