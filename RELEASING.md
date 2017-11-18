# Release process

## Resulting artifacts
Creating a new release creates the following artifact
* `bin/confd`

## Preparing for a release
Ensure that the branch you want to release from (typically master) is in a good state.
e.g. Update any pins in glide.yaml

You should have no local changes and tests should be passing.

Verify that the versions of calicoctl etc. at the top of the Makefile are correct, and that
glide has been revved to the appropriate version of libcalico-go.

## Creating the release

1. Run `make release VERSION=<version>` and follow the steps.
1. Create a release on Github, using the tag which was just pushed.
1. Update the `confd` artifact on github.com
