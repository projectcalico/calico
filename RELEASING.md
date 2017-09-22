# Release process

## Resulting artifacts
Creating a new release creates the following artifact
* `bin/confd`

## Preparing for a release
Ensure that the branch you want to release from (typically master) is in a good state.
e.g. Update any pins in glide.yaml, update `vendor.go` with the new version, create PR,
and ensure tests pass and merge.

You should have no local changes and tests should be passing.

## Creating the release
1. `make clean && make`
2. Tag the release and push the tag
3. Create a release on Github, using the tag which was just pushed.
4. Update the `confd` artifact on github.com

