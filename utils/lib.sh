# Library of functions for Felix process and release automation.

# Get the root directory of the Git repository that we are in.
function git_repo_root {
    git rev-parse --show-toplevel
}
