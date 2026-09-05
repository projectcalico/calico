---
applyTo:
  - "**/*Makefile"
  - "**/*.mk"
---

# Fetching from remote repos in build files

CI runners share a source IP, so GitHub throttles the build in ways a laptop
never sees. Two wrappers centralise the handling — use them instead of calling
`curl` or `git clone` directly.

## Downloading a file

```make
	$(call fetch_file,https://github.com/org/repo/releases/download/$(VERSION)/foo.tgz,/tmp/foo.tgz)
```

Forces HTTP/1.1, which GitHub throttles less than HTTP/2, retries, and creates
the destination directory.

## Checking out a pinned revision

```make
	$(call fetch_repo,$(THING_REPO),$(THING_SHA),thing)
```

Fetches the revision in one round-trip and resets the remote URL every run, so
a directory left by an earlier build cannot fetch from a stale origin. Re-runs
do no network I/O. Disables the credential prompt, which a throttled clone
would otherwise block on until the job times out.

Pin a tag or a full SHA — a short SHA is rejected, and a branch name freezes at
the first commit fetched. Only that commit arrives, so `git describe` works
only when the revision is itself a tag, and merge-base does not work at all.

Name the URL `<THING>_REPO` next to the version pin; some repos are fetched
from more than one Makefile.

## Auth tokens

`fetch_repo` sends `GITHUB_TOKEN` when the environment has one — GitHub gives
authenticated git traffic higher limits. Unset, it stays anonymous.

`fetch_file` does not, deliberately: those URLs are CDN-served and not limited
by identity, and a stale token makes `raw.githubusercontent.com` return 404
instead of the file.

## Secrets on a recipe line

Make echoes each unprefixed recipe, so a token expanded by make into
`--header "Authorization: Bearer ..."` lands in the build log. Keep credential
handling inside the wrapper scripts, where the shell expands it at run time.
