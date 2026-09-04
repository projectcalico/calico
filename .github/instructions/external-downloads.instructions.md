---
applyTo:
  - "**/*Makefile"
  - "**/*.mk"
---

# Fetching from remote repos in build files

CI runners share a source IP, so anything the build pulls from GitHub is
subject to throttling that a laptop never sees. Two wrappers centralise the
handling — use them instead of calling `curl` or `git clone` directly.

## Downloading a file

```make
	$(call fetch_file,https://github.com/org/repo/releases/download/$(VERSION)/foo.tgz,/tmp/foo.tgz)
```

Forces HTTP/1.1, which GitHub throttles less than HTTP/2, and retries.
Creates the destination directory.

## Checking out a pinned revision

```make
	$(call fetch_repo,$(THING_REPO),$(THING_SHA),thing)
```

Fetches the revision in one network round-trip, sets the remote URL every run
so a directory left by an earlier build cannot fetch from a stale origin, and
disables the git credential prompt on CI — a throttled anonymous clone
otherwise blocks on that prompt until the job times out.

Re-running does no network I/O once the revision is present. Pin a tag or a
full commit SHA; a short SHA is rejected, and a branch name freezes at the
first commit fetched.

Only the pinned commit is fetched: no history and no other tags. `git describe`
resolves only when the revision is itself a tag, and a merge-base against the
checkout does not work.

## Keep the repo URL in a variable

Name it `<THING>_REPO` next to the version pin. Some repos are fetched from
more than one Makefile.

## Auth tokens

Neither wrapper sends one, and a download recipe should not add one. Release,
archive and raw URLs are CDN-served and are not rate limited by identity
today, so a token buys nothing, and a stale one makes
`raw.githubusercontent.com` return 404 instead of the file.

That balance is what makes the wrappers token-free, not a rule against auth.
If GitHub starts rate limiting these downloads by source IP, authenticating
becomes the fix — change it in the wrappers so every call site moves at once.
The REST API does rate limit by identity, and the GitHub API helpers in
`lib.Makefile` pass their own token for it.

## Secrets on a recipe line

Make echoes each unprefixed recipe before running it, so a token expanded by
make into `--header "Authorization: Bearer ..."` lands in the build log. Keep
credential handling inside the wrapper scripts, where the shell expands it at
run time.
