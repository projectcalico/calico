---
applyTo:
  - "**/Makefile"
  - "**/*.mk"
---

# Fetching from GitHub in build files

CI runners share a source IP, so anything the build pulls from GitHub is
subject to throttling that a laptop never sees.

## Force HTTP/1.1 on every GitHub download

Pass `$(CURL_GITHUB_OPTS)` to any `curl` that hits `github.com` or
`raw.githubusercontent.com`. GitHub throttles HTTP/2 harder than HTTP/1.1,
and a throttled download fails the job. The variable is defined in
`lib.Makefile`, which every component Makefile already includes.

```make
curl -sSfL --retry 5 $(CURL_GITHUB_OPTS) -o /tmp/foo.tgz https://github.com/org/repo/releases/download/$(VERSION)/foo.tgz
```

`wget` needs nothing — it only speaks HTTP/1.1.

## Do not add a token to these downloads

Only `api.github.com` is rate limited by identity (60/hr anonymous vs
5000/hr authenticated), and no Makefile calls it — `github_call_api` in
`lib.Makefile` is the one API caller and sends its own token.

Release, archive and raw URLs are CDN-served and return no rate-limit
headers, so a token buys nothing. On `raw.githubusercontent.com` it makes
things worse: a stale or wrong token turns a working 200 into a 404.

## Never put a secret on a recipe line

Make echoes each unprefixed recipe before running it, so
`--header "Authorization: Bearer $(TOKEN)"` prints the token into the build
log. Write `$$TOKEN` so the shell expands it at run time, and prefix the
line with `@`.

## Fetch a pinned commit in one round-trip

`git clone --depth 1` only fetches the default branch tip, so a later
`git checkout <pinned-sha>` can never find it and always falls through to a
second fetch. Fetch the commit directly instead:

```make
	mkdir -p thing
	cd thing && \
	  git init -q . && \
	  git remote add origin $(THING_REPO) 2>/dev/null || \
	    git remote set-url origin $(THING_REPO); \
	  git fetch -q --depth 1 origin $(THING_SHA) && \
	  git checkout -q $(THING_SHA)
```

Set the remote URL every run, not just on first init — a directory left by
an earlier build may have no origin or a stale one.

This needs a full 40-character SHA. `git fetch` cannot resolve an
abbreviated one, so pins like `ff287602` must keep using `git clone`.

Do not reach for `--filter=blob:none` to trim a clone: checkout then fetches
the missing blobs, which adds round-trips rather than removing them.

## Keep the repo URL in a variable

Name it `<THING>_REPO` next to the version pin. Several repos are cloned
from more than one Makefile.
