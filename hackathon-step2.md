# Version Mismatch GitHub Lookup

Extending calicoctl commands

---

## The Idea

Calicoctl is a command-line utility that allows users to interact with Calico’s custom resources stored in the Kubernetes datastore. When calicoctl detects a version mismatch between the client and the cluster, it returns an error by design. This safeguard exists because API changes between releases may not be supported by older calicoctl versions, and using an outdated client can result in malformed resources in newer clusters.

In this example, you’ll learn how to enhance that error output by using a bit of Go to dynamically retrieve the latest Calico release and present it to the user.

By querying the GitHub API at the time the error occurs, we can embed the latest available version directly in the message. This gives users clear, actionable guidance in one place: upgrade to the latest release, downgrade to match the cluster, or use `--allow-version-mismatch` if they understand and accept the risk.

---

## How We Achieved It

### 1. Add `fetchLatestCalicoVersion`

In `calicoctl/calicoctl/commands/common/version_mismatch.go`, we added a helper that:

- Calls `https://api.github.com/repos/projectcalico/calico/releases/latest`
- Uses a 5-second timeout via `context.WithTimeout` to avoid hanging
- Parses the JSON response into a `githubRelease` struct with `tag_name`
- Returns the tag name on success, or `""` on any failure
- Logs failures at debug level only—no user-facing errors

### 2. Update the Error Message

When a version mismatch is detected, we now:

1. Call `fetchLatestCalicoVersion()` before building the message
2. Build a multi-line message with:
   - "Version mismatch detected"
   - Client and cluster versions
   - "Latest available Calico version: X" (only if the fetch succeeded)
   - A link to the release notes
   - Instructions to upgrade/downgrade or use `--allow-version-mismatch`

### 3. Adjust the Test

The system test in `calicoctl/tests/st/calicoctl/test_flags.py` asserted on the substring `"version mismatch."`. We updated it to `"Version mismatch detected"` to match the new message.

---

## Gotchas

- **HTTP timeout**: The GitHub API call uses a 5-second timeout. If it times out or fails, we simply omit the "Latest available" line. The error message is still useful.
- **Silent failure**: We never surface fetch errors to the user. Failures are logged with `log.Debugf` only, so they appear only when debug logging is enabled.
- **Test assertion**: The test checks for a substring in the error output. Changing the message wording requires updating the assertion accordingly.

---

## Adding Your Own Functionality

To extend this further:

- **Other API lookups**: Follow the same pattern: `context.WithTimeout`, `http.NewRequestWithContext`, parse JSON, and fail silently with `log.Debugf`.
- **Different endpoints**: Swap the URL constant and adjust the response struct.
- **Unit tests**: Use `net/http/httptest` to mock the API and test success, timeout, and error cases without hitting the real GitHub API.

---

## What's Next

Learn more about Calico, version compatibility, and release notes at [docs.tigera.io](https://docs.tigera.io).
