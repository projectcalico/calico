---
name: operator-versioning
description: Map between Calico/enterprise versions and tigera/operator release branches. Use this skill whenever you need to determine which operator branch corresponds to a Calico or enterprise release (e.g., "which operator branch is Calico v3.30?"), or the reverse (e.g., "what Calico version does release-v1.40 ship?"). Also use this skill whenever cherry-picking to operator release branches, creating cherry-pick PRs targeting release branches, or any task that requires knowing the operator↔Calico version relationship. Trigger even if the user doesn't explicitly ask about versioning — if the task involves targeting an operator release branch by Calico version, use this skill to find the right branch.
---

# Operator Version Mapping

The tigera/operator repo uses its own versioning (release-v1.X) that does NOT have a simple 1:1 offset with Calico versions. Some operator branches correspond to Calico OSS releases, others to Calico Enterprise releases, and the mapping changes over time. Never guess the mapping — always look it up.

## Calico version → operator branch

The authoritative source is the `OPERATOR_BRANCH` variable in `metadata.mk`:

1. **Calico OSS (projectcalico/calico)**: check `metadata.mk` on the `release-vX.Y` branch.
   ```bash
   git show origin/release-vX.Y:metadata.mk | grep OPERATOR_BRANCH
   ```

2. **Calico Enterprise (tigera/calico-private)**: check `metadata.mk` on the appropriate `release-calient-*` branch. The branch naming convention is `release-calient-vX.Y-Z` where `-Z` is the EP (engineering preview) number (e.g., `release-calient-v3.23-1` = v3.23 EP1). List matching branches to find the right one:
   ```bash
   git branch -r | grep "release-calient-vX.Y"
   git show origin/release-calient-vX.Y-Z:metadata.mk | grep OPERATOR_BRANCH
   ```

3. **Confirm** by checking `config/calico_versions.yml` or `config/enterprise_versions.yml` on the operator branch (in tigera/operator) — the `title` field shows the Calico/enterprise version that branch ships:
   ```bash
   git show origin/release-v1.XX:config/calico_versions.yml | head -3
   git show origin/release-v1.XX:config/enterprise_versions.yml | head -3
   ```

If you don't have the calico or calico-private repo locally, you can work backwards from the operator side: check `config/calico_versions.yml` on several candidate operator branches until you find the one whose `title` matches the target Calico version.

## Operator branch → Calico version

Check the version files on the operator branch directly:

```bash
git show origin/release-v1.XX:config/calico_versions.yml | head -3
git show origin/release-v1.XX:config/enterprise_versions.yml | head -3
```

The `title` field in each file gives the Calico OSS and enterprise versions respectively.

## Important notes

- Multiple operator branches can ship the same Calico OSS version (e.g., one paired with an OSS release, another with an enterprise release). The `metadata.mk` approach is definitive for a given Calico/enterprise release stream.
- The GitHub releases page for tigera/operator can also help — it shows which operator versions were released from which branches and what Calico versions they include.
