# Cherry-pick PR Details for release-v3.30

## Summary
This document contains the complete details for creating a cherry-pick PR similar to #10893 against the `release-v3.30` branch.

## Original PR Information
- **PR Number**: #10893
- **Title**: Remove manual Windows Kubernetes service installation
- **Commit SHA**: 9d1147cf55a0b338bf02dd469281bd73c931d6c2
- **Author**: Song Jiang <song@tigera.io>
- **Merged**: August 28, 2025
- **Original Target**: master branch
- **Milestone**: Calico v3.31.0

## Cherry-pick Branch Details
- **Cherry-pick Branch**: cherry-pick-pr10893-v3.30
- **Target Branch**: release-v3.30
- **Cherry-picked Commit**: c388566ac38eb31c990d6c18219b4daf2f063f06

## Commands Used for Cherry-pick
```bash
# Fetch all branches
git fetch --all

# Create cherry-pick branch based on target release branch
git checkout -b cherry-pick-pr10893-v3.30 origin/release-v3.30

# Cherry-pick the commit from the original PR
git cherry-pick 9d1147cf55a0b338bf02dd469281bd73c931d6c2

# Verify the cherry-pick
git log --oneline -3
git show --name-status HEAD
```

## Files Changed
The cherry-pick successfully applied and made the following changes:

### Files Deleted:
- `node/windows-packaging/CalicoWindows/kubernetes/README.txt`
- `node/windows-packaging/CalicoWindows/kubernetes/install-kube-services.ps1`
- `node/windows-packaging/CalicoWindows/kubernetes/kube-proxy-service.ps1`
- `node/windows-packaging/CalicoWindows/kubernetes/kubelet-service.ps1`
- `node/windows-packaging/CalicoWindows/kubernetes/uninstall-kube-services.ps1`

### Files Modified:
- `process/testing/winfv-felix/run-fv-full.ps1`
- `process/testing/winfv-felix/setup-fv-capz.sh`

## Validation Performed
- [x] Cherry-pick applied cleanly without conflicts
- [x] PowerShell syntax validation passed
- [x] Shell script syntax validation passed
- [x] Git status shows clean working tree
- [x] Branch is ready for PR creation

## Required PR Details

### PR Title Format
`[release-v3.30] cherry-pick: Remove manual Windows Kubernetes service installation`

### PR Description Template
```markdown
## Description

This PR cherry-picks the changes from #10893 to the release-v3.30 branch.

Original PR: https://github.com/projectcalico/calico/pull/10893

This change removes manual Windows Kubernetes service installation and simplifies Felix Windows FV to default to capz provisioner.

Note: This PR does not remove the process of releasing a Calico for Windows zip file. This will be addressed by another PR.

## Related issues/PRs

- Original PR: #10893

## Cherry-pick Details

- Source commit: 9d1147cf55a0b338bf02dd469281bd73c931d6c2
- Cherry-picked commit: c388566ac38eb31c990d6c18219b4daf2f063f06
- Target branch: release-v3.30

## Release Note

```release-note
Removed manual Windows Kubernetes service installation scripts.
```

## Reminder for the reviewer

Make sure that this PR has the correct labels and milestone set.

Every PR needs one `docs-*` label.

- `docs-pr-required`: This change requires a change to the documentation that has not been completed yet.
- `docs-completed`: This change has all necessary documentation completed.
- `docs-not-required`: This change has no user-facing impact and requires no docs.

Every PR needs one `release-note-*` label.

- `release-note-required`: This PR has user-facing changes. Most PRs should have this label.
- `release-note-not-required`: This PR has no user-facing changes.

Other optional labels:

- `cherry-pick-candidate`: This PR should be cherry-picked to an earlier release. For bug fixes only.
- `needs-operator-pr`: This PR is related to install and requires a corresponding change to the operator.
```

### Required Labels
- `release-note-required`
- `docs-not-required` (since this removes scripts that are not user-facing documentation)

### Required Milestone
- Should be set to the next v3.30.x release milestone

## Next Steps to Complete Cherry-pick Process

1. **Push the cherry-pick branch**:
   ```bash
   git push origin cherry-pick-pr10893-v3.30
   ```

2. **Create PR against release-v3.30**:
   - Base branch: `release-v3.30`
   - Compare branch: `cherry-pick-pr10893-v3.30`
   - Use the title and description template above
   - Add required labels and milestone

3. **Notify the original reviewer** of the cherry-pick PR

4. **After PR is merged**, update original PR #10893:
   - Remove `cherry-pick-candidate` label
   - Add `cherry-pick-completed` label

## Verification Commands
To verify this cherry-pick is correct, compare with the original:
```bash
# Check differences between original and cherry-picked commits
git diff 9d1147cf55a0b338bf02dd469281bd73c931d6c2 c388566ac38eb31c990d6c18219b4daf2f063f06

# Should show no differences in the actual changes, only commit metadata
```