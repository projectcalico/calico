# Cherry-pick PR Summary

## Completed Work

✅ **Successfully created cherry-pick branch for PR #10893 against release-v3.30**

### What Was Done:
1. **Analyzed original PR #10893**: "Remove manual Windows Kubernetes service installation"
   - Commit: `9d1147cf55a0b338bf02dd469281bd73c931d6c2`
   - Author: Song Jiang
   - Merged to master on August 28, 2025

2. **Created cherry-pick branch**: `cherry-pick-pr10893-v3.30`
   - Based on: `origin/release-v3.30`
   - Cherry-picked commit: `c388566ac38eb31c990d6c18219b4daf2f063f06`
   - Applied cleanly with no conflicts

3. **Validated changes**:
   - Removed 5 PowerShell files from Windows Kubernetes service installation
   - Modified 2 files to default to capz provisioner
   - All syntax validation passed

4. **Created comprehensive documentation**:
   - `CHERRY_PICK_PR_DETAILS.md`: Complete details and PR template
   - `cherry-pick-script.sh`: Script to complete the process

### Files Changed in Cherry-pick:
- **Deleted**: 5 PowerShell service installation scripts
- **Modified**: 2 test scripts to remove manual provisioner option

### Ready for PR Creation:
The cherry-pick branch is ready and the following information is provided:

**PR Title**: `[release-v3.30] cherry-pick: Remove manual Windows Kubernetes service installation`

**Required Labels**: `release-note-required`, `docs-not-required`

**Milestone**: Next v3.30.x release

**Complete PR description** and all necessary details are in `CHERRY_PICK_PR_DETAILS.md`.

## What's Needed to Complete:

Since I cannot directly push branches to the repository, a maintainer with push access needs to:

1. **Push the cherry-pick branch**:
   ```bash
   git push origin cherry-pick-pr10893-v3.30
   ```

2. **Create the PR** using the details in `CHERRY_PICK_PR_DETAILS.md`

3. **Follow the post-merge steps** to update labels on the original PR

The cherry-pick has been successfully prepared and is ready for completion following the Calico contribution guidelines.