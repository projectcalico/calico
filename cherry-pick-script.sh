#!/bin/bash

# Cherry-pick PR Creation Script
# This script completes the cherry-pick process for PR #10893 to release-v3.30

set -e

echo "=== Cherry-pick PR Creation Script ==="
echo "Target: release-v3.30"
echo "Original PR: #10893"
echo "Original commit: 9d1147cf55a0b338bf02dd469281bd73c931d6c2"
echo ""

# Verify we're in the right directory
if [ ! -f "CHERRY_PICK_PR_DETAILS.md" ]; then
    echo "Error: CHERRY_PICK_PR_DETAILS.md not found. Please run from the repository root."
    exit 1
fi

# Check if the cherry-pick branch exists
if ! git show-ref --verify --quiet refs/heads/cherry-pick-pr10893-v3.30; then
    echo "Error: cherry-pick-pr10893-v3.30 branch not found."
    echo "Please run the cherry-pick commands first:"
    echo "  git checkout -b cherry-pick-pr10893-v3.30 origin/release-v3.30"
    echo "  git cherry-pick 9d1147cf55a0b338bf02dd469281bd73c931d6c2"
    exit 1
fi

echo "✓ Cherry-pick branch found"

# Show the commit details
echo ""
echo "=== Cherry-picked Commit Details ==="
git log --oneline -1 cherry-pick-pr10893-v3.30
echo ""

# Show the files changed
echo "=== Files Changed ==="
git show --name-status cherry-pick-pr10893-v3.30 | grep -E '^[ADM]'
echo ""

# Push the cherry-pick branch
echo "=== Pushing Cherry-pick Branch ==="
echo "Running: git push origin cherry-pick-pr10893-v3.30"
git push origin cherry-pick-pr10893-v3.30

echo ""
echo "✓ Cherry-pick branch pushed successfully"
echo ""

# Instructions for creating the PR
echo "=== Next Steps ==="
echo "1. Go to: https://github.com/projectcalico/calico/compare/release-v3.30...cherry-pick-pr10893-v3.30"
echo ""
echo "2. Use this PR title:"
echo "   [release-v3.30] cherry-pick: Remove manual Windows Kubernetes service installation"
echo ""
echo "3. Use the description from CHERRY_PICK_PR_DETAILS.md"
echo ""
echo "4. Add these labels:"
echo "   - release-note-required"
echo "   - docs-not-required"
echo ""
echo "5. Set milestone to the next v3.30.x release"
echo ""
echo "6. After PR is merged, update original PR #10893:"
echo "   - Remove 'cherry-pick-candidate' label"
echo "   - Add 'cherry-pick-completed' label"
echo ""

echo "=== Cherry-pick Process Complete ==="