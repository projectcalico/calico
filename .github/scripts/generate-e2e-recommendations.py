#!/usr/bin/env python3
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
# Generates e2e test recommendations based on changed files.
# Reads: /tmp/changed-files.txt, .github/e2e-path-labels.yaml, .github/e2e-profiles.yaml
# Writes: /tmp/recommendation-body.md
from collections import defaultdict
from fnmatch import fnmatch

import yaml

with open(".github/e2e-path-labels.yaml") as f:
    path_labels_config = yaml.safe_load(f)

with open(".github/e2e-profiles.yaml") as f:
    profiles_config = yaml.safe_load(f)

with open("/tmp/changed-files.txt") as f:
    changed_files = [line.strip() for line in f if line.strip()]

recommendations = defaultdict(lambda: {"reason": "", "matched_files": []})

for rule in path_labels_config.get("path_labels", []):
    patterns = rule.get("paths", [])
    profiles = rule.get("profiles", [])
    label = rule.get("labels", "")
    reason = rule.get("reason", "")

    matched = [f for f in changed_files if any(fnmatch(f, p) for p in patterns)]
    if not matched:
        continue

    for profile in profiles:
        key = (profile, label)
        rec = recommendations[key]
        rec["reason"] = reason
        for mf in matched:
            if mf not in rec["matched_files"]:
                rec["matched_files"].append(mf)

lines = []
if recommendations:
    lines.append("Based on the changes in this PR, here are some recommended commands:\n")
    for (profile, label), info in sorted(recommendations.items()):
        reason = info["reason"]
        matched_files = info["matched_files"]

        if label:
            cmd = f'/e2e {profile} --label-filter="{label}"'
        else:
            cmd = f"/e2e {profile}"

        shown = matched_files[:3]
        remainder = len(matched_files) - len(shown)
        file_list = ", ".join(f"`{f}`" for f in shown)
        if remainder > 0:
            file_list += f" and {remainder} more"

        lines.append(f"- `{cmd}` - {reason} ({file_list})")
    lines.append("\nCopy a command and paste it as a PR comment to trigger.")
else:
    lines.append(
        "No specific tests were identified for the changes in this PR. "
        "Consider running one of the following for general coverage:\n"
    )
    lines.append("- `/e2e iptables-gcp`")
    lines.append("- `/e2e bpf-gcp`")
    lines.append("- `/e2e nft-gcp`")

body = "\n".join(lines)
with open("/tmp/recommendation-body.md", "w") as f:
    f.write(body)
