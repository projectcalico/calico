#!/usr/bin/env python3
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
# Validates an e2e profile and resolves the effective label filter.
# Inputs:  PROFILE_INPUT, LABEL_FILTER_INPUT (env vars)
# Outputs: profile_invalid, help_mode, available_profiles,
#          semaphore_pipeline, effective_label_filter (GITHUB_OUTPUT)
import os

import yaml

with open(".github/e2e-profiles.yaml") as f:
    config = yaml.safe_load(f)

profiles = config.get("profiles", {})
profile = os.environ.get("PROFILE_INPUT", "")
output_file = os.environ["GITHUB_OUTPUT"]

print(f"[DEBUG] profile={profile!r}")
print(f"[DEBUG] available profiles={list(profiles.keys())}")
print(f"[DEBUG] profile in profiles: {profile in profiles}")

with open(output_file, "a") as out:
    if not profile:
        names = "\n".join(f"- `{k}` \u2014 {v['description']}" for k, v in profiles.items())
        out.write("profile_invalid=true\n")
        out.write("help_mode=true\n")
        out.write(f"available_profiles<<ENDOFPROFILES\n{names}\nENDOFPROFILES\n")
    elif profile not in profiles:
        names = "\n".join(f"- `{k}` \u2014 {v['description']}" for k, v in profiles.items())
        out.write("profile_invalid=true\n")
        out.write("help_mode=false\n")
        out.write(f"available_profiles<<ENDOFPROFILES\n{names}\nENDOFPROFILES\n")
    else:
        p = profiles[profile]
        lf = os.environ.get("LABEL_FILTER_INPUT", "").strip()
        effective = lf if lf else p.get("default_label_filter", "")
        out.write("profile_invalid=false\n")
        out.write(f"semaphore_pipeline={p['semaphore_pipeline']}\n")
        out.write(f"effective_label_filter={effective}\n")
