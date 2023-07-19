#!/usr/bin/env python3

import os
import subprocess

from types import SimpleNamespace

from ruamel.yaml import YAML

yaml = YAML()

from rich import print

# ====

CHARTS = ["charts/calico/values.yaml", "charts/tigera-operator/values.yaml"]


def get_git_root():
    return (
        subprocess.check_output(["git", "rev-parse", "--show-toplevel"])
        .strip()
        .decode()
    )


def get_git_describe():
    result = (
        subprocess.check_output(["git", "describe", "--tags", "--long"])
        .strip()
        .decode()
    )
    describe = result.split("-")
    version, commits, abbr = describe

    d = SimpleNamespace(
        version=version, commits=int(commits), abbr=abbr, commit=abbr.strip("g")
    )
    return d


def parse_version(version):
    return [int(ver) for ver in version.strip("v").split(".")]


def unparse_version(version):
    return f"v{version[0]}.{version[1]}.{version[2]}"


def bump_version_string(version_string):
    version = parse_version(version_string)
    version[2] += 1
    new_version_string = unparse_version(version)
    return new_version_string


def get_should_version(describe):
    if describe.commits == 0:
        return describe.version
    else:
        return bump_version_string(describe.version)


os.chdir(get_git_root())


def update_calico_chart(chart_file_path):
    with open(chart_file_path) as values_file:
        input_values = yaml.load(values_file)

    describe = get_git_describe()
    old_version = input_values["version"]
    tag_version = describe.version

    should_version = get_should_version(describe)

    update_msg = (
        f"[bold]Checking calico chart '{chart_file_path}'[/bold]",
        f"  Detected tag:    [cyan]{tag_version}[/cyan]",
        f"  Target version:  [cyan]{should_version}[/cyan]",
        f"  Current version: [cyan]{old_version}[/cyan]",
    )
    print("\n    ".join(update_msg))

    if should_version != old_version:
        input_values["version"] = should_version
        print(f"  Updating chart from {old_version} to {should_version}")
        with open(chart_file_path, "w") as output_yaml:
            yaml.dump(input_values, output_yaml)
    else:
        print(f"  Already at target version '{should_version}'; nothing to do.")


def update_operator_chart(chart_file_path):
    with open(chart_file_path) as values_file:
        input_values = yaml.load(values_file)

    describe = get_git_describe()
    old_version = input_values["calicoctl"]["tag"]
    tag_version = describe.version

    should_version = get_should_version(describe)

    update_msg = (
        f"[bold]Checking operator chart '{chart_file_path}'[/bold]",
        f"  Detected tag:    [cyan]{tag_version}[/cyan]",
        f"  Target version:  [cyan]{should_version}[/cyan]",
        f"  Current version: [cyan]{old_version}[/cyan]",
    )
    print("\n    ".join(update_msg))

    if should_version != old_version:
        input_values["calicoctl"]["tag"] = should_version
        print(f"  Updating chart from {old_version} to {should_version}")
        with open(chart_file_path, "w") as output_yaml:
            yaml.dump(input_values, output_yaml)
    else:
        print(f"  Already at target version '{should_version}'; nothing to do.")


update_calico_chart("charts/calico/values.yaml")
print()
update_operator_chart("charts/tigera-operator/values.yaml")
