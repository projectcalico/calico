#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
import os
import re
import io
import datetime

# To install, run python3 -m pip install PyGithub==2.3.0
from github import (
    Github,
    Auth,
    UnknownObjectException,
)  # https://github.com/PyGithub/PyGithub

# Validate required environment variables
assert os.environ.get("GITHUB_TOKEN"), "GITHUB_TOKEN must be set"
assert os.environ.get("VERSION"), "VERSION must be set"
VERSION = os.environ.get("VERSION")
assert VERSION.startswith("v"), "VERSION must start with 'v'"

# First create a Github instance. Create a token through GitHub website - provide "repo" auth.
auth = Auth.Token(os.environ.get("GITHUB_TOKEN"))
g = Github(auth=auth)

# The milestone to generate notes for.
MILESTONE = f"Calico {VERSION}"
RELEASE_STREAM = ".".join(VERSION.split(".")[:2])

# The file where we'll store the release notes.
FILENAME = f"release-notes/{VERSION}-release-notes.md"

# Repositories we care about. Add repositories here to include them in release
# note generation.
REPOS = [
    "calico",
    "bird",
]


class ReleaseNoteError(Exception):
    pass


# Returns a dictionary where the keys are repositories, and the values are
# a list of issues in the repository which match the milestone and
# have a `release-note-required` label.
def issues_by_repo():
    all_repos_issues = {}
    org = g.get_organization("projectcalico")
    for _repo in org.get_repos():
        if not _repo.name in REPOS:
            continue
        print(f"Processing repo {org.login}/{_repo.name}")

        # Find the milestone. This finds all open milestones.
        milestones = _repo.get_milestones()
        for m in milestones:
            if m.title == MILESTONE:
                # Found the milestone in this repo - look for issues (but only
                # ones that have been closed!)
                print(f"  found milestone {m.title}")
                try:
                    label = _repo.get_label("release-note-required")
                except UnknownObjectException:
                    # Label doesn't exist, skip this repo.
                    break
                milestone_issues = _repo.get_issues(
                    milestone=m, LABELS=[label], state="closed"
                )
                for issue in milestone_issues:
                    pr = issue.as_pull_request()
                    if pr.merged:
                        all_repos_issues.setdefault(_repo.name, []).append(issue)
                    else:
                        print(f"WARNING: {pr.number} is not merged, skipping")
    if len(all_repos_issues) == 0:
        raise ReleaseNoteError(f"no issues found for milestone {MILESTONE}")
    return all_repos_issues


# Takes an issue and returns the appropriate release notes from that
# issue as a list.  If it has a release-note section defined, that is used.
# If not, then it simply returns the title.
def extract_release_notes(issue):
    # Look for a release note section in the body.
    matches = re.findall(r"```release-note(.*?)```", str(issue.body), re.DOTALL)
    if matches:
        return [m.strip() for m in matches]
    else:
        print(f"WARNING: {issue.number} has no release-note section")
        return [issue.title.strip()]


if __name__ == "__main__":
    # Get the list of issues.
    all_issues = issues_by_repo()

    # Get date in the right format.
    date = datetime.date.today().strftime("%d %b %Y")

    # Make the directory, if needed.
    os.makedirs("release-notes")

    # Write release notes out to a file.
    with io.open(FILENAME, "w", encoding="utf-8") as f:
        f.write(f"{date}\n\n")
        f.write("#### Headline feature 1\n\n")
        f.write("#### Headline feature 2\n\n")
        f.write("#### Bug fixes\n\n")
        f.write("#### Other changes\n\n")
        for repo, issues in all_issues.items():
            print(f"Writing notes for {repo}")
            for i in issues:
                for note in extract_release_notes(i):
                    f.write(
                        f" - {note} [{repo} #{i.number}]({i.html_url}) (@{i.user.login})\n"
                    )

    print("")
    print("Release notes written to " + FILENAME)
    print("Please review for accuracy, and format appropriately before releasing.")
