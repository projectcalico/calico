#!/usr/bin/env python3
import os
import re
import sys
import logging
import pathlib
import argparse
import datetime

import github  # https://github.com/PyGithub/PyGithub

logging.basicConfig(
    format='[Release Notes] [%(levelname)-7s] %(message)s', level=logging.INFO)

# First create a Github instance. Since we're using public repositories,
# we don't need a token. If this changes, add a token with 'repo' access!
# If you get a rate limit error, export GITHUB_TOKEN
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", None)
if GITHUB_TOKEN:
    logging.info(
        f"Using Github access token from GITHUB_TOKEN environment variable")

g = github.Github(GITHUB_TOKEN)

# Repositories we care about. Add repositories here to include them in release
# note generation.
REPOS = [
    "calico",
    "bird",
]

parser = argparse.ArgumentParser()
parser.add_argument("--version", action="store", metavar="VERSION", required=True,
                    help="The version number of the release, in the format v3.xx.y")
parser.add_argument("--fail-missing", action="store_true", default=False,
                    help="Fail if a repository is missing its milestone")
parser.add_argument("--organization", action="store", metavar="ORG", default="projectcalico",
                    help="The organization to check for projects in. Defaults to 'projectcalico'.")
args = parser.parse_args()

# The milestone to generate notes for.
VERSION = args.version
MILESTONE = f"Calico {VERSION}"
RELEASE_STREAM = ".".join(VERSION.split(".")[:2])

# The file where we'll store the release notes.
FILENAME = f"{VERSION}-release-notes.md"


# Returns a dictionary where the keys are repositories, and the values are
# a list of issues in the repository which match the milestone and
# have a `release-note-required` label.
def issues_by_repo():
    all_issues = {}
    org = g.get_organization(args.organization)
    for repo_name in REPOS:
        repo = org.get_repo(repo_name)
        sys.stdout.flush()

        # Find the milestone. This finds all open milestones.
        all_milestones = repo.get_milestones()
        matching_milestones = [
            m for m in all_milestones if m.title == MILESTONE]
        all_milestones_titles = [m.title for m in all_milestones]
        if len(matching_milestones) == 0:
            logging.warning(
                f"Fetching milestone {MILESTONE} from repo {org.login}/{repo.name} failed!")
            logging.warning(f"Maybe you're looking for one of these?")
            for milestone_title in all_milestones_titles:
                logging.warning(f"  - {milestone_title}")
            if args.fail_missing:
                logging.error(
                    f"Stopping here because --fail-missing was specified")
                sys.exit(-2)
            else:
                continue
        milestone = matching_milestones[0]
        # Found the milestone in this repo - look for issues (but only
        # ones that have been closed!)
        # TODO: Assert that the PR has been merged somehow?
        logging.info(
            f"Fetching milestone {MILESTONE} from repo {org.login}/{repo.name} succeeded!")
        try:
            label = repo.get_label("release-note-required")
        except github.UnknownObjectException:
            # Label doesn't exist, skip this repo.
            break
        issues = repo.get_issues(milestone=milestone, labels=[
                                 label], state="closed")
        for i in issues:
            all_issues.setdefault(repo.name, []).append(i)
    return all_issues

# Takes an issue and returns the appropriate release notes from that
# issue as a list.  If it has a release-note section defined, that is used.
# If not, then it simply returns the title.


def extract_release_notes(issue):
    logging.debug(f"  - #{issue.number} {issue.title}")
    # Look for a release note section in the body.
    matches = re.findall(r'```release-note(.*?)```', issue.body, re.DOTALL)
    if matches:
        return [m.strip() for m in matches]
    else:
        logging.warning(f"{issue.number} has no release-note section")
        return [issue.title.strip()]

# if __name__ == "__main__":


def main():
    logging.info(
        f"Fetching all issues for repositories in milestone {MILESTONE} for these repositories: {', '.join(REPOS)}")
    # Get the list of issues.
    all_issues = issues_by_repo()

    if not all_issues:
        logging.warning(
            "No issues were fetched from any repositories; your release notes will be empty!")

    # Get date in the right format.
    date = datetime.date.today().strftime("%d %b %Y")

    # Make the directory, if needed.
    release_notes_dir = pathlib.Path("release-notes")
    release_notes_dir.mkdir(exist_ok=True)
    release_notes_file = release_notes_dir.joinpath(FILENAME)

    # Generate release notes
    output = [
        f"{date}",
        "#### Headline feature 1",
        "#### Headline feature 2",
        "#### Bug fixes",
        "#### Other changes"
    ]

    release_notes_lines = []
    for repo, issues in all_issues.items():
        logging.info(f"Writing notes for repository {repo}")
        for issue in issues:
            for note in extract_release_notes(issue):
                release_notes_lines.append(
                    f" - {note} [{repo} #{issue.number}]({issue.html_url}) (@{issue.user.login})")

    release_notes = "\n".join(release_notes_lines)
    output.append(release_notes)

    final_output = "\n\n".join(output) + "\n"

    release_notes_file.write_text(final_output)

    logging.info(f"Release notes written to {FILENAME}")
    logging.info(
        "Please review for accuracy, and format appropriately before releasing.")


if __name__ == "__main__":
    try:
        main()
    except github.RateLimitExceededException:
        logging.error("Unable to access the Github API due to rate limiting. Please wait a bit before your next attempt, or `export GITHUB_TOKEN` with a token which has `repo` access.")
