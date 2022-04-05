#!/usr/bin/env python
import github
from github import Github  # https://github.com/PyGithub/PyGithub
import os

# First create a Github instance. Create a token through Github website - provide "repo" auth.
assert os.environ.get('GITHUB_TOKEN')
g = Github(os.environ.get('GITHUB_TOKEN'))

# Orgs to filter on.
REPOSITORIES = ["calico"]

login_exists = {}
logins_by_name = {}
nonames = []
titles = u'| Name   | GitHub |'
header = u'|--------|--------|'
linefmt = u'| {0:<40} | @{1} |'

def process_all_repos():
    global nonames
    org = g.get_organization("projectcalico")
    for repo in org.get_repos():
        if repo.name not in REPOSITORIES:
            # Skip repos which aren't part of the core project.
            continue
        for c in repo.get_contributors():
            login = c.login
            name = c.name
            if login in login_exists:
                pass
            elif name:
                logins_by_name[name] = login
            else:
                nonames.append(login)
            login_exists[login] = ""

    # Print a sorted list of contributors.
    names = logins_by_name.keys()
    names = sorted(names, key=lambda x: x.lower())
    nonames = sorted(nonames, key=lambda x: x.lower())
    print(titles)
    print(header)
    for name in names:
        login = logins_by_name[name]
        print(linefmt.format(name, login))
    # Print contributors with no name listed in their account.
    for login in nonames:
        print(linefmt.format("---", login))

if __name__ == "__main__":
    process_all_repos()
