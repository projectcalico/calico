#!/usr/bin/env python
import github
from github import Github  # https://github.com/PyGithub/PyGithub
import os
import subprocess

# First create a Github instance. Create a token through Github website - provide "repo" auth.
assert os.environ.get('GITHUB_TOKEN')
g = Github(os.environ.get('GITHUB_TOKEN'))

# Orgs to filter on.
REPOSITORIES = ["calico"]

login_exists = {}
logins_by_name = {}
titles = u'| Name   | Email  |'
header = u'|--------|--------|'
linefmt = u'| {0:<40} | @{1} |'

def get_contributors():
    # Get output from git.
    process = subprocess.Popen(['git', '--no-pager', 'shortlog', '-se'],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout, _ = process.communicate()

    # Do our best to filter duplicates.
    for line in stdout.split("\n"):
        if line == "":
            continue

        name, login = extract_author(line)
        if login in login_exists:
            pass
        elif name:
            logins_by_name[name] = login
        login_exists[login] = ""

    # Print a sorted list of contributors.
    names = logins_by_name.keys()
    names = sorted(names, key=lambda x: x.lower())
    print(titles)
    print(header)
    for name in names:
        login = logins_by_name[name]
        try:
            print(linefmt.format(name.decode('utf8'), login))
        except UnicodeDecodeError:
            print(name)

def extract_author(line):
    splits = line.split("\t")
    if len(splits) == 2:
        # Splits is now of form:
        # [1, "First Last e@mail.com"]
        splits = splits[1].split(" ")
        if len(splits) >= 2:
            return " ".join(splits[0:-1]), splits[-1]

    raise Exception("Bad line: %s" % line)

if __name__ == "__main__":
    get_contributors()
