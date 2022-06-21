#!/usr/bin/env python
import os
import subprocess

login_exists = {}
info_by_name = {}
titles = u'| Name   | Email  |'
header = u'|--------|--------|'
linefmt = u'| {0:<40} | {1}  |'

def get_contributors():
    # Get output from git.
    process = subprocess.Popen(['git', '--no-pager', 'shortlog', '-se'],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout, _ = process.communicate()

    # Do our best to filter duplicates.
    for line in stdout.splitlines():
        if line == "" or line is None:
            continue

        name, login = extract_author(line)

        # Downcase for comparison.
        if login in login_exists:
            pass
        elif name:
            info_by_name[name.lower()] = (name, login)
        login_exists[login] = ""

    # Print a sorted list of contributors.
    names = info_by_name.keys()
    names = sorted(names, key=lambda x: x.lower())
    print(titles)
    print(header)
    for name in names:
        info = info_by_name[name]
        try:
            print(linefmt.format(info[0].decode('utf8'), info[1].decode('utf8')))
        except UnicodeDecodeError:
            print(name)

def extract_author(line):
    splits = line.split(b"\t")
    if len(splits) == 2:
        # Splits is now of form:
        # [1, "First Last e@mail.com"]
        splits = splits[1].split(b" ")
        if len(splits) >= 2:
            return b" ".join(splits[0:-1]), extract_email(splits[-1])

    raise Exception("Bad line: %s, splits=%s" % (line, splits))

def extract_email(s):
    return s.replace(b"<", b"").replace(b">", b"")

if __name__ == "__main__":
    get_contributors()
