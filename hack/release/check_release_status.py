#!/usr/bin/env python3

# PYZSHCOMPLETE_OK

import re
import time
import json
import argparse
import subprocess

from functools import cache

try:
    import yaml

    import rich.color
    from rich.text import Text
    from rich.table import Table
    from rich.style import Style
    from rich.emoji import Emoji
    from rich.console import Console
    from rich.traceback import install as install_rich_traceback
    from rich import print

    import xdg

except ImportError as ex:
    import sys
    print(f"Err: Unable to load third-party module '{ex.name}'. Please try running '{sys.executable} -m pip install -U rich pyyaml xdg'", file=sys.stderr)
    sys.exit(1)

# import argcomplete
# import pyzshcomplete

install_rich_traceback(show_locals=False, suppress=[rich])

# For creating our URLs
from urllib.parse import urlparse, urlunparse, quote_plus

# Static defines
VERSIONS_FILE = "calico/_data/versions.yml"

GH_JSON_FIELDS = ("number","title","url","labels", "body")
GH_LABELS_URL_BASE = 'https://github.com/projectcalico/calico/pulls?q=is%3Aopen+is%3Apr+milestone%3A"Calico+{milestone_version}"+label%3A{label_name}'
APP_NAME = "calico_oss_preflight"
CACHE_DIR = xdg.xdg_cache_home().joinpath(APP_NAME)

CACHE_DIR.mkdir(exist_ok=True)

STATUS = {
    True: ":white_check_mark:",
    False: ":cross_mark:"
}


def needs_which(f):
    def which(self, params):
        if self.which is None:
            raise RuntimeError("You must set the object by calling pulls() or issues()")
        else:
            return f(self, params)
    return which

class GithubUrl:
    def __init__(self, project):
        self.project = project
        self.baseurl = f"https://github.com/{project}"
        self.pullsurl = f"{self.baseurl}/pulls"
        self.issuesurl = f"{self.baseurl}/issues"
        self.which = None
        self.query_params = []
    def pulls(self):
        self.which = "pulls"
        self.query_params = []
        return self
    def issues(self):
        self.which = "issues"
        self.query_params = []
        return self
    @needs_which
    def true(self, param):
        self.query_params.append(f"is:{param}")
        return self
    def milestone(self, param):
        self.query_params.append(f'milestone:"{param}"')
        return self
    def label(self, param):
        self.query_params.append(f"label:{param}")
        return self
    @property
    def object_url(self):
        if self.which is None:
            raise ValueError
        return {
            'pulls': self.pullsurl,
            'issues': self.issuesurl
        }[self.which]
    @property
    def url(self):
        query_string = ' '.join(self.query_params)
        query_string_quoted = quote_plus(query_string)
        # returns:
        #   [0]             [1]                  [2]                                 [3]        [4]                       [5]
        #   scheme='https', netloc='github.com', path='/projectcalico/calico/pulls', params='', query='q=this+is+a+test', fragment=''
        parsed_url = urlparse(self.object_url)
        new_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            f"q={query_string_quoted}",
            parsed_url.fragment
        ))
        return new_url

def get_cache_data(filename):
    """Get data out of a cached file"""
    cache_file = CACHE_DIR.joinpath(filename)
    # If the file is a symlink, delete it (we don't trust symlinks)
    if cache_file.is_symlink():
        cache_file.unlink()
    # If the file is not a file, no cache to load
    if not cache_file.is_file():
        return None
    # Get the creation time of the file and the current time;
    # if the file is more than 30m old, delete it. Otherwise,
    # json-parse it.
    ctime = cache_file.stat().st_ctime
    now = time.time()
    if now - ctime < 1800:
        return json.load(cache_file.open())
    else:
        cache_file.unlink()
        return None

def set_cache_data(filename, contents):
    cache_file = CACHE_DIR.joinpath(filename)
    # We don't trust symlinks. Remove them.
    if cache_file.is_symlink():
        cache_file.unlink()
    cache_file.write_text(json.dumps(contents))

@cache
def get_version_from_git_index():
    git_command = ["git", "show", f":{VERSIONS_FILE}"]
    git_process = subprocess.Popen(git_command, stdout=subprocess.PIPE)
    git_process.wait()
    if git_process.returncode != 0:
        console.log(f"Got error {git_process.returncode} from git process ({git_command})")
        raise ChildProcessError
    data = yaml.safe_load(git_process.stdout)
    version = data[0]['title']
    # console.log(f"Got current version '{version}' from file git index")
    return version

def get_version_from_versions():
    with open(VERSIONS_FILE) as versions_yaml:
        data = yaml.safe_load(versions_yaml)
    version = data[0]['title']
    console.log(f"Got current version '{version}' from file {VERSIONS_FILE}")
    return version

@cache
def bump_patch_version(version):
    major, minor, patch = map(int, version.strip("v").split("."))
    patch +=1
    new_version = f"v{major}.{minor}.{patch}"
    console.log(f"Detected version '{version}' from git index, bumping to '{new_version}' for next release")
    return new_version

@cache
def get_next_patch_version():
    return bump_patch_version(get_version_from_git_index())

@cache
def calculate_foreground_color(hex):
    parsed_color = rich.color.parse_rgb_hex(hex.strip("#"))
    calculation = 0.2126 * (parsed_color.red/255) + 0.7152 * (parsed_color.green/255) + 0.0722 * (parsed_color.blue/255)
    if calculation > 0.5:
        return "black"
    else:
        return "white"

def get_milestone_link_url(milestone):
    return available_milestones[milestone]['url']

def check_release_notes(body_text):
    pat = re.compile("(?<=```release-note\n).+?(?=\n```)", re.MULTILINE | re.DOTALL)
    release_notes_text = pat.findall(body_text.replace("\r\n","\n"))
    if not release_notes_text:
        return False
    return len(release_notes_text[0]) > 10

def get_prs_for_milestone_version(version):
    console.log(f"Getting PR list for Calico version '{version}'")
    cmd = ["gh", "pr", "list", "--search", f'milestone:"Calico {version}"', "--json", ",".join(GH_JSON_FIELDS)]
    gh_process = subprocess.check_output(cmd)
    prs = json.loads(gh_process)
    return prs

def get_closed_prs_for_milestone_label(version, label):
    console.log(f"Getting closed PR list for Calico version '{version}' with label '{label}'")
    cmd = ["gh", "pr", "list", "--label", "docs-pr-required", "--state", "closed", "--search", f'milestone:"Calico {version}"', "--json", ",".join(GH_JSON_FIELDS)]
    gh_process = subprocess.check_output(cmd)
    prs = json.loads(gh_process)
    return prs

def get_closed_prs_with_label_no_milestone(label):
    console.log(f"Getting closed PRs with label '{label}' but no milestone")
    cmd = ["gh", "pr", "list", "--label", "docs-pr-required", "--state", "closed", "--search", 'no:milestone', "--json", ",".join(GH_JSON_FIELDS)]
    gh_process = subprocess.check_output(cmd)
    prs = json.loads(gh_process)
    return prs

def get_prs_for_label(label, body=False):
    console.log(f"Getting PR list for label '{label}'")

    cmd = ["gh", "pr", "list", "--label", label, "--json", ",".join(GH_JSON_FIELDS)]
    gh_process = subprocess.check_output(cmd)
    prs = json.loads(gh_process)
    return prs

def get_milestones():
    data = get_cache_data("github_milestones")
    if data:
        return data
    else:
        try:
            cmd = ["gh", "milestone", "list", "--json", "number,title,url"]
            gh_process = subprocess.check_output(cmd)
            milestones = json.loads(gh_process)
            milestones_map = {}
            for milestone in milestones:
                title = milestone['title'].replace("Calico ","")
                milestones_map[title] = milestone
            set_cache_data("github_milestones", milestones_map)
            return milestones_map
        except Exception as ex:
            console.log(f"Could not get milestones list from `gh` command: {ex}")
            return {}

def render_pr_table(prs_list, title=None, label_links_with_milestone=True):
    table = Table(title=title, padding=(1,1), collapse_padding=True)
    table.add_column("PR", width=5)
    table.add_column("Title")
    table.add_column("Release Notes", width=7, justify="center")
    table.add_column("Labels")

    for pr in prs:
        title = Text(pr['title'])
        title.highlight_words([pr['title']], style=Style(link=pr['url']))
        labels = Text(" ".join([label['name'] for label in pr['labels']]))
        for label in pr['labels']:
            name = label['name']
            bgcolor = label['color']
            color = calculate_foreground_color(bgcolor)
            if label_links_with_milestone:
                link = github_url.pulls().true("open").true("pr").label(name).milestone(f"Calico {milestone}").url
            else:
                link = github_url.pulls().true("open").true("pr").label(name).url
            labels.highlight_words([name], style=Style(color=color, bgcolor=f"#{bgcolor}", bold=True, link=link))
        table.add_row(
            f"#{pr['number']}",
            title,
            STATUS[check_release_notes(pr['body'])],
            labels
        )
    return table


# globals
console = Console()
github_url = GithubUrl("projectcalico/calico")


available_milestones = get_milestones()

parser = argparse.ArgumentParser()
parser.add_argument("--milestone", action='store', help="Which milestone to get PRs for. Default: autodetect")
# argcomplete.autocomplete(parser)
# pyzshcomplete.autocomplete(parser)
args = parser.parse_args()

milestone = args.milestone
new_version = get_next_patch_version()

if milestone is None:
    milestone = new_version

if milestone != new_version:
    console.log(f"Note: overriding detected version '{new_version}' with manually specified version '{milestone}'", style='yellow')


outputs = []

prs = get_prs_for_milestone_version(milestone)
table = render_pr_table(prs, title=f"Open PRs for {milestone}")
outputs.append(table)

prs = get_prs_for_label('cherry-pick-candidate')
table = render_pr_table(prs, title=f"Currently open cherry-pick PRs")
outputs.append(table)

prs = get_closed_prs_for_milestone_label(milestone, 'docs-pr-required')
table = render_pr_table(prs, title=f"Closed {milestone} PRs with docs PRs required")
outputs.append(table)

prs = get_closed_prs_with_label_no_milestone("release-note-required")
table = render_pr_table(prs, title=f"Closed PRs which require release notes but have no milestone", label_links_with_milestone=False)
outputs.append(table)

console.line()
console.rule(Text(f"Please check the following before continuing with a release", style="bold red"), align="left"   )
console.line()

# with console.pager(styles=True, links=True)
for table in outputs:
    if table.row_count > 0:
        console.print(table)
    else:
        console.print(f"(The table '{table.title}' was empty, and so it was skipped)")
    console.line()
