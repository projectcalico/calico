#!/usr/bin/env python
"""validate.py

Validates the current code tree:
-  Markdown URLs are accessible
-  Analytics URLs have the correct file name in MD files

Usage:
  validate.py

Options:
  -h --help     Show this screen.

"""
import re

from docopt import docopt

import utils

if __name__ == "__main__":
    arguments = docopt(__doc__)
    utils.validate_markdown_uris()
