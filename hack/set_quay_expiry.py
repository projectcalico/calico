#!/usr/bin/env python3

# NOTE: This script makes optional use of some modules for 'nicer'
#       output, and I highly recommend installing them if you're
#       using this script manually, or testing it; however, the
#       entire script can run using only modules in the Python 3
#       standard library, so that no docker container, requirements.txt,
#       or virtualenv is required.
#
#       We also support inline dependencies a la PEP 723, and recommend
#       using `uv` for this project (and every other project):
#
#           https://docs.astral.sh/uv/

"""
This script takes an expiry time and an image name on
quay.io and uses the API to set the expiry on that image.
"""

# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "rich",
#     "rich-argparse",
# ]
# ///

import os
import sys
import json
import logging
import argparse
import datetime

from functools import cache
from enum import IntEnum, auto

from typing import Optional

import urllib.error
import urllib.request

try:
    # Use nicer printing if we have it
    from rich import print
except ImportError:
    pass

try:
    # Use nicer help formatting if we have it
    from rich_argparse.contrib import ParagraphRichHelpFormatter as HelpFormatter
except ImportError:
    from argparse import HelpFormatter

MONO_FORMAT = "[%(levelname)-8s] %(asctime)s [%(funcName)s:%(lineno)d] %(message)s"

HELP_DESCRIPTION_TEXT = """
A simple script to add an expiration date to an image tag on quay.io, or to remove the expiration date from one, using the quay.io API.

When removing an expiry it's also possible to un-expire an image thanks to some peculiarities of the quay.io tag API, since the API returns the list of previous tag data for a specific tag even if it's expired.
"""

HELP_EPILOGUE_TEXT = """
For prettier logging output, `pip install rich`. For prettier --help output, `pip install rich_argparse`.
"""


try:
    # Use nicer log formatting if we have it
    from rich.logging import RichHandler

    handler = RichHandler(rich_tracebacks=True)
except ImportError:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(MONO_FORMAT))

handler.setLevel(logging.INFO)
logging.basicConfig(
    datefmt=r"%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG,
    format="%(message)s",
    handlers=[handler],
)

log = logging.getLogger(__name__)

GET_TAG_INFO_URL = (
    "https://quay.io/api/v1/repository/{image_name}/tag?specificTag={image_tag}"
)
PUT_TAG_INFO_URL = "https://quay.io/api/v1/repository/{image_name}/tag/{image_tag}"
DATETIME_FORMAT = "%a, %d %b %Y %X %z"


class ReturnCodes(IntEnum):
    """
    common return codes used in this module
    """

    OK = 0
    NOAPITOKEN = auto()
    INVALIDIMAGENAME = auto()
    HTTPSETEXPIRYFORBIDDEN = auto()
    HTTPIMAGENOTFOUND = auto()


class Image:
    """
    The Image class represents a docker image on Quay.io, and
    includes functionality to interact with its API to get information
    and set expiry times.
    """

    def __init__(self, image_identifier):
        if image_identifier.count(":") > 1:
            log.critical(
                "Image name needs to be of the format quay.io/image/name:<tag>"
            )
            sys.exit(ReturnCodes.INVALIDIMAGENAME)
        image_uri, image_tag = image_identifier.split(":")
        self.image_identifier = image_identifier
        self.image_uri = image_uri
        self.image_name = image_uri.removeprefix("quay.io/")
        self.image_tag = image_tag

        self.data = None

        self.fetch_tag_info()
        self.validate_dates()

    @property
    def last_modified_datetime(self):
        return datetime.datetime.strptime(
            self.latest_tag["last_modified"], DATETIME_FORMAT
        )

    @property
    def has_expiry(self):
        return self.expiry_datetime is not None

    @property
    def tag_data(self):
        if self.data is None:
            self.fetch_tag_info()
        return self.data

    @property
    def latest_tag(self):
        return self.data["tags"][0]

    @property
    def expiry_datetime(self):
        try:
            return datetime.datetime.strptime(
                self.latest_tag["expiration"], DATETIME_FORMAT
            )
        except KeyError:
            return None

    @property
    def is_expired(self):
        if self.expiry_datetime:
            return self.expiry_datetime < datetime.datetime.now(tz=datetime.UTC)
        else:
            return False

    def fetch_tag_info(self):
        log.debug(
            "Fetching info for image tag '%s' from quay.io API", self.image_identifier
        )
        req = urllib.request.Request(
            url=GET_TAG_INFO_URL.format(
                image_name=self.image_name, image_tag=self.image_tag
            ),
            headers=auth_header(),
            method="GET",
        )
        log.debug("Fetching tag data for tag '%s'", self.image_identifier)
        with urllib.request.urlopen(req) as response:
            data = json.load(response)
            self.data = data

    def validate_dates(self):
        log.debug("Last modified date: '%s'", self.last_modified_datetime)
        log.debug("Expiry date: '%s'", self.last_modified_datetime)
        if self.expiry_datetime:
            if self.is_expired:
                log.error(
                    (
                        "Image tag '%s' exists in the API, but is already expired! "
                        "Further API calls against this tag are likely to fail."
                    ),
                    self.image_identifier,
                )
            else:
                log.debug(
                    "Image tag '%s' has configured expiration '%s'",
                    self.image_identifier,
                    self.expiry_datetime,
                )
        else:
            log.debug(
                "Image tag '%s' has no configured expiration", self.image_identifier
            )

    def __put_tag_info(self, info):
        req = urllib.request.Request(
            url=PUT_TAG_INFO_URL.format(
                image_name=self.image_name, image_tag=self.image_tag
            ),
            headers=auth_header(),
            data=json.dumps(info).encode(),
            method="PUT",
        )
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as response:
                if response.code == 201:
                    log.debug(
                        "Successfully updated tag '%s' with data %s",
                        self.image_identifier,
                        info,
                    )
                else:
                    log.warning("Got unexpected HTTP response %s", response.status)
        except urllib.error.HTTPError as http_exc:
            log.error(
                "Caught HTTP error setting tag data for '%s': %s",
                self.image_identifier,
                http_exc,
            )

    def remove_expiry(self, restore=False):
        """
        Removes the expiry date from an image. Due to a quirk of
        the API, we can also use this functionality to restore an
        image that has already expired.

        Args:
            restore (bool, optional): Whether or not to restore the image if it's expired. Defaults to False.
        """

        # If the current tag doesn't have an expiry, that means there's nothing
        # to remove and we don't need to restore it even if we were asked to.
        if self.has_expiry is False:
            log.info(
                "Image tag '%s' has no expiry set, skipping", self.image_identifier
            )
            return

        # Setting only the manifest digest creates a "new" entry in the tag's history,
        # which, by default, has no expiry set. This not only means we can use this
        # to remove expiry, but we can also use it to restore an already-expired image
        # to its previous, un-expired version.
        data = {"manifest_digest": self.latest_tag["manifest_digest"]}

        # Image is expired and we're not trying to restore it - do nothing.
        if self.is_expired and restore is False:
            log.error(
                "Image tag '%s' has expired, skipping (use --restore to restore this image)",
                self.image_identifier,
            )
            return

        # Here we set the tag's manifest_digest but nothing else
        self.__put_tag_info(data)

        # Do some logic to determine what our log should be like
        if self.is_expired:
            log.info(
                "Restored expired image tag '%s' to manifest '%s' from '%s'",
                self.image_identifier,
                self.latest_tag["manifest_digest"],
                self.last_modified_datetime,
            )
        elif self.has_expiry:
            log.info(
                "Removed expiry '%s' from image tag '%s'",
                self.expiry_datetime,
                self.image_identifier,
            )

    def set_expiry(self, days: int, relative=False, override=False):
        if self.has_expiry:
            if override is False:
                log.warning(
                    "Image tag '%s' already has expiry set, skipping",
                    self.image_identifier,
                )
                return
            log.warning(
                "Image tag '%s' already has expiry set, but --force-override was set, proceeding anyway",
                self.image_identifier,
            )

        if relative:
            expiry_datetime = make_expiry_datetime(days, self.last_modified_datetime)
        else:
            expiry_datetime = make_expiry_datetime(days)

        data = {"expiration": expiry_datetime.timestamp()}
        self.__put_tag_info(data)
        log.info(
            "Set expiry information for image tag '%s' to '%s'",
            self.image_identifier,
            expiry_datetime,
        )


@cache
def auth_header():
    return {"Authorization": f"Bearer {get_quay_token()}"}


def get_quay_token():
    try:
        token = os.environ["QUAY_API_TOKEN"]
        if not token:
            raise RuntimeError("QUAY_API_TOKEN is unset or empty")
    except (KeyError, RuntimeError):
        log.critical(
            "Please set QUAY_API_TOKEN in the environment before running this script"
        )
        sys.exit(ReturnCodes.NOAPITOKEN)
    return token


def make_expiry_datetime(days: int, starting_date: Optional[datetime.datetime] = None):
    # Create a timedelta from the number of days passed in
    time_delta = datetime.timedelta(days=days)

    # Get the current timestamp. We'll use this as a default starting_date, but
    # also use it to validate that our expiration date is in the future.
    now = datetime.datetime.now(tz=datetime.UTC)

    if starting_date is None:
        starting_date = now

    # Strip away the time from the datetime so that we're operating at midnight
    # UTC (which makes things predictable to some extent)
    expiry_datetime = (
        starting_date.replace(hour=0, minute=0, second=0, microsecond=0) + time_delta
    )

    # The API won't let us set dates in the past, so we need to set the expiry
    # to be 'now' (or, to account for time skew, ten seconds from now)
    if now > expiry_datetime:
        log.warning(
            "Target expiry '%s' is in the past! Setting expiry to ten seconds from now instead.",
            expiry_datetime,
        )
        expiry_datetime = now + datetime.timedelta(minutes=10)
    return expiry_datetime


def main():
    parser = argparse.ArgumentParser(
        formatter_class=HelpFormatter,
        description=HELP_DESCRIPTION_TEXT,
        epilog=HELP_EPILOGUE_TEXT,
    )
    parser.add_argument(
        "--debug", action="store_true", default=False, help="Enable debug logging"
    )

    subparsers = parser.add_subparsers(dest="action")
    parser_add_expiry = subparsers.add_parser(
        "add", help="Add expiry to an image", formatter_class=parser.formatter_class
    )

    parser_add_expiry.add_argument(
        "image_names", nargs="+", help="The image to add expiry to"
    )
    parser_add_expiry.add_argument(
        "--expiry-days",
        type=int,
        default=90,
        help="The time (in days from today UTC) to expire the images (default: 90d)",
    )
    parser_add_expiry.add_argument(
        "--relative-date",
        action="store_true",
        default=False,
        help="Set the expiry to days from last image modification instead",
    )
    parser_add_expiry.add_argument(
        "--force-override",
        action="store_true",
        default=False,
        help="Set expiry even if the image has an expiry set already",
    )

    parser_remove_expiry = subparsers.add_parser(
        "remove",
        help="Remove expiry to an image (and optionally un-expire the image)",
        formatter_class=parser.formatter_class,
    )
    parser_remove_expiry.add_argument(
        "image_names", nargs="+", help="The image to remove expiry from"
    )
    parser_remove_expiry.add_argument(
        "--restore",
        action="store_true",
        default=False,
        help="If the image tag is already expired, restore it to the last known tag",
    )

    args = parser.parse_args()

    if args.debug:
        handler.setLevel(logging.DEBUG)
        log.debug("Executing with args %s", args)

    for image_spec in args.image_names:
        image_spec = image_spec.removeprefix("https://")
        if not image_spec.startswith("quay.io"):
            log.error(
                "Image '%s' does not appear to be a quay.io image, skipping", image_spec
            )
            continue
        image_obj = Image(image_spec)
        if args.action == "add":
            image_obj.set_expiry(args.expiry_days, relative=args.relative_date)
        elif args.action == "remove":
            image_obj.remove_expiry(restore=args.restore)


if __name__ == "__main__":
    main()
