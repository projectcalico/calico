# Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import functools
import logging
import subprocess
import threading
import time
import unittest
from unittest.case import SkipTest

_log = logging.getLogger(__name__)

first_log_time = None


def log_banner(msg, *args, **kwargs):
    # Calculate elapsed hours, minutes and seconds since first log.
    global first_log_time
    time_now = time.time()
    if not first_log_time:
        first_log_time = time_now
    time_now -= first_log_time
    elapsed_hms = "%02d:%02d:%02d " % (
        time_now / 3600,
        (time_now % 3600) / 60,
        time_now % 60,
    )

    level = kwargs.pop("level", logging.INFO)
    msg = elapsed_hms + str(msg) % args
    banner = "+" + ("-" * (len(msg) + 2)) + "+"
    _log.log(level, "\n" + banner + "\n| " + msg + " |\n" + banner)


def decorate_test(test_method):
    """
    Wraps each test_method with calls to the test hooks.
    """

    @functools.wraps(test_method)
    def call_test_hooks(self):
        """
        Calls the test_method. If the test fails or succeeds, runs the
        on_failure hook or the on_success hook defined in the test class.
        """
        try:
            log_banner("TEST STARTING: %s", self.id())
            test_method(self)
        except KeyboardInterrupt:
            log_banner("TEST INTERRUPTED: %s", self.id(), level=logging.WARNING)
            raise
        except SkipTest:
            log_banner("TEST SKIPPED: %s", self.id())
            raise
        except Exception as e:
            _log.exception("Test %s failed with exception", self.id())
            log_banner("TEST FAILED: %s", self.id(), level=logging.ERROR)
            self.on_failure(test_id=self.id())
            raise e
        else:
            log_banner("TEST SUCCEEDED: %s", self.id())
            self.on_success()
        finally:
            log_banner("TEST CLEAN-UP DONE: %s", self.id())

    return call_test_hooks


def decorate_set_up_class(set_up_class, cls_name):
    """
    Wraps each setUpClass method with calls to the test hooks.
    """

    @functools.wraps(set_up_class)
    def wrapped_set_up_class(cls):
        if not hasattr(cls, "set_up_class_call_in_progress"):
            try:
                # Stash a flag on the class to indicate that the setUpClass()
                # is in progress.  This allows us to avoid logging at every
                # superclass.
                cls.set_up_class_call_in_progress = True
                log_banner("SETUP FOR CLASS STARTING: %s", cls.__name__)
                set_up_class(cls)
            except KeyboardInterrupt:
                log_banner(
                    "SETUP FOR CLASS INTERRUPTED: %s",
                    cls.__name__,
                    level=logging.WARNING,
                )
                raise
            except SkipTest:
                log_banner("SETUP FOR CLASS SKIPPED: %s", cls.__name__)
                raise
            except Exception:
                _log.exception("SETUP FOR CLASS %s failed with exception", cls.__name__)
                log_banner(
                    "SETUP FOR CLASS FAILED: %s", cls.__name__, level=logging.ERROR
                )
                cls.on_failure(test_id=cls.__name__ + ".setUpClass")
                raise
            else:
                log_banner("SETUP FOR CLASS SUCCEEDED: %s", cls.__name__)
            finally:
                del cls.set_up_class_call_in_progress
        else:
            _log.info("Running %s.setUpClass", cls_name)
            set_up_class(cls)
            _log.info("Finished %s.setUpClass", cls_name)

    return wrapped_set_up_class


def decorate_set_up(set_up, cls_name):
    """
    Wraps each setUp method with calls to the test hooks.
    """

    @functools.wraps(set_up)
    def wrapped_setup(self):
        if not hasattr(self, "set_up_call_in_progress"):
            try:
                # Stash a flag on the object to indicate that the setUp() is in
                # progress.  This allows us to avoid logging at every
                # superclass.  Note: this is safe because the test harness uses
                # a fresh instance of the class for running each test.
                self.set_up_call_in_progress = True
                log_banner("SETUP FOR TEST STARTING: %s", self.id())
                set_up(self)
            except KeyboardInterrupt:
                log_banner(
                    "SETUP FOR TEST INTERRUPTED: %s", self.id(), level=logging.WARNING
                )
                raise
            except SkipTest:
                log_banner("SETUP FOR TEST SKIPPED: %s", self.id())
                raise
            except Exception:
                _log.exception("setUp() failed for test %s", self.id())
                log_banner("SETUP FOR TEST FAILED: %s", self.id(), level=logging.ERROR)
                self.on_failure(test_id=self.id() + "-setUp")
                raise
            else:
                log_banner("SETUP FOR TEST SUCCEEDED: %s", self.id())
            finally:
                del self.set_up_call_in_progress
        else:
            _log.info("Running %s.setUp", cls_name)
            set_up(self)
            _log.info("Finished %s.setUp", cls_name)

    return wrapped_setup


class ResultsWithHooks(type):
    """
    Metaclass that decorates all test_* class methods with decorate_with_hooks.
    """

    def __new__(cls, name, bases, dct):
        for attr, value in dct.items():
            if attr.startswith("test_"):
                dct[attr] = decorate_test(value)
            elif attr == "setUpClass":
                # Need to unwrap the classmethod as a bare function so we can
                # insert our hook.
                raw_func = decorate_set_up_class(value.__func__, name)
                # Then re-wrap as we write it back.
                dct[attr] = classmethod(raw_func)
            elif attr == "setUp":
                dct[attr] = decorate_set_up(value, name)

        return super(ResultsWithHooks, cls).__new__(cls, name, bases, dct)


class TestWithHooks(unittest.TestCase, metaclass=ResultsWithHooks):
    """
    Base unittest class implementing success and failure hooks.
    """

    @classmethod
    def on_success(cls):
        """
        The test completed without raising an exception.
        """
        _log.info("Test succeeded")

    @classmethod
    def on_failure(cls, test_id=None):
        """
        The test raised an exception.
        """
        _log.info("Test failed.")


def retry_until_success(
    function,
    retries=10,
    wait_time=1,
    ex_class=None,
    log_exception=True,
    context_string="",
    function_args=None,
    function_kwargs=None,
):
    """
    Retries function until no exception is thrown. If exception continues,
    it is reraised.

    :param function: the function to be repeatedly called
    :param retries: the maximum number of times to retry the function.  A value
    of 0 will run the function once with no retries.
    :param wait_time: the time to wait between retries (in s)
    :param ex_class: The class of expected exceptions.
    :param log_exception: By default this function logs the exception if the
    function is still failing after max retries.   This log can sometimes be
    superfluous -- if e.g. the calling code is going to make a better log --
    and can be suppressed by setting this parameter to False.
    :param context_string: A string used to flag the context of a specific call
    in logs.
    :param function_args: A list of arguments to pass to function
    :param function_kwargs: A dictionary of keyword arguments to pass to
                            function
    :returns: the value returned by function
    """
    if function_args is None:
        function_args = []
    if function_kwargs is None:
        function_kwargs = {}
    with time_block_execution(function_name(function), context_string):
        for retry in range(int(retries) + 1):
            try:
                result = function(*function_args, **function_kwargs)
            except Exception as e:
                if ex_class and e.__class__ is not ex_class:
                    _log.exception(
                        "Hit unexpected exception in function - not retrying."
                    )
                    raise
                if retry < retries:
                    _log.debug("Hit exception in function - retrying: %s", e)
                    time.sleep(wait_time)
                else:
                    if log_exception:
                        _log.exception(
                            "Function %s did not succeed before timeout.", function
                        )
                    raise
            else:
                # Successfully ran the function
                return result


@contextlib.contextmanager
def time_block_execution(block_name, context_string, level=logging.INFO):
    """
    This context manager times the execution of a block of code and emits a log
    when that block is exited indicating how long the code took to execute.

    :param block_name: The name of the block being executed.
    :param context_string: A context string to add to the log.
    :param level: (optional) the logging level to use.
    """
    log_string = 'TIMING: block="%s",  duration="%f", context="%s"'
    start_time = time.time()
    try:
        # If the containing block throws an exception it'll get throw into this
        # function at the yield. We always want to log, so use a try/finally
        # block to ensure that happens.
        yield
    finally:
        end_time = time.time()
        _log.log(level, log_string, block_name, end_time - start_time, context_string)


def function_name(f):
    """
    A function that returns the name of the provided function as a string.
    This primarily exists to handle the fact that functools.partial is an
    imperfect wrapper.
    """
    if isinstance(f, functools.partial):
        f = f.func

    try:
        return f.__name__
    except Exception:
        return "<unknown function>"


class ThreadWithReturn(threading.Thread):
    """
    Thread that returns an object upon completion with .join()
    """

    def __init__(self, **kwargs):
        super(ThreadWithReturn, self).__init__(**kwargs)
        self._return = None
        self._exception = None
        self._target = kwargs.get("target")
        self._args = kwargs.get("args", [])
        self._kwargs = kwargs.get("kwargs", {})

    def run(self):
        try:
            if self._target is not None:
                self._return = self._target(*self._args, **self._kwargs)
        except BaseException as e:
            _log.exception("Thread %s failed with exception", self)
            self._exception = e
            raise

    def join(self, *args, **kwargs):
        super(ThreadWithReturn, self).join(*args, **kwargs)
        if self._exception is not None:
            raise self._exception
        return self._return


def run(command, logerr=True, allow_fail=False, allow_codes=[], env=None):
    out = ""
    _log.info("Run: %s", command)
    try:
        out = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT, env=env
        )
        _log.info("Output:\n%s", out)
    except subprocess.CalledProcessError as e:
        if logerr:
            _log.info("Failure output:\n%s", e.output)
        if not (allow_fail or e.returncode in allow_codes):
            raise
    if isinstance(out, bytes):
        return out.decode("utf-8")
    return out
