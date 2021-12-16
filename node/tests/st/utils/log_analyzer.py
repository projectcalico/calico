# Copyright (c) 2015-2017 Tigera, Inc. All rights reserved.
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
# limitations under the License.ra, Inc. All rights reserved.

from collections import deque
from datetime import datetime
import logging
import re

from tests.st.utils.exceptions import CommandExecError

_log = logging.getLogger(__name__)

FELIX_LOG_FORMAT = (
    "(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).\d{0,3} "
    "\\[(?P<loglevel>\w+)\\]"
    "\\[(?P<pid>\d+)(/\d+)?\\] "
    "(?P<logtext>.*)"
)

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# The number of additional logs to trace out before the first error log, and
# the maximum number of errors to report.
NUM_CONTEXT_LOGS = 300
MAX_NUM_ERRORS = 100

# This is the list of logs we should ignore for all tests.
LOGS_IGNORE_ALL_TESTS = [
    "Failed to connect to syslog error=Unix syslog delivery error level=",
    "Exiting for config change",
    "Exiting. reason=\"config changed\"",
    "Exiting immediately reason=\"config changed\"",
]


class Log(object):
    """
    Class encapsulating information about a log extracted from a log file.
    """

    def __init__(self, timestamp, level, pid, msg):
        """
        :param timestamp: The log datetime.
        :param level:  The log level
        :param pid: The PID of the process that created the log
        :param msg: The log text.
        """
        self.timestamp = timestamp
        self.level = level
        self.pid = pid
        self.msg = msg

    def append(self, logtext):
        """
        Append the text to the end of the current text with a newline
        separator.

        :param logtext:  The text to append to the log.
        """
        self.msg += "\n" + logtext

    def detailed(self):
        return "=== LOG %s %s [pid %s] ===\n%s" % (self.timestamp, self.level,
                                                   self.pid, self.msg)

    def __str__(self):
        return "%s %s %s %s" % (self.timestamp, self.level,
                                self.pid, self.msg)

    def __repr__(self):
        return self.__str__()

class LogAnalyzer(object):
    """
    LogAnalyzer class to check any new logs generated since the analyzer
    was instantiated.

    This is a fairly simpler parser - it doesn't check flipped files.
    """

    def __init__(self, host, filename, log_format, timestamp_format,
                 continuation_level=None):
        """
        :param host: the host running calico-node
        :param filename: The log filename on the server
        :param log_format: The format of the logs
        :param timestamp_format: The date/time format in the logs.
        :param continuation_level: An optional log level that indicates the
        log is a continuation of the previous log (i.e. the text can be
        extracted and appended to the previous log).

        The log format should be a regex string containing the following
        named matches:
          - timestamp  (the extracted timestamp)
          - loglevel   (the log level)
          - pid        (the process ID)
          - logtext    (the actual log message)

        The timestamp format is the format of the extracted timestamp in
         notation used by datetime.datetime.strptime().
        """
        self.host = host
        self.filename = filename
        self.log_regex = re.compile(log_format)
        self.timestamp_format = timestamp_format
        self.init_log_time = None
        self.init_log_lines = None
        self.continuation_level = continuation_level

        # Store the time of the last log in the file.
        self.reset()

    def reset(self):
        """
        Initialise the time of the first log in the log file and the number
        of lines in the log file.

        This information is used to work out where to start from when looking
        at new logs.
        """
        _log.debug("Resetting log analyzer on %s", self.host.name)
        # Grab the time of the first log.
        self.init_log_time = self._get_first_log_time()
        _log.debug("First log has timestamp: %s", self.init_log_time)

        self.init_log_lines = self._get_logs_num_lines()
        _log.debug("Log file has %s lines", self.init_log_lines)

    def _get_first_log_time(self):
        """
        Extract the time of the first log in the file.  This is used to
        determine whether a file has flipped during a test.
        """
        cmd = "head -100 %s"
        for log in self._parse_logs(cmd, self.filename):
            return log.timestamp
        return None

    def _get_logs_num_lines(self):
        """
        Return the number of lines in the log file.

        :return: The number of lines in the log file or None if the file does
        not exist or cannot be read.
        """
        cmd = "wc -l %s" % self.filename
        lines = None
        stdout = None
        try:
            stdout = self.host.execute(cmd)
        except CommandExecError:
            _log.debug("Error running command: %s", cmd)

        _log.debug("Extract number of lines in file: %s",
                   self.filename)
        try:
                lines = int(stdout.split(" ")[0])
        except ValueError:
            _log.error("Unable to parse output: %s", stdout)
        except AttributeError:
            _log.error("None output?: %s", stdout)

        return lines

    def get_latest_logs(self, logfilter=None):
        """
        Get the latest (filtered) logs from the server.

        :param logfilter: An optional filter that determines whether a log
        should be stored.  This is a function that takes the log as the only
        argument and returns True if the log should be filtered _out_ of the
        list.
        :return: A list of Log objects.
        """
        return [log for log in self._parse_latest_logs() if not logfilter or not logfilter(log)]

    def _parse_latest_logs(self):
        """
        Parse the latest logs from the server, returning a generator that
        iterates through the logs.

        :return: A Log generator.
        """
        # Use the entire log file if the file has flipped (i.e. the first log
        # time is not the same, otherwise tail all but the first logs.
        first_log_time = self._get_first_log_time()
        _log.debug("First log has timestamp: %s", first_log_time)

        if first_log_time != self.init_log_time or \
                not self.init_log_lines:
            _log.debug("Log file is new")
            cmd = "cat %s"
        else:
            _log.debug("Check appended logs")
            cmd = "tail -n +%s %s" % (self.init_log_lines + 1, self.filename)
        return self._parse_logs(cmd, self.filename)

    def _parse_logs(self, cmd, filename):
        """
        Parse the logs from the output of the supplied command, returning a
        generator that iterates through the logs.

        :param cmd: The command to run to output the logs.

        :return: A Log generator.
        """
        last_log = None
        try:
            for line in self.host.execute_readline(cmd, filename):
                log = self._process_log_line(line, last_log)

                # Logs may be continued, in which case we only return the log
                # when the parsing indicates a new log.
                if last_log and last_log != log:
                    yield last_log
                last_log = log
        except Exception:
            _log.exception(
                "Hit exception getting logs from %s - skip logs",
                self.host.name)

        # Yield the final log.
        if last_log:
            yield last_log

    def _process_log_line(self, line, last_log):
        """
        Build up a list of logs from the supplied log line.

        If a line in the logs_text does not match the format of the log string
        it is assumed it is a continuation of the previous log.  Similarly,
        a log with level "TRACE" is also treated as a continuation.

        :param line: The log line to process.  This may either add a new log
        or may be a continuation of a previous log, or may be filtered out.
        :param last_log: The previous log that was processed by this command.
        This may be None for the first line in the log file.
        :return: The log that was added or updated by this method.  This may
        return None if no log was parsed.  If this line was appended to the
        previous log, it will return last_log.
        """
        # Put the full text of the log into logtext, but strip off ending whitespace because
        # we'll add \n back to it when we append to it
        logtext = line.rstrip()
        # Strip superfluous whitespace
        line = line.strip()

        # Check the line for a log match.
        log_match = self.log_regex.match(line)

        # If the line does not match the regex it will be a continuation
        # of the previous log.  If there was no previous log then we must
        # have starting parsing in the middle of a multi-line log.
        if not log_match:
            if last_log:
                last_log.append(line)
            return last_log

        # Extract the parameters from the match object.
        groupdict = log_match.groupdict()
        loglevel = groupdict["loglevel"]
        timestamp = datetime.strptime(groupdict["timestamp"],
                                      self.timestamp_format)
        pid = groupdict["pid"]

        # Neutron logs use a log level of TRACE to continue a multi-line
        # log.  If there was no previous log then we must have starting parsing
        # in the middle of a multi-line log.
        if self.continuation_level == loglevel:
            if last_log:
                last_log.append(logtext)
            return last_log

        # Create and return the new log.  We don't add it until we start the
        # next log as we need to get the entire log before we can run it
        # through the filter.
        log = Log(timestamp, loglevel, pid, logtext)
        return log

    def check_logs_for_exceptions(self, err_words=None, ignore_list=[]):
        """
        Check the logs for any error level logs and raises an exception if
        any are found.
        """
        _log.info("Checking logs for exceptions")
        _log.debug("Analyzing logs from %s on %s",
                   self.filename, self.host.name)

        # Store each error with a set of preceding context logs.
        errors = []
        logs = deque(maxlen=NUM_CONTEXT_LOGS)

        # Iterate through the logs finding all error logs and keeping track
        # of unfiltered context logs.
        for log in self._parse_latest_logs():
            logs.append(log)
            if self._is_error_log(log, err_words, ignore_list):
                _log.info("Error found in node logs: %s", log)
                errors.append(logs)
                logs = deque(maxlen=NUM_CONTEXT_LOGS)

            # Limit the number of errors we report.
            if len(errors) == MAX_NUM_ERRORS:
                break

        if errors:
            # Trace out the error logs (this is the last entry in each of the
            # error deques).
            _log.error("***** Start of errors in logs from %s on %s *****"
                       "\n\n%s\n\n",
                       self.filename, self.host.name,
                       "\n\n".join(map(lambda logs: logs[-1].detailed(), errors)))
            _log.error("****** End of errors in logs from %s on %s ******",
                       self.filename, self.host.name)

            if len(errors) == MAX_NUM_ERRORS:
                _log.error("Limited to %d errors reported" % MAX_NUM_ERRORS)

            # Trace out the unfiltered logs - each error stored above contains a set
            # proceeding context logs followed by the error log.  Join them all
            # together to trace out, delimiting groups of logs with a "..." to
            # indicate that some logs in between may be missing (because we only
            # trace out a max number of proceeding logs).
            _log.error("***** Start of context logs from %s on %s *****"
                       "\n\n%s\n\n",
                       self.filename, self.host.name,
                       "\n...\n".join(map(lambda logs: "\n".join(map(str, logs)), errors)))
            _log.error("****** End of context logs from %s on %s ******",
                       self.filename, self.host.name)

        assert not errors, "Test suite failed due to errors raised in logs"

    def _is_error_log(self, log, err_words=None, ignore_list=[]):
        """
        Return whether the log is an error log or not.

        :return: True if the log is an error log.
        :param log: Log need to be checked.
        :param err_words: The per test error words.
        :param ignore_list: The per test ignore list.
        Note that we are also skipping known failures as defined by the
        LOGS_IGNORE_ALL_TESTS.
        """

        ignores = LOGS_IGNORE_ALL_TESTS + ignore_list

        if err_words is None:
            err_words = {"ERROR", "PANIC", "FATAL", "CRITICAL"}
        is_error = log.level in err_words
        if is_error:
            is_error = not any(log.msg.find(txt) > 0 for txt in ignores)

        return is_error
