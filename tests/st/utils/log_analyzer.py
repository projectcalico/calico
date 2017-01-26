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

# This is the list of logs we should ignore for all tests.
LOGS_IGNORE_ALL_TESTS = [
    "Failed to connect to syslog error=Unix syslog delivery error level=",
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

    def __str__(self):
        return "=== LOG %s %s [pid %s] ===\n%s" % (self.timestamp, self.level,
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
        cmd = "head -100 %s" % self.filename
        logs = self._extract_logs(cmd)
        if not logs:
            return None
        return logs[0].timestamp

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
        Get the latest logs from the server.

        :param logfilter: An optional filter that determines whether a log
        should be stored.  This is a function that takes the log as the only
        argument and returns True if the log should be filtered _out_ of the
        list.
        :return: A list of Log objects.
        """
        # Use the entire log file if the file has flipped (i.e. the first log
        # time is not the same, otherwise tail all but the first logs.
        first_log_time = self._get_first_log_time()
        _log.debug("First log has timestamp: %s", first_log_time)

        if first_log_time != self.init_log_time or \
                not self.init_log_lines:
            _log.debug("Log file is new")
            cmd = "cat %s" % self.filename
        else:
            _log.debug("Check appended logs")
            cmd = "tail -n +%s %s" % (self.init_log_lines + 1,
                                      self.filename)

        return self._extract_logs(cmd, logfilter=logfilter)

    def _extract_logs(self, cmd, logfilter=None):
        """
        Return a list of logs parsed from the output of the supplied command.

        :param cmd: The command to run to output the logs.
        :param logfilter: The log filter.  See get_latest_logs for details.
        """
        logs = []
        last_log = None
        try:
            for line in self.host.execute_readline(cmd):
                last_log = self._process_log_line(logs, line, logfilter,
                                                  last_log)
        except Exception:
            _log.exception(
                "Hit exception getting logs from %s - skip logs",
                self.host.name)

        # The last log will not have been added yet, so add it now if it is
        # not filtered.
        if last_log and (not logfilter or not logfilter(last_log)):
            logs.append(last_log)

        return logs

    def _process_log_line(self, logs, line, logfilter, last_log):
        """
        Build up a list of logs from the supplied log line.

        If a line in the logs_text does not match the format of the log string
        it is assumed it is a continuation of the previous log.  Similarly,
        a log with level "TRACE" is also treated as a continuation.

        :param logs: List of logs to append any valid log to.
        :param line: The log line to process.  This may either add a new log
        or may be a continuation of a previous log, or may be filtered out.
        :param logfilter: The log filter.  See get_latest_logs for details.
        :param last_log: The previous log that was processed by this command.
        This may be None if the previous invocation did not add or update a
        log (e.g. because it was filtered out).
        :return: The log that was added or updated by this method.  This may
        return None if no log was added or updated.
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

        # We have started a new log.  We can now append the previous log iff
        # it is not filtered out.
        if last_log and (not logfilter or not logfilter(last_log)):
            logs.append(last_log)

        # Create and return the new log.  We don't add it until we start the
        # next log as we need to get the entire log before we can run it
        # through the filter.
        log = Log(timestamp, loglevel, pid, logtext)
        return log

    def check_logs_for_exceptions(self):
        """
        Check the logs for any error level logs and raises an exception if
        any are found.
        """
        _log.info("Checking logs for exceptions")
        hit_errors = False
        _log.debug("Analyzing logs from %s on %s",
                   self.filename, self.host.name)
        errors = self.get_latest_logs(logfilter=self.log_filter_in_errors)
        errors_to_print = 100
        if errors:
            hit_errors = True
            _log.error("***** Start of errors in logs from %s on %s *****"
                       "\n\n%s\n\n",
                       self.filename, self.host.name,
                       "\n\n".join(map(str, errors)))
            _log.error("****** End of errors in logs from %s on %s ******",
                       self.filename, self.host.name)
            errors_to_print -= 1
            if errors_to_print <= 0:
                _log.error("Limited to 100 errors reported")
        assert not hit_errors, "Test suite failed due to errors raised in logs"

    @staticmethod
    def log_filter_in_errors(log):
        """
        Return the log filter function used for filtering logs to leave behind
        just the error logs that will cause a test to fail.

        :return: True if the log is being filtered (i.e. is NOT an error log),
         otherwise returns False (it is an error log).

        Note that if we are skipping known failures, then ignore logs as
        specified in the IGNORE_LOGS_LIST.
        """
        is_error = log.level in {"ERROR", "PANIC", "FATAL", "CRITICAL"}
        if is_error:
            is_error = not any(txt in log.msg for txt in LOGS_IGNORE_ALL_TESTS)

        return not is_error
