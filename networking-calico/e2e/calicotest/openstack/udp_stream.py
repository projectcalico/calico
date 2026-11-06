# Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

import logging
import re
import time

from calicotest.common.testutils import retry_until_success

_log = logging.getLogger(__name__)


class UdpStream:
    """
    A class representing a stream between two vms
    """

    def __init__(self, vm, target_vm, server_timeout=False):
        self.vm = vm
        self.target_vm = target_vm
        self.duration = 10
        self.buffer_duration = 5
        self.server_timeout = server_timeout

    def start_stream(self):
        """
        Starts a UDP stream from the given vm to the target_vm
        The target_vm will stop running iperf after one connection
        :return:
        """

        # On GCE, first packets sometimes get lost. Test is to check packets
        # aren't lost over action. So this initial loss is not relevant.
        # Start with short burst to ignore.
        command = "iperf -c %s -u -i 1 -t %s > test.tmp &" % (
            self.target_vm.get_ip_addr(),
            "1",
        )
        self.vm.execute(command)
        time.sleep(5)

        # Now run the test
        server_cmd = "iperf -s -u -i 1 -P 1 -l 2000"
        if self.server_timeout:
            server_cmd += " -t %s" % (self.duration + self.buffer_duration)
        self.target_vm.execute(server_cmd + " > test.txt &")
        retry_until_success(self.check_server_started)
        command = "iperf -c %s -u -i 1 -t %s > test.txt &" % (
            self.target_vm.get_ip_addr(),
            self.duration,
        )
        self.vm.execute(command)

    def check_server_started(self):
        command = 'grep "Server listening" test.txt'
        assert self.target_vm.execute(command).stdout != ""

    def completed_successfully(self):
        """
        Checks if the Udpstream has been successfully completed, i.e.
        acceptable packet loss.
        :return: Boolean
        """
        # Example Server report:
        # ------------------------------------------------------------
        # Client connecting to 10.28.0.8, UDP port 5001
        # Sending 1470 byte datagrams
        # UDP buffer size:  208 KByte (default)
        # ------------------------------------------------------------
        # [  3] local 10.28.0.9 port 51343 connected with 10.28.0.8 port 5001
        # [ ID] Interval       Transfer     Bandwidth
        # [  3]  0.0- 1.0 sec   128 KBytes  1.05 Mbits/sec
        # [  3]  1.0- 2.0 sec   128 KBytes  1.05 Mbits/sec
        # [  3]  2.0- 3.0 sec   128 KBytes  1.05 Mbits/sec
        # [  3]  3.0- 4.0 sec   129 KBytes  1.06 Mbits/sec
        # [  3]  4.0- 5.0 sec   128 KBytes  1.05 Mbits/sec
        # [  3]  5.0- 6.0 sec   128 KBytes  1.05 Mbits/sec
        # [  3]  6.0- 7.0 sec   128 KBytes  1.05 Mbits/sec
        # [  3]  7.0- 8.0 sec   128 KBytes  1.05 Mbits/sec
        # [  3]  8.0- 9.0 sec   128 KBytes  1.05 Mbits/sec
        # [  3]  0.0-10.0 sec  1.25 MBytes  1.05 Mbits/sec
        # [  3] Sent 892 datagrams
        # [  3] Server Report:
        # [  3]  0.0-10.2 sec  1.25 MBytes  1.03 Mbits/sec  38.993 ms   15/  892 \
        #           (1.7%)
        # [  3]  0.0-10.2 sec  15 datagrams received out-of-order

        if not self.stream_finished():
            return False

        # Output both test.txt files in their entirety
        self.vm.execute("cat test.txt")
        self.target_vm.execute("cat test.txt")

        success = False
        # The output should have a line starting "Server Report",
        # followed by some output statistics
        command = 'grep -A 2 "Server Report:" test.txt'
        output = self.vm.execute(command)
        lines = output.stdout.split("\n")
        summary_line = lines[1].split()
        # Note that additional_line could be empty, but there always is one
        additional_line = lines[2]
        # Grab the 3rd from last out of the summary line
        # That's '15/' in the example above
        # remove the trailing character and convert to int
        lost_packets = int(summary_line[-3][:-1])
        total_packets = int(summary_line[-2])
        if lost_packets == 0:
            _log.info("No packets dropped - yay!")
            success = True
        else:
            _log.info(
                "%s packets dropped? Check for out of order packets",
                lost_packets,
            )
            ooo_packets = 0
            m = re.search(r"(\d+) datagrams received out-of-order", additional_line)
            if m:
                _log.info("Got some datagrams out of order.  Looking closer")
                ooo_packets = int(m.group(1))
                _log.info("Saw %s out-of-order packets", ooo_packets)
            else:
                _log.info("No out-of-order packets found")
            unaccounted_packets = lost_packets - ooo_packets
            _log.warning("%s packets unaccounted for", unaccounted_packets)
            # If we have more than 1% of packets actually missing, fail.
            if unaccounted_packets < (total_packets * 0.01):
                _log.info("But this is less than 1%, so ship it anyway")
                success = True
            else:
                _log.info("More than 1% packets unaccounted for - FAIL")
        return success

    def stream_finished(self):
        """
        Checks to see if the stream has finished being sent yet
        :return:
        """
        if self.vm.execute('grep "Server Report:" test.txt').stdout != "":
            return True

        # When packet loss is expected, e.g. because of limited bandwidth, we
        # can't rely on seeing "Server Report" on the client, but the server
        # should have been run with a timeout and we can check for the
        # server-side output that we expect in that case.  It looks like this:
        #
        # ------------------------------------------------------------
        # Server listening on UDP port 5001
        # Receiving 2000 byte datagrams
        # UDP buffer size:  208 KByte (default)
        # ------------------------------------------------------------
        # [  3] local 10.28.0.160 port 5001 connected with 10.28.2.233 port 54904
        # [ ID] Interval       Transfer     Bandwidth        Jitter   Lost/Total Datagrams  # noqa: E501
        # [  3]  0.0- 1.0 sec  60.3 KBytes   494 Kbits/sec  19.495 ms    0/   42 (0%)
        # [  3]  1.0- 2.0 sec  35.9 KBytes   294 Kbits/sec  27.183 ms    0/   25 (0%)
        # [  3]  2.0- 3.0 sec  35.9 KBytes   294 Kbits/sec  28.718 ms    0/   25 (0%)
        # [  3]  3.0- 4.0 sec  34.5 KBytes   282 Kbits/sec  29.381 ms    0/   24 (0%)
        # [  3]  4.0- 5.0 sec  35.9 KBytes   294 Kbits/sec  29.220 ms    0/   25 (0%)
        # [  3]  5.0- 6.0 sec  35.9 KBytes   294 Kbits/sec  29.340 ms    0/   25 (0%)
        # [  3]  6.0- 7.0 sec  35.9 KBytes   294 Kbits/sec  29.179 ms    0/   25 (0%)
        # [  3]  7.0- 8.0 sec  34.5 KBytes   282 Kbits/sec  29.214 ms    0/   24 (0%)
        # [  3]  8.0- 9.0 sec  35.9 KBytes   294 Kbits/sec  29.125 ms    0/   25 (0%)
        # [  3]  9.0-10.0 sec  35.9 KBytes   294 Kbits/sec  29.140 ms    0/   25 (0%)
        # [  3] 10.0-11.0 sec  34.5 KBytes   282 Kbits/sec  29.294 ms    0/   24 (0%)
        # [  3] 11.0-12.0 sec  35.9 KBytes   294 Kbits/sec  29.146 ms    0/   25 (0%)
        # [  3] 12.0-13.0 sec  35.9 KBytes   294 Kbits/sec  29.311 ms    0/   25 (0%)
        # [  3] 13.0-14.0 sec  35.9 KBytes   294 Kbits/sec  29.142 ms    0/   25 (0%)
        # [  3] 14.0-15.0 sec  34.5 KBytes   282 Kbits/sec  29.341 ms    0/   24 (0%)
        # [  3] 15.0-16.0 sec  35.9 KBytes   294 Kbits/sec  29.146 ms    0/   25 (0%)
        # [  3] 16.0-17.0 sec  35.9 KBytes   294 Kbits/sec  29.111 ms    0/   25 (0%)
        # [  3] 17.0-18.0 sec  35.9 KBytes   294 Kbits/sec  29.101 ms    0/   25 (0%)
        # [  3] 18.0-19.0 sec  35.9 KBytes   294 Kbits/sec  29.099 ms    0/   25 (0%)
        # [  3] 19.0-20.0 sec  34.5 KBytes   282 Kbits/sec  29.099 ms    0/   24 (0%)
        # [  3] 20.0-21.0 sec  35.9 KBytes   294 Kbits/sec  29.104 ms    0/   25 (0%)
        # [  3] 21.0-22.0 sec  35.9 KBytes   294 Kbits/sec  29.144 ms    0/   25 (0%)
        # [  3] 22.0-23.0 sec  35.9 KBytes   294 Kbits/sec  29.111 ms    0/   25 (0%)
        # [  3] 23.0-24.0 sec  35.9 KBytes   294 Kbits/sec  29.100 ms    0/   25 (0%)
        # [  3] 24.0-25.0 sec  34.5 KBytes   282 Kbits/sec  29.100 ms    0/   24 (0%)
        # [  3] 25.0-26.0 sec  35.9 KBytes   294 Kbits/sec  29.093 ms    0/   25 (0%)
        # [  3] 26.0-27.0 sec  35.9 KBytes   294 Kbits/sec  29.102 ms    0/   25 (0%)
        # [  3] 27.0-28.0 sec  35.9 KBytes   294 Kbits/sec  29.102 ms    0/   25 (0%)
        # [  3] 28.0-29.0 sec  35.9 KBytes   294 Kbits/sec  29.096 ms    0/   25 (0%)
        # [  3] 29.0-30.0 sec  34.5 KBytes   282 Kbits/sec  29.100 ms    0/   24 (0%)
        # [  3] 30.0-31.0 sec  35.9 KBytes   294 Kbits/sec  29.101 ms    0/   25 (0%)
        # [  3] 31.0-32.0 sec  35.9 KBytes   294 Kbits/sec  29.107 ms    0/   25 (0%)
        # [  3] 32.0-33.0 sec  35.9 KBytes   294 Kbits/sec  29.102 ms    0/   25 (0%)
        # [  3] 33.0-34.0 sec  35.9 KBytes   294 Kbits/sec  29.095 ms    0/   25 (0%)
        # [  3] 34.0-35.0 sec  34.5 KBytes   282 Kbits/sec  29.100 ms    0/   24 (0%)
        # [  3]  0.0-35.3 sec  1.25 MBytes   297 Kbits/sec  29.100 ms    0/  893 (0%)
        if self.server_timeout:
            try:
                self.server_bandwidth_kbps()
                return True
            except Exception:
                pass

        return False

    def server_bandwidth_kbps(self):
        server_output = self.target_vm.execute("cat test.txt").stdout
        total_time_secs = 0
        total_rcvd_kbytes = 0
        for line in server_output.splitlines():
            # We're looking for the last line, for the complete time range.
            if " 0.0-" in line and " 0.0- " not in line:
                words = line.split()
                for i in range(1, len(words)):
                    if words[i] == "Kbits/sec":
                        return int(float(words[i - 1]))
                    elif words[i] == "Mbits/sec":
                        return int(float(words[i - 1]) * 1000)
            # When packet loss is expected, the server might not emit the final
            # line that we're looking for just above.  Instead we rely on
            # server timeout to terminate the server iperf process, and we need
            # to total up the individual per-second lines of its output in
            # order to calculate an overall received bandwidth.
            elif " sec " in line and "Bytes " in line and "/sec " in line:
                words = line.split()
                for i in range(1, len(words)):
                    if words[i] == "KBytes":
                        total_rcvd_kbytes += float(words[i - 1])
                        break
                    elif words[i] == "MBytes":
                        total_rcvd_kbytes += float(words[i - 1]) * 1000
                        break
                total_time_secs += 1

        if total_time_secs >= self.duration + self.buffer_duration:
            return int(total_rcvd_kbytes * 8 / total_time_secs)

        raise Exception("Couldn't calculate server bandwidth from %s" % server_output)

    def wait_for_stream_to_finish(self):
        """
        Waits up to the duration of the stream for it to finish,
        plus a bit longer, and returns False if the stream isn't
        completed, True otherwise.
        :return: Boolean
        """
        # The number of extra seconds to wait for it to finish
        for _ in range(0, self.duration + self.buffer_duration):
            if self.stream_finished():
                return True
            time.sleep(1)
        return False

    def client_output(self):
        self.vm.execute("cat test.txt").stdout

    def server_output(self):
        self.target_vm.execute("cat test.txt").stdout
