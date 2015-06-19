from test_base import TestBase
from docker_host import DockerHost


class TestEndpointCommands(TestBase):
    def test_endpoint_commands_mainline(self):
        """
        Run a mainline multi-host test using endpoint commands.

        This test uses the "endpoint profile set" command to assign
        endpoints to profiles according to the following topology:
            Host1: [workload_A, workload_B, workload_C]
            Host2: [workload_D, workload_E]
            Creates a profile that connects A, C, & E
            Creates an additional isolated profile for B.
            Creates an additional isolated profile for D.
        IP Connectivity is then tested to ensure that only workloads
        in the same profile can ping one another
        """
        host1 = DockerHost('host1')
        host2 = DockerHost('host2')

        ip_a = "192.168.1.1"
        ip_b = "192.168.1.2"
        ip_c = "192.168.1.3"
        ip_d = "192.168.1.4"
        ip_e = "192.168.1.5"

        workload_a = host1.create_workload("workload_a", ip_a)
        workload_b = host1.create_workload("workload_b", ip_b)
        workload_c = host1.create_workload("workload_c", ip_c)
        workload_d = host2.create_workload("workload_d", ip_d)
        workload_e = host2.create_workload("workload_e", ip_e)

        host1.calicoctl("profile add PROF_1_3_5")
        host1.calicoctl("profile add PROF_2")
        host1.calicoctl("profile add PROF_4")

        workload_a_endpoint_id = host1.calicoctl("container workload_a endpoint-id show").strip()
        workload_b_endpoint_id = host1.calicoctl("container workload_b endpoint-id show").strip()
        workload_c_endpoint_id = host1.calicoctl("container workload_c endpoint-id show").strip()
        workload_d_endpoint_id = host2.calicoctl("container workload_d endpoint-id show").strip()
        workload_e_endpoint_id = host2.calicoctl("container workload_e endpoint-id show").strip()

        host1.calicoctl("endpoint %s profile set PROF_1_3_5" % workload_a_endpoint_id)
        host1.calicoctl("endpoint %s profile set PROF_2" % workload_b_endpoint_id)
        host1.calicoctl("endpoint %s profile set PROF_1_3_5" % workload_c_endpoint_id)
        host2.calicoctl("endpoint %s profile set PROF_4" % workload_d_endpoint_id)
        host2.calicoctl("endpoint %s profile set PROF_1_3_5" % workload_e_endpoint_id)

        self.assert_connectivity(pass_list=[workload_a, workload_c, workload_e],
                                 fail_list=[workload_b, workload_d])

        self.assert_connectivity(pass_list=[workload_b],
                                 fail_list=[workload_a, workload_c, workload_d, workload_e])

        self.assert_connectivity(pass_list=[workload_d],
                                 fail_list=[workload_a, workload_b, workload_c, workload_e])

    def test_endpoint_commands(self):
        """
        Run a mainline multi-host test using endpoint commands

        Performs more complicated endpoint profile assignments to test
        the append, set, and remove commands in situations where the commands
        specify multiple profiles at once.
        """
        host1 = DockerHost('host1')
        host2 = DockerHost('host2')

        ip_main = "192.168.1.1"
        ip_a = "192.168.1.2"
        ip_b = "192.168.1.3"
        ip_c = "192.168.1.4"

        workload_main = host1.create_workload("workload_main", ip_main)
        host2.create_workload("workload_a", ip_a)
        host2.create_workload("workload_b", ip_b)
        host2.create_workload("workload_c", ip_c)


        workload_main_endpoint_id = host1.calicoctl("container workload_main endpoint-id show").strip()
        workload_a_endpoint_id = host2.calicoctl("container workload_a endpoint-id show").strip()
        workload_b_endpoint_id = host2.calicoctl("container workload_b endpoint-id show").strip()
        workload_c_endpoint_id = host2.calicoctl("container workload_c endpoint-id show").strip()

        host1.calicoctl("profile add PROF_A")
        host1.calicoctl("profile add PROF_B")
        host1.calicoctl("profile add PROF_C")

        host2.calicoctl("endpoint %s profile set PROF_A" % workload_a_endpoint_id)
        host2.calicoctl("endpoint %s profile set PROF_B" % workload_b_endpoint_id)
        host2.calicoctl("endpoint %s profile set PROF_C" % workload_c_endpoint_id)

        # Test set single profile
        host1.calicoctl("endpoint %s profile set PROF_A" % workload_main_endpoint_id)
        workload_main.assert_can_ping(ip_a, retries=4)
        workload_main.assert_cant_ping(ip_b)
        workload_main.assert_cant_ping(ip_c)

        # Test set multiple profiles (note: PROF_A should now be removed)
        host1.calicoctl("endpoint %s profile set PROF_B PROF_C" % workload_main_endpoint_id)
        workload_main.assert_cant_ping(ip_a, retries=4)
        workload_main.assert_can_ping(ip_b)
        workload_main.assert_can_ping(ip_c)

        # Test set profile to None
        host1.calicoctl("endpoint %s profile set" % workload_main_endpoint_id)
        workload_main.assert_cant_ping(ip_a, retries=4)
        workload_main.assert_cant_ping(ip_b)
        workload_main.assert_cant_ping(ip_c)

        # Append a single profile
        host1.calicoctl("endpoint %s profile append PROF_A" % workload_main_endpoint_id)
        workload_main.assert_can_ping(ip_a, retries=4)
        workload_main.assert_cant_ping(ip_b)
        workload_main.assert_cant_ping(ip_c)

        # Append two profiles at once
        host1.calicoctl("endpoint %s profile append PROF_B PROF_C" % workload_main_endpoint_id)
        workload_main.assert_can_ping(ip_a, retries=4)
        workload_main.assert_can_ping(ip_b)
        workload_main.assert_can_ping(ip_c)

        # Remove a single profile
        host1.calicoctl("endpoint %s profile remove PROF_C" % workload_main_endpoint_id)
        workload_main.assert_can_ping(ip_a, retries=4)
        workload_main.assert_can_ping(ip_b)
        workload_main.assert_cant_ping(ip_c)

        # Remove two profiles at once
        host1.calicoctl("endpoint %s profile remove PROF_A PROF_B" % workload_main_endpoint_id)
        workload_main.assert_cant_ping(ip_a, retries=4)
        workload_main.assert_cant_ping(ip_b)
        workload_main.assert_cant_ping(ip_c)
