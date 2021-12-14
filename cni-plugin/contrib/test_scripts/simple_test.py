from util import *

cont, ip = create_container()
print ip
run_command(cont, "ip link")
delete_container(cont)

