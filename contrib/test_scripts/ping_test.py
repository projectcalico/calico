from util import *

cont1, ip = create_container()
cont2, _ = create_container()

run_command(cont1, "date")
run_command(cont1, "sleep 2")

# The ping will only work if felix is running
run_command(cont2, "ping %s" % ip)

delete_container(cont1)
delete_container(cont2)

