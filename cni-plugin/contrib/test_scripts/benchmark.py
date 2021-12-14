from util import *

REPS = 10

check_call("rm -f addstats delstats", shell=True)
for i in range(0, REPS):
    cont, ip = create_container("command time -o addstats -a -f '%e,%S,%U,%M,%t,%K,%I,%O' ")
    delete_container(cont, "command time -o delstats -a -f '%e,%S,%U,%M,%t,%K,%I,%O' ")

print "Add stats"
print "wallclock(s),system(s),user(s),max rss(KB),avg rss(KB),avg tot mem(KB),I,O"
check_call("cat addstats", shell=True)

print "\nDel stats"
print "wallclock(s),system(s),user(s),max rss(KB),avg rss(KB),avg tot mem(KB),I,O"
check_call("cat delstats", shell=True)
