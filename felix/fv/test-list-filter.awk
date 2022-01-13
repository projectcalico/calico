BEGIN {
    print;
    print "The following FV tests will run in this batch";
    print "=============================================";
}

/msg="Loaded config"/ {
    next;
}

/^Running Suite:/ {
    next;
}

/^==============/ {
    next;
}

/^Random Seed:/ {
    next;
}

/^Parallel test node/ {
    next;
}

/^JUnit report was created/ {
    next;
}

/^Ran [[:digit:]]+ of [[:digit:]]+ Specs/ {
    next;
}

/^SUCCESS!/ {
    next;
}

/^PASS$/ {
    next;
}

/^[•S]+$/ {
    next;
}

{
    print;
}
