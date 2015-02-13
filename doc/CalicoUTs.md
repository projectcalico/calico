# Calico Unit Tests
This document describes the Calico unit tests, both how to run them and how they are designed.

*Before you submit a pull request to Calico, you must normally run the unit tests and verify that they pass, according to the instructions below. These unit tests normally run after every checkin.*

## How to run the unit tests
Running the tests requires `nose`, which you can normally install using `pip install nose`. The tests do not require any other non-standard python software (in particular, they do not test either `0MQ` or `python-iptables`, although that might change in the future).

You can then run the tests from your repository as follows.

* Change to the top level directory of the repository (the one with subdirectories `calico`, `doc`, `etc`, ...).

* Run the following command (coverage is turned on by default).

        nosetests

* The tests pass if `nose` reports success, and there is full code coverage of all new and modified code. *Note that in due course we shall have reached 100% code coverage, at which point the requirement becomes 100% code coverage).*

## Test status
As of now, the tests are not complete. For Felix, there are a number of `TODO` markers scattered around the test code, and not all modules are at 100% coverage, but we're getting there (and the tests do run reliably, and must be used).

## Unit test design
### Felix
The Felix code splits into several categories.

* There is a certain amount of utility code. The testing of this is straightforward; there are classes of unit tests that exercise all the code and function in that utility code. Since some of this code calls out to OS specific function, we use mocks as you might expect to get full coverage. This covers `futils`, `config`, `ipsets` and `devices`.

* There is the core Felix logic, contained in the modules `felix`, `endpoint`, `frules`, and `fsocket`. This is tested for the most part as a whole, ensuring that the overall Felix behaviour end-to-end is as expected (i.e. that Felix turns messages on the `0MQ` interface and events reported by the system and gets the system into the correctly configured state). When doing so, there are some elements controlling the interface to the outside world, including both `zmq` for `0MQ` and `iptc` for `python-iptables`. We aren't interested in testing third party code in our UTs, and we have to run in any environment, so our approach is as follows.

    * For `zmq`, the module is never loaded during tests, and instead is replaced by a stub module which mimics the interface.
    * For `iptc`, the interface is enormous, though we only use a subset of it. Hence rather than stub it all out, we stub out the wrapper module that Felix uses (`fiptables`).
    * Other components that access the system configuration (such as callouts to `ipset` management function) are mocked out.

    If you want to get a better understanding of how this works in practice, take a look at the code in [test_felix.py](../calico/felix/test/test_felix.py) and the various stubs.


### ACL Manager
*The ACL Manager tests are still under construction - this section will be written when they are complete.*

