from subprocess import CalledProcessError


class CommandExecError(CalledProcessError):
    """
    Wrapper for CalledProcessError with an Exception message that gives the
    output captured from the failed command.
    """

    def __init__(self, called_process_error):
        self.called_process_error = called_process_error

    @property
    def returncode(self):
        return self.called_process_error.returncode

    @property
    def output(self):
        return self.called_process_error.output

    @property
    def cmd(self):
        return self.called_process_error.cmd

    def __str__(self):
        return "Command %s failed with RC %s and output:\n%s" % \
               (self.called_process_error.cmd,
                self.called_process_error.returncode,
                self.called_process_error.output)

