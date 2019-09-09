import subprocess


def run(cmd):
    """ Runs a shell command and returns its output """
    try:
        proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        output = '\n'.join((out, err))
        return output
    except Exception as exc:
        return exc.__repr__()
