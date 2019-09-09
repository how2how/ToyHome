import os
import sys
import StringIO


def run(command_or_file):
    """ Runs a python command or a python file and returns the output """
    new_stdout = StringIO.StringIO()
    old_stdout = sys.stdout
    sys.stdout = new_stdout
    new_stderr = StringIO.StringIO()
    old_stderr = sys.stderr
    sys.stderr = new_stderr
    if os.path.exists(command_or_file):
        # self.send_output("[*] Running python file...")
        with open(command_or_file, 'r') as f:
            python_code = f.read()
            try:
                exec(python_code)
            except Exception as exc:
                # self.send_output(traceback.format_exc())
                pass
    else:
        # self.send_output("[*] Running python command...")
        try:
            exec(command_or_file)
        except Exception as exc:
            # self.send_output(traceback.format_exc())
            pass
    sys.stdout = old_stdout
    sys.stderr = old_stderr
    return '\n'.join((new_stdout.getvalue(), new_stderr.getvalue()))
