"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import asyncio
import json
import os
import re
import subprocess
from datetime import datetime

import software.constants as constants


class SoftwareWorker(object):
    """This class wraps the subprocess commands used by USM
    modules to run a command with parameters and write its
    return code, stdout, stderr and other useful information into
    a structured json file that can be later recovered to create
    a deployment summary report.
    """
    def __init__(self, release, stage):
        """SoftwareWorker constructor

        :param release: target release name, used to define
        the directory in which json files will be created
        :param stage: deployment stage which the commands
        are being executed, used to define the json filename
        """
        self._release = release
        self._stage = stage
        self._directory = os.path.join(constants.WORKER_SUMMARY_DIR, self._release)
        os.makedirs(self._directory, exist_ok=True)
        self._filename = os.path.join(self._directory, self._stage) + ".json"
        operations = self._read_file()
        self._run = str(SoftwareWorker._get_key(operations))

    def _read_file(self):
        """Reads the file and returns its content in a dictionary.

        :returns: dictionary loaded with content from json file
        """
        try:
            with open(self._filename, "r") as f:
                return json.loads(f.read())
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            return {}

    def _write_file(self, operation, cmd, rc, output):
        """Writes the command in a structured format in the file.

        :param cmd: command that was run via subprocess
        :param rc: command return code
        :param output: output (stdout + stderr) returned by the command
        """
        operations = self._read_file()
        command = SoftwareWorker._suppress_text(cmd)
        if not isinstance(cmd, list):
            command = [command]
        with open(self._filename, "w") as f:
            if self._run not in operations:
                operations[self._run] = {}
            operations[self._run][operation] = {
                "timestamp": datetime.strftime(datetime.utcnow(),
                                               constants.WORKER_DATETIME_FORMAT),
                "command": " ".join(command),
                "rc": rc,
                "output": output,
            }
            f.write(json.dumps(operations))

    async def _run_async(self, operation, cmd, *args, **kwargs):
        """Run a command with asyncio lib, which allows returning
        a line-by-line output for stdout and stderr that is then
        written to a json file.

        :param operation: operation name written to json file
        :param cmd: command to be executed in string format
        :param args: list of arguments passed along with the command
        :param kwargs: extra arguments to change the behavior of the output
        :returns: instance of CompletedProcess object
        """
        if "env" in kwargs:
            env = kwargs["env"]
        else:
            env = {}

        # concatenate params for shell command format
        cmd_str = " ".join([cmd] + list(args))

        # create process, capture output and wait it to end
        if "shell" in kwargs and kwargs["shell"]:
            process = await asyncio.create_subprocess_shell(
                cmd_str,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env)
        else:
            process = await asyncio.create_subprocess_exec(
                cmd,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env)
        stdout, stderr = await asyncio.gather(
            SoftwareWorker._read_pipe(process.stdout, "stdout"),
            SoftwareWorker._read_pipe(process.stderr, "stderr")
        )
        await process.wait()

        # sort pipes by timestamp to write to json
        rc = process.returncode
        output = stdout + stderr
        sorted_output = sorted(output, key=lambda item: list(item.values())[0])
        self._write_file(operation, cmd_str, process.returncode, sorted_output)

        # join stdout and stderr to return
        stdout_str, stderr_str = SoftwareWorker._join_stdout_stderr(sorted_output)

        # do some validation to simulate subprocess behavior
        if "check" in kwargs and kwargs["check"]:
            if rc != 0:
                raise subprocess.CalledProcessError(cmd=cmd, returncode=rc,
                                                    output=stdout_str, stderr=stderr_str)
        cp = subprocess.CompletedProcess(args=args, returncode=rc,
                                         stdout=stdout_str, stderr=stderr_str)
        return cp

    def run(self, operation, cmd, *args, **kwargs):
        """Run the _run_async() method with asyncio.run()
           to hide asyncio complexity details from the user.

        :param operation: operation name written to json file
        :param cmd: command to be run
        :param args: extra arguments passes to the command
        :param kwargs: extra keyword arguments
        :returns: command output
        """
        return asyncio.run(self._run_async(operation, cmd, *args, **kwargs))

    def run_func(self, operation, function, *args, **kwargs):
        """Runs a function, capture its output and writes
           to a json file.

        :param operation: operation name written to json file
        :param function: function to be executed
        :param args: args to pass to function
        :param kwargs: kwargs to pass to function
        :returns: executed function return
        """
        str_args = [str(arg) for arg in args]
        str_kwargs = [str(arg) + "=" + str(kwargs[arg]) for arg in kwargs]
        cmd = function.__name__ + "(" + ", ".join(str_args + str_kwargs) + ")"
        msg = "'%s' executed " % function.__name__
        ret, rc = None, 0
        try:
            ret = function(*args, **kwargs)
            msg = msg + "with success: %s" % str(ret)
        except Exception as e:
            rc = 1
            msg = msg + "with failure: %s" % str(e)
            raise e
        finally:
            msg_type = "stdout" if rc == 0 else "stderr"
            self._write_file(operation, cmd, rc, [{
                "timestamp": datetime.strftime(datetime.utcnow(),
                                               constants.WORKER_DATETIME_FORMAT),
                "type": msg_type,
                "output": msg
            }])
        return ret

    @staticmethod
    async def _read_pipe(stream, pipe):
        """Read an IO stream created by asyncio line-by-line

        :param stream: stream of data to be read
        :param pipe: type of the output (e.g. stdio)
        :returns: list of dictionaries containing
                  each line of the stream marked
                  with date and type
        """
        output_list = []
        while True:
            chunk = await stream.readline()
            if len(chunk) == 0:
                break
            line = str(chunk.decode('utf-8'))
            output_list.append({
                "timestamp": datetime.strftime(datetime.utcnow(),
                                               constants.WORKER_DATETIME_FORMAT),
                "type": pipe,
                "output": line
            })
        return output_list

    @staticmethod
    def _join_stdout_stderr(output_list):
        """Join a list of lines with two different types

        :param output_list: list of lines to be merged
        :returns: two strings, one with all stdio output
                  and one with all stderr output
        """
        stderr, stdout = "", ""
        for output in output_list:
            if output["type"] == "stdout":
                stdout += output["output"]
            else:
                stderr += output["output"]
        return stdout, stderr

    @staticmethod
    def _get_key(d):
        """Receive a dictionary with integer keys
           and return the next valid integer

           :param d: dictionary with integer keys
           :returns: next valid integer key
        """
        if not d:
            return 1
        keys = sorted(list(d.keys()))
        last = keys[-1]
        return int(last) + 1

    @staticmethod
    def _suppress_text(_str):
        """Suppress a set of patterns from a string

           :param _str: source string
           :returns: suppressed string
        """
        search_patterns = [
            r".*(?:password|pass|pw)[= ]+(\S+)\s",
        ]

        suppressed = _str
        for sp in search_patterns:
            match = re.match(sp, _str)
            if match:
                suppressed = suppressed.replace(match.group(1), "xxxxxxx")
        return suppressed
