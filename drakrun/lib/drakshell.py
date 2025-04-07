import enum
import logging
import os
import select
import signal
import socket
import struct
import sys
import threading
import time

import mslex

from .paths import PACKAGE_TOOLS_PATH, RUN_DIR

log = logging.getLogger(__name__)


class ReqCode(enum.IntEnum):
    REQ_PING = 0xA0
    REQ_GET_INFO = 0xA1
    REQ_INTERACTIVE_EXECUTE = 0xA2
    REQ_NON_INTERACTIVE_EXECUTE = 0xA3
    REQ_EXECUTE_AND_FINISH = 0xA4
    REQ_FINISH = 0xA5
    REQ_DATA = 0xA6
    REQ_TERMINATE_PROCESS = 0xA7


class RespCode(enum.IntEnum):
    RESP_PONG = 0xA0
    RESP_INFO = 0xA1
    RESP_INTERACTIVE_EXECUTE_START = 0xA2
    RESP_NON_INTERACTIVE_EXECUTE_START = 0xA3
    RESP_EXECUTE_AND_FINISH_START = 0xA4
    RESP_FINISH_START = 0xA5
    RESP_STDOUT_DATA = 0xA6
    RESP_STDERR_DATA = 0xA7
    RESP_PROCESS_START = 0xA8
    RESP_PROCESS_EXIT = 0xA9
    RESP_BAD_REQ = 0xB0
    RESP_FATAL_ERROR = 0xB1
    RESP_PROCESS_ERROR = 0xB2


class Channel:
    MAX_BUFFER_SIZE = 4096

    def __init__(self, unix_socket_path):
        self.unix_socket_path = unix_socket_path
        self._sock = None

    def connect(self):
        try:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.connect(self.unix_socket_path)
        except Exception:
            self._sock = None
            raise

    def disconnect(self):
        if self._sock is None:
            raise RuntimeError("Socket is not connected")
        self._sock.close()
        self._sock = None

    def send_control(self, req):
        if self._sock is None:
            raise RuntimeError("Socket is not connected")
        msg = struct.pack("<B", int(req))
        self._sock.send(msg)

    def _recv_control(self):
        if self._sock is None:
            raise RuntimeError("Socket is not connected")
        msg = self._sock.recv(1)
        if not msg:
            raise RuntimeError("Socket has unexpectedly disconnected")
        return RespCode(msg[0])

    def _recvn(self, size):
        data = b""
        while size > 0:
            part = self._sock.recv(size)
            if not part:
                raise RuntimeError("Socket has unexpectedly disconnected")
            size -= len(part)
            data += part
        return data

    def _recv_status_code(self):
        if self._sock is None:
            raise RuntimeError("Socket is not connected")
        msg = self._recvn(4)
        if not msg:
            raise RuntimeError("Socket has unexpectedly disconnected")
        return struct.unpack("<I", msg)[0]

    def _recv_info(self):
        if self._sock is None:
            raise RuntimeError("Socket is not connected")
        msg = self._recvn(8)
        if not msg:
            raise RuntimeError("Socket has unexpectedly disconnected")
        return struct.unpack("<II", msg)

    def _recv_data(self):
        if self._sock is None:
            raise RuntimeError("Socket is not connected")
        len_msg = self._recvn(2)
        if not len_msg:
            raise RuntimeError("Socket has unexpectedly disconnected")
        arg_len = struct.unpack("<H", len_msg)[0]
        return self._recvn(arg_len)

    def send_data(self, arg):
        if self._sock is None:
            raise RuntimeError("Socket is not connected")
        if len(arg) > self.MAX_BUFFER_SIZE:
            raise ValueError("Message block too long")
        self.send_control(ReqCode.REQ_DATA)
        len_msg = struct.pack("<H", len(arg))
        self._sock.send(len_msg + arg)

    def recv_response(self, timeout=15):
        self._sock.settimeout(timeout)
        resp = self._recv_control()
        if resp in [RespCode.RESP_STDOUT_DATA, RespCode.RESP_STDERR_DATA]:
            block = self._recv_data()
            return resp, block
        elif resp in [
            RespCode.RESP_PROCESS_EXIT,
            RespCode.RESP_PROCESS_ERROR,
            RespCode.RESP_FATAL_ERROR,
        ]:
            code = self._recv_status_code()
            return resp, code
        elif resp == RespCode.RESP_INFO:
            info = self._recv_info()
            return resp, info
        return resp, None

    def sync(self, timeout=3):
        self.send_control(ReqCode.REQ_PING)
        status, _ = self.recv_response(timeout=timeout)


class InteractiveProcessExit(Exception):
    def __init__(self, exit_code):
        self.exit_code = exit_code


class DrakshellInteractiveProcess:
    def __init__(self, channel: Channel, stdin, stdout, stderr):
        self.channel = channel
        self.terminated = False

        self._exit_code = None
        self._fatal_error = None
        self._stdin = stdin
        self._stdout = stdout
        self._stderr = stderr
        self._thread = threading.Thread(target=self.handler)
        self._thread.start()

    def _handle_streams(self):
        _exc = None
        fds = (
            [self._stdin, self.channel._sock]
            if self._stdin is not None
            else [self.channel._sock]
        )
        while True:
            ready_list, _, _ = select.select(fds, [], [], 1)
            for ready_thing in ready_list:
                if ready_thing is self._stdin:
                    if self._stdin is sys.stdin:
                        stdin_data = os.read(self._stdin.fileno(), 2048)
                    else:
                        stdin_data = self._stdin.recv(2048)
                    self.channel.send_data(stdin_data)
                else:
                    try:
                        status, data = self.channel.recv_response(timeout=3)
                    except Exception as e:
                        if _exc is not None:
                            # I don't know how to handle it now
                            raise
                        else:
                            self.terminate()
                            _exc = e
                    else:
                        if status == RespCode.RESP_STDOUT_DATA:
                            if self._stdout is not None:
                                if hasattr(self._stdout, "send"):
                                    self._stdout.send(data)
                                else:
                                    self._stdout.buffer.write(data)
                                    self._stdout.flush()
                        elif status == RespCode.RESP_STDERR_DATA:
                            if self._stderr is not None:
                                if hasattr(self._stderr, "send"):
                                    self._stderr.send(data)
                                else:
                                    self._stderr.buffer.write(data)
                                    self._stderr.flush()
                        elif status == RespCode.RESP_PROCESS_EXIT:
                            self.terminated = True
                            raise InteractiveProcessExit(data)
                        elif status == RespCode.RESP_FATAL_ERROR:
                            self.terminated = True
                            raise RuntimeError(f"Fatal execution error: code={data}")
                        else:
                            raise RuntimeError(
                                f"Drakshell is out of sync: got {status} during process execution"
                            )

    def handler(self):
        try:
            self._handle_streams()
        except InteractiveProcessExit as e:
            self._exit_code = e.exit_code
        except Exception as e:
            self._fatal_error = e

    def terminate(self):
        if self.terminated:
            return
        self.terminated = True
        self.channel.send_control(ReqCode.REQ_TERMINATE_PROCESS)

    def join(self):
        # We can't rely on KeyboardInterrupt because threads are immediately terminated
        # when signal handler raises an Exception. I don't know why it works that way
        # but we need to setup our own handler here.
        orig_handler = signal.getsignal(signal.SIGINT)

        def sigint_handler(sig, frame):
            self.terminate()

        try:
            signal.signal(signal.SIGINT, sigint_handler)
            self._thread.join()
        finally:
            signal.signal(signal.SIGINT, orig_handler)

        if self._exit_code is not None:
            return self._exit_code
        else:
            raise self._fatal_error


class Drakshell:
    def __init__(self, vm_name: str):
        self.vm_name = vm_name

        unix_socket_path = RUN_DIR / f"{vm_name}.sock"
        self.channel = Channel(str(unix_socket_path))

    def connect(self, timeout: int = 3):
        self.channel.connect()
        try:
            self.channel.send_control(ReqCode.REQ_PING)
            status, _ = self.channel.recv_response(timeout=timeout)
            if status != RespCode.RESP_PONG:
                raise RuntimeError(
                    f"Drakshell is out of sync: got {status} instead of {RespCode.RESP_PONG}"
                )
        except Exception:
            self.channel.disconnect()
            raise

    def disconnect(self):
        self.channel.disconnect()

    def get_info(self):
        self.channel.send_control(ReqCode.REQ_GET_INFO)
        status, info = self.channel.recv_response(timeout=3)
        if status != RespCode.RESP_INFO:
            raise RuntimeError(
                f"Drakshell is out of sync: got {status} instead of {RespCode.RESP_INFO}"
            )
        return {"pid": info[0], "tid": info[1]}

    def finish(self):
        self.channel.send_control(ReqCode.REQ_FINISH)
        status, info = self.channel.recv_response(timeout=15)
        if status != RespCode.RESP_FINISH_START:
            raise RuntimeError(
                f"Drakshell is out of sync: got {status} instead of {RespCode.RESP_FINISH_START}"
            )

    def _start_process(self, args, start_code: ReqCode):
        if type(args) is list or type(args) is tuple:
            args = mslex.join(args, for_cmd=False)
        cmdline = args.encode("utf-16le") + b"\0\0"
        if len(cmdline) > 2048:
            raise RuntimeError("Command line too long")

        expected_status = {
            ReqCode.REQ_INTERACTIVE_EXECUTE: RespCode.RESP_INTERACTIVE_EXECUTE_START,
            ReqCode.REQ_NON_INTERACTIVE_EXECUTE: RespCode.RESP_NON_INTERACTIVE_EXECUTE_START,
            ReqCode.REQ_EXECUTE_AND_FINISH: RespCode.RESP_EXECUTE_AND_FINISH_START,
        }[start_code]
        self.channel.send_control(start_code)

        status, _ = self.channel.recv_response(timeout=15)
        if status != expected_status:
            raise RuntimeError(
                f"Drakshell is out of sync: got {status} instead of {expected_status}"
            )

        self.channel.send_data(cmdline)
        status, code = self.channel.recv_response(timeout=15)
        if status == RespCode.RESP_PROCESS_START:
            pass
        elif status == RespCode.RESP_PROCESS_ERROR:
            raise RuntimeError(f"Process startup failed: {code}")
        else:
            raise RuntimeError(
                f"Drakshell is out of sync: got {status} instead of {expected_status}"
            )

    def run(self, args, terminate_drakshell=False):
        if terminate_drakshell:
            start_code = ReqCode.REQ_EXECUTE_AND_FINISH
        else:
            start_code = ReqCode.REQ_NON_INTERACTIVE_EXECUTE

        self._start_process(args, start_code)

    def run_interactive(self, args, stdin=None, stdout=sys.stdout, stderr=sys.stderr):
        self._start_process(args, ReqCode.REQ_INTERACTIVE_EXECUTE)
        return DrakshellInteractiveProcess(self.channel, stdin, stdout, stderr)

    def check_call(self, args):
        process = self.run_interactive(args)
        exit_code = process.join()
        if exit_code != 0:
            raise RuntimeError(f"Process exited with exit code {exit_code}")


def get_drakshell(vm, injector):
    drakshell = Drakshell(vm.vm_name)
    connected = False
    try:
        drakshell.connect()
        connected = True
    except Exception as e:
        log.warning(f"Failed to connect to drakshell: {str(e)}")

    if not connected:
        log.info("Injecting drakshell...")
        drakshell_path = (
            (PACKAGE_TOOLS_PATH / "drakshell" / "drakshell").resolve().as_posix()
        )
        injector.inject_shellcode(drakshell_path)
        log.info("Injected. Trying to connect.")
        time.sleep(1)
        drakshell.connect()

    info = drakshell.get_info()
    return drakshell, info
