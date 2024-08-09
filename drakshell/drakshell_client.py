import enum
import struct
import socket
import mslex


class ReqCode(enum.IntEnum):
    REQ_PING = 0x30
    REQ_INTERACTIVE_EXECUTE = 0x31
    REQ_NON_INTERACTIVE_EXECUTE = 0x32
    REQ_EXECUTE_AND_FINISH = 0x33
    REQ_FINISH = 0x34
    REQ_DATA = 0x35
    REQ_TERMINATE_PROCESS = 0x36


class RespCode(enum.IntEnum):
    RESP_PONG = 0x30
    RESP_INTERACTIVE_EXECUTE_START = 0x31
    RESP_NON_INTERACTIVE_EXECUTE_START = 0x32
    RESP_EXECUTE_AND_FINISH_START = 0x33
    RESP_FINISH_START = 0x34
    RESP_STDOUT_DATA = 0x35
    RESP_STDERR_DATA = 0x36
    RESP_PROCESS_START = 0x37
    RESP_PROCESS_EXIT = 0x38
    RESP_BAD_REQ = 0x40
    RESP_FATAL_ERROR = 0x41
    RESP_PROCESS_ERROR = 0x42


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
            raise RuntimeError('Socket is not connected')
        self._sock.close()
        self._sock = None

    def send_control(self, req):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        msg = struct.pack("<B", int(req))
        self._sock.send(msg)

    def _recv_control(self):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        msg = self._sock.recv(1)
        if not msg:
            raise RuntimeError('Socket has unexpectedly disconnected')
        return RespCode(msg[0])

    def _recv_status_code(self):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        msg = self._sock.recv(4)
        if not msg:
            raise RuntimeError('Socket has unexpectedly disconnected')
        return struct.unpack("<I", msg)[0]

    def _recv_data(self):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        len_msg = self._sock.recv(2)
        if not len_msg:
            raise RuntimeError('Socket has unexpectedly disconnected')
        arg_len = struct.unpack("<H", len_msg)[0]
        arg = b''
        while arg_len > 0:
            part = self._sock.recv(arg_len)
            if not part:
                raise RuntimeError('Socket has unexpectedly disconnected')
            arg_len -= len(part)
            arg += part
        return arg

    def send_data(self, arg):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
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
        elif resp in [RespCode.RESP_PROCESS_EXIT, RespCode.RESP_PROCESS_ERROR, RespCode.RESP_FATAL_ERROR]:
            code = self._recv_status_code()
            return resp, code
        return resp, None


class Drakshell:
    def __init__(self, unix_socket_path):
        self.channel = Channel(unix_socket_path)

    def connect(self):
        self.channel.connect()

    def disconnect(self):
        self.channel.disconnect()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False

    def run(self, args, capture_output=False, timeout=15):
        self.channel.send_control(ReqCode.REQ_PING)
        status, _ = self.channel.recv_response(timeout=3)
        if status != RespCode.RESP_PONG:
            raise RuntimeError(f"Drakshell ping failed: {status}")

        cmdline = mslex.join(args, for_cmd=False).encode("utf-16le") + b"\0\0"

        if len(cmdline) > 2048:
            raise RuntimeError("Command line too long")

        if capture_output:
            self.channel.send_control(ReqCode.REQ_INTERACTIVE_EXECUTE)
            expected_status = RespCode.RESP_INTERACTIVE_EXECUTE_START
        else:
            self.channel.send_control(ReqCode.REQ_NON_INTERACTIVE_EXECUTE)
            expected_status = RespCode.RESP_NON_INTERACTIVE_EXECUTE_START

        status, _ = self.channel.recv_response(timeout=3)
        if status != expected_status:
            raise RuntimeError(f"Fatal error: {status}")

        self.channel.send_data(cmdline)

        status, code = self.channel.recv_response(timeout=3)
        if status == RespCode.RESP_PROCESS_START:
            pass
        elif status == RespCode.RESP_PROCESS_ERROR:
            raise RuntimeError(f"Process startup failed: {code}")
        else:
            raise RuntimeError(f"Fatal error: {status}")

        stdout = b''
        stderr = b''
        exit_code = 0

        while True:
            try:
                status, data = self.channel.recv_response(timeout=timeout)
            except:
                self.channel.send_control(ReqCode.REQ_TERMINATE_PROCESS)
                # Consume possible response
                self.channel.recv_response()
                raise
            if status == RespCode.RESP_STDOUT_DATA:
                stdout += data
            elif status == RespCode.RESP_STDOUT_DATA:
                stderr += data
            elif status == RespCode.RESP_PROCESS_EXIT:
                exit_code = data
                break
            else:
                raise RuntimeError(f"Fatal error: {status}")

        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
        }
