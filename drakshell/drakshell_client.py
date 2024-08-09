import enum
import struct
import socket

REQ_PING = 0x30
REQ_INTERACTIVE_EXECUTE = 0x31
REQ_EXECUTE_AND_FINISH = 0x32
REQ_FINISH = 0x33
REQ_BLOCK = 0x34


class DrakshellRespCode(enum.IntEnum):
    RESP_PONG = 0x30
    RESP_INTERACTIVE_EXECUTE_START = 0x31
    RESP_EXECUTE_AND_FINISH_START = 0x32
    RESP_FINISH_START = 0x33
    RESP_STDOUT_BLOCK = 0x34
    RESP_STDERR_BLOCK = 0x35
    RESP_INTERACTIVE_EXECUTE_PROCESS_CREATED = 0x36
    RESP_INTERACTIVE_EXECUTE_END = 0x37

    RESP_BAD_REQ = 0x40
    RESP_FATAL_ERROR = 0x41


class DrakshellClient:
    MAX_BUFFER_SIZE = 4096

    def __init__(self, unix_socket_path):
        self.unix_socket_path = unix_socket_path
        self._sock = None

    def connect(self):
        try:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.settimeout(3)
            self._sock.connect(self.unix_socket_path)
        except Exception:
            self._sock = None
            raise

    def send_control(self, req):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        msg = struct.pack("<B", req)
        self._sock.send(msg)

    def _recv_control(self):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        msg = self._sock.recv(1)
        if not msg:
            raise RuntimeError('Socket has unexpectedly disconnected')
        return DrakshellRespCode(msg[0])

    def _recv_status_code(self):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        msg = self._sock.recv(4)
        if not msg:
            raise RuntimeError('Socket has unexpectedly disconnected')
        return struct.unpack("<I", msg)[0]

    def _recv_block(self):
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

    def send_block(self, arg):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        if len(arg) > self.MAX_BUFFER_SIZE:
            raise ValueError("Message block too long")
        self.send_control(REQ_BLOCK)
        len_msg = struct.pack("<H", len(arg))
        self._sock.send(len_msg + arg)

    def recv_response(self):
        resp = self._recv_control()

        if resp in [DrakshellRespCode.RESP_STDOUT_BLOCK, DrakshellRespCode.RESP_STDERR_BLOCK]:
            block = self._recv_block()
            return resp, block
        elif resp in [DrakshellRespCode.RESP_FATAL_ERROR, DrakshellRespCode.RESP_INTERACTIVE_EXECUTE_END]:
            code = self._recv_status_code()
            return resp, code
        return resp, None
