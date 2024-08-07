import struct
import socket

REQ_PING = 0x30
REQ_UPLOAD = 0x31
REQ_DOWNLOAD = 0x32
REQ_EXIT = 0x33

RESP_SUCCESS = 0x30
RESP_FILE_OPENED = 0x31
RESP_ERROR = 0x32


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

    def _send_req(self, req):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        msg = struct.pack("<B", req)
        self._sock.send(msg)

    def _recv_resp(self):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        msg = self._sock.recv(1)
        if not msg:
            raise RuntimeError('Socket has unexpectedly disconnected')
        return msg[0]

    def _recv_gle(self):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        msg = self._sock.recv(4)
        if not msg:
            raise RuntimeError('Socket has unexpectedly disconnected')
        return struct.unpack("<I", msg)[0]

    def _send_arg(self, arg):
        if self._sock is None:
            raise RuntimeError('Socket is not connected')
        if len(arg) > self.MAX_BUFFER_SIZE:
            raise ValueError("Message block too long")
        len_msg = struct.pack("<H", len(arg))
        self._sock.send(len_msg + arg)

    def _recv_arg(self):
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

    def ping(self):
        self._send_req(REQ_PING)
        resp = self._recv_resp()
        if resp != RESP_SUCCESS:
            raise RuntimeError(f'Unexpected response: {resp}')
        return True

    def upload_file(self, host_path, guest_path):
        self._send_req(REQ_UPLOAD)
        self._send_arg(guest_path.encode("utf-16le") + b"\0\0")
        resp = self._recv_resp()
        if resp == RESP_FILE_OPENED:
            target_guest_path = self._recv_arg()
        elif resp == RESP_ERROR:
            gle = self._recv_gle()
            raise RuntimeError(f"Can't open file for writing: {gle}")
        else:
            raise RuntimeError(f'Unexpected response: {resp}')

        with open(host_path, "rb") as f:
            while True:
                block = f.read(self.MAX_BUFFER_SIZE)
                self._send_arg(block)
                if not block:
                    break

        resp = self._recv_resp()
        if resp == RESP_SUCCESS:
            return target_guest_path.decode("utf-16le")
        elif resp == RESP_ERROR:
            gle = self._recv_gle()
            raise RuntimeError(f"Error during file read: {gle}")
        else:
            raise RuntimeError(f'Unexpected response: {resp}')

