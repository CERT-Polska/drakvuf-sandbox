import socket
import ssl
from python_socks.sync import Proxy


def create_connection(
    host,
    port,
    proxy_username=None,
    proxy_password=None,
    proxy_host=None,
    proxy_port=None
):
    """
    Establishes TCP connection with host via SOCKS5 over TLS proxy
    """
    # Make TLS connection with proxy
    proxy_socket = socket.socket()
    ssl_proxy_socket = ssl.create_default_context().wrap_socket(proxy_socket, server_hostname=proxy_host)
    ssl_proxy_socket.connect((proxy_host, proxy_port))

    proxy = Proxy.from_url(f'socks5://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}')
    # Use TLS connection for establishing SOCKS5 connection with target host
    return proxy.connect(host, port, _socket=ssl_proxy_socket)
