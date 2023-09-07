import requests
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
    Establishes TCP connection with host via SOCKS5
    """
    proxy = Proxy.from_url(f'socks5://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}')
    return proxy.connect(host, port)


def make_session(socks5_uri):
    session = requests.Session()
    session.proxies.update({
        'http': socks5_uri,
        'https': socks5_uri
    })
    return session
