from __future__ import annotations

import typing

from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import NewConnectionError
from urllib3.poolmanager import PoolManager
from urllib3.util.url import parse_url

from .sockstls import create_connection

import requests
import requests.adapters
from requests.utils import get_auth_from_url
from python_socks import ProxyError


class SOCKSTLSConnection(HTTPConnection):
    """
    A plain-text HTTP connection that connects via a SOCKS proxy.
    """

    def __init__(
        self,
        _socks_options,
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> None:
        self._socks_options = _socks_options
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        """
        Establish a new connection via the SOCKS proxy.
        """
        try:
            conn = create_connection(
                self.host, self.port,
                proxy_host=self._socks_options["proxy_host"],
                proxy_port=self._socks_options["proxy_port"],
                proxy_username=self._socks_options["username"],
                proxy_password=self._socks_options["password"]
            )
        except (OSError, ProxyError) as e:
            raise NewConnectionError(
                self, f"Failed to establish a new connection: {e}"
            ) from e

        return conn


# We don't need to duplicate the Verified/Unverified distinction from
# urllib3/connection.py here because the HTTPSConnection will already have been
# correctly set to either the Verified or Unverified form by that module. This
# means the SOCKSHTTPSConnection will automatically be the correct type.
class SOCKSTLSHTTPSConnection(SOCKSTLSConnection, HTTPSConnection):
    pass


class SOCKSTLSHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = SOCKSTLSConnection


class SOCKSTLSHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = SOCKSTLSHTTPSConnection


class SOCKSTLSProxyManager(PoolManager):
    """
    A version of the urllib3 ProxyManager that routes connections via the
    defined SOCKS proxy.
    """

    pool_classes_by_scheme = {
        "http": SOCKSTLSHTTPConnectionPool,
        "https": SOCKSTLSHTTPSConnectionPool,
    }

    def __init__(
        self,
        proxy_url: str,
        username: str | None = None,
        password: str | None = None,
        num_pools: int = 10,
        headers: typing.Mapping[str, str] | None = None,
        **connection_pool_kw: typing.Any,
    ):
        parsed = parse_url(proxy_url)

        if username is None and password is None and parsed.auth is not None:
            split = parsed.auth.split(":")
            if len(split) == 2:
                username, password = split
        if parsed.scheme != "socks5tls":
            raise ValueError(f"Incorrect SOCKS5TLS scheme from {proxy_url}")

        self.proxy_url = proxy_url

        socks_options = {
            "proxy_host": parsed.host,
            "proxy_port": parsed.port,
            "username": username,
            "password": password,
        }
        connection_pool_kw["_socks_options"] = socks_options

        super().__init__(num_pools, headers, **connection_pool_kw)

        self.pool_classes_by_scheme = SOCKSTLSProxyManager.pool_classes_by_scheme


class SOCKSTLSAdapter(requests.adapters.HTTPAdapter):
    def proxy_manager_for(self, proxy, **proxy_kwargs):
        if proxy.startswith("socks5tls"):
            username, password = get_auth_from_url(proxy)
            manager = self.proxy_manager[proxy] = SOCKSTLSProxyManager(
                proxy,
                username=username,
                password=password,
                num_pools=self._pool_connections,
                maxsize=self._pool_maxsize,
                block=self._pool_block,
                **proxy_kwargs,
            )
        else:
            manager = super().proxy_manager_for(proxy, **proxy_kwargs)
        return manager


def make_session(socks5tls_uri):
    session = requests.Session()
    adapter = SOCKSTLSAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.proxies.update({
        'http': socks5tls_uri,
        'https': socks5tls_uri
    })
    return session
