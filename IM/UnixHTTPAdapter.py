# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# The following file has been taken from requests-unixsocket
# https://github.com/msabramo/requests-unixsocket/blob/master/requests_unixsocket/adapters.py

import socket

from requests.adapters import HTTPAdapter
from requests.compat import urlparse, unquote
try:
    from requests.packages.urllib3.connection import HTTPConnection
    from requests.packages.urllib3.connectionpool import HTTPConnectionPool
except ImportError:
    from urllib3.connection import HTTPConnection
    from urllib3.connectionpool import HTTPConnectionPool


class UnixHTTPConnection(HTTPConnection):

    def __init__(self, unix_socket_url, timeout=60):
        """Create an HTTP connection to a unix domain socket
        :param unix_socket_url: A URL with a scheme of 'http+unix' and the
        netloc is a percent-encoded path to a unix domain socket. E.g.:
        'http+unix://%2Ftmp%2Fprofilesvc.sock/status/pid'
        """
        HTTPConnection.__init__(self, 'localhost', timeout=timeout)
        self.unix_socket_url = unix_socket_url
        self.timeout = timeout

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        socket_path = unquote(urlparse(self.unix_socket_url).netloc)
        sock.connect(socket_path)
        self.sock = sock


class UnixHTTPConnectionPool(HTTPConnectionPool):

    def __init__(self, socket_path, timeout=60):
        HTTPConnectionPool.__init__(self, 'localhost', timeout=timeout)
        self.socket_path = socket_path
        self.timeout = timeout

    def _new_conn(self):
        return UnixHTTPConnection(self.socket_path, self.timeout)


class UnixHTTPAdapter(HTTPAdapter):

    def __init__(self, timeout=60):
        super(UnixHTTPAdapter, self).__init__()
        self.timeout = timeout

    def get_connection(self, socket_path, proxies=None):
        proxies = proxies or {}
        proxy = proxies.get(urlparse(socket_path.lower()).scheme)

        if proxy:
            raise ValueError('%s does not support specifying proxies'
                             % self.__class__.__name__)
        return UnixHTTPConnectionPool(socket_path, self.timeout)

    def request_url(self, request, proxies):
        return request.path_url
