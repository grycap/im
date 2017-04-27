#
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

import ssl
try:
    from SimpleXMLRPCServer import SimpleXMLRPCServer
except ImportError:
    from xmlrpc.server import SimpleXMLRPCServer


class SSLSimpleXMLRPCServer(SimpleXMLRPCServer, object):
    """
    Class that adds SSL security to SimpleXMLRPCServer
    """

    def __init__(self, address, keyfile=None, certfile=None, ca_certs=None,
                 cert_reqs=ssl.CERT_NONE):
        self._keyfile = keyfile
        self._certfile = certfile
        self._ca_certs = ca_certs
        self._cert_reqs = cert_reqs
        super(SSLSimpleXMLRPCServer, self).__init__(address)

    def get_request(self):
        client, addr = super(SSLSimpleXMLRPCServer, self).get_request()
        client_ssl = ssl.wrap_socket(client,
                                     keyfile=self._keyfile,
                                     certfile=self._certfile,
                                     ca_certs=self._ca_certs,
                                     cert_reqs=self._cert_reqs,
                                     server_side=True)
        return client_ssl, addr
