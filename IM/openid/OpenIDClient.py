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
# GNU General Public Licenslast_updatee for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''
Class to contact with an OpenID server
'''
import httplib
import urlparse
import json
from JWT import JWT


class OpenIDClient(object):
    def __init__(self):
        self.a = 1

    @staticmethod
    def get_connection(url):
        """
        Get a HTTP/S connection with the specified server.
        """
        parsed_url = urlparse.urlparse(url)
        port = None
        server = parsed_url[1]
        if parsed_url[1].find(":") != -1:
            parts = parsed_url[1].split(":")
            server = parts[0]
            port = int(parts[1])
        if parsed_url[0] == "https":
            return httplib.HTTPSConnection(server, port)
        else:
            return httplib.HTTPConnection(server, port)

    @staticmethod
    def get_user_info_request(token):
        try:
            decoded_token = JWT().get_info(token)
            headers = {'Authorization': 'Bearer %s' % token}
            conn = OpenIDClient.get_connection(decoded_token['iss'])
            conn.request('GET', "/userinfo", headers=headers)
            resp = conn.getresponse()

            output = resp.read()
            if resp.status != 200:
                return False, resp.reason + "\n" + output
            return True, json.loads(output)
        except Exception, ex:
            return False, str(ex)
