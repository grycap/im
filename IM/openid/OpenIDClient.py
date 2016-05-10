'''
Created on 10 de may. de 2016

@author: micafer
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
